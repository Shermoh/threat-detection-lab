"""Offline fixture tests for the PowerShell KQL detection.

These tests mirror KQL filter and classification logic in Python.
They DO NOT execute KQL in a Sentinel workspace.
"""
import csv
import re
import unittest
from collections import Counter
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "sample-data" / "windows_4688_synthetic.csv"
ENCODED_FLAG = re.compile(r"(^|\s)-(encodedcommand|enc)(\s|:|$)", re.IGNORECASE)
UNUSUAL_PARENT = re.compile(
    r"(^|\\)(winword|excel|outlook|powerpnt|wscript|cscript|mshta)\.exe$",
    re.IGNORECASE,
)


def matches_detection(event):
    """Return True for event 4688 and encoded PowerShell arguments."""
    if int(event["EventID"]) != 4688:
        return False
    image = event["NewProcessName"].replace("/", "\\").split("\\")[-1].lower()
    if image not in {"powershell.exe", "pwsh.exe"}:
        return False
    return bool(ENCODED_FLAG.search(event["CommandLine"] or ""))


def triage_category(event):
    """Mirror KQL triage categorization; this is not a maliciousness verdict."""
    if not matches_detection(event):
        return "No alert"
    parent = (event.get("ParentProcessName") or "").strip()
    if not parent:
        return "Review - parent unavailable"
    if UNUSUAL_PARENT.search(parent):
        return "Elevated - unusual parent"
    return "Review - encoded command"


class PowerShellEncodedCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with DATA.open(newline="", encoding="utf-8") as stream:
            cls.events = list(csv.DictReader(stream))
        cls.by_id = {event["CaseID"]: event for event in cls.events}

    def test_every_fixture_matches_expected_result(self):
        for event in self.events:
            with self.subTest(case=event["CaseID"]):
                self.assertEqual(
                    matches_detection(event), event["ExpectedMatch"] == "true"
                )

    def test_each_priority_matches_expected_result(self):
        for event in self.events:
            with self.subTest(case=event["CaseID"]):
                self.assertEqual(triage_category(event), event["ExpectedPriority"])

    def test_expected_matches_and_priorities(self):
        matched = {e["CaseID"] for e in self.events if matches_detection(e)}
        self.assertEqual(
            matched,
            {"S001", "S002", "S003", "S004", "S005", "S015", "S016", "S018", "S019"},
        )
        categories = Counter(triage_category(e) for e in self.events)
        self.assertEqual(categories["Elevated - unusual parent"], 4)
        self.assertEqual(categories["Review - encoded command"], 4)
        self.assertEqual(categories["Review - parent unavailable"], 1)
        self.assertEqual(categories["No alert"], 11)

    def test_known_false_positives_and_false_negative(self):
        for case_id in ("S004", "S016"):
            self.assertTrue(matches_detection(self.by_id[case_id]))
            self.assertEqual(self.by_id[case_id]["GroundTruth"], "benign")
        self.assertFalse(matches_detection(self.by_id["S013"]))
        self.assertEqual(self.by_id["S013"]["GroundTruth"], "suspicious")

    def test_context_is_not_a_detection_shortcut(self):
        self.assertEqual(triage_category(self.by_id["S017"]), "No alert")
        self.assertEqual(triage_category(self.by_id["S020"]), "No alert")
        self.assertEqual(
            triage_category(self.by_id["S018"]), "Review - parent unavailable"
        )

    def test_fixture_integrity(self):
        self.assertEqual(len(self.events), 20)
        self.assertEqual(len(self.by_id), len(self.events))
        self.assertTrue(all(e["Computer"].startswith("LAB-WIN") for e in self.events))
        self.assertTrue(all("ExpectedPriority" in e for e in self.events))


if __name__ == "__main__":
    unittest.main()
