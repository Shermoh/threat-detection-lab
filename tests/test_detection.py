"""Offline parity checks for the PowerShell encoded-command KQL detection.

These tests emulate its predicate against synthetic CSV fixtures.
They DO NOT execute or certify the KQL query in Microsoft Sentinel.
"""
import csv
import re
import unittest
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "sample-data" / "windows_4688_synthetic.csv"
ENCODED_FLAG = re.compile(r"(^|\s)-(encodedcommand|enc)(\s|:|$)", re.IGNORECASE)


def matches_detection(event):
    """Mirror the KQL event-ID, process-name, and argument filters."""
    if int(event["EventID"]) != 4688:
        return False
    image = event["NewProcessName"].replace("/", "\\").split("\\")[-1].lower()
    if image not in {"powershell.exe", "pwsh.exe"}:
        return False
    command = event["CommandLine"] or ""
    return bool(ENCODED_FLAG.search(command))


class PowerShellEncodedCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with DATA.open(newline="", encoding="utf-8") as f:
            cls.events = list(csv.DictReader(f))
        cls.by_id = {event["CaseID"]: event for event in cls.events}

    def test_every_fixture_has_expected_result(self):
        for event in self.events:
            with self.subTest(event=event["CaseID"]):
                expected = event["ExpectedMatch"].lower() == "true"
                self.assertEqual(matches_detection(event), expected)

    def test_expected_alert_ids(self):
        actual = {event["CaseID"] for event in self.events if matches_detection(event)}
        self.assertEqual(actual, {"S001", "S002", "S003", "S004", "S005"})

    def test_known_false_positive_and_false_negative(self):
        # EncodedCommand can be legitimate; renamed PowerShell can evade this rule.
        self.assertTrue(matches_detection(self.by_id["S004"]))
        self.assertEqual(self.by_id["S004"]["GroundTruth"], "benign")
        self.assertFalse(matches_detection(self.by_id["S013"]))
        self.assertEqual(self.by_id["S013"]["GroundTruth"], "suspicious")

    def test_all_cases_have_unique_ids_and_only_synthetic_lab_hosts(self):
        ids = [e["CaseID"] for e in self.events]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(e["Computer"].startswith("LAB-WIN") for e in self.events))


if __name__ == "__main__":
    unittest.main()
