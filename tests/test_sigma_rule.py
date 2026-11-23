"""Validate the Sigma YAML and its fixture-level detection behaviour.

pySigma parses the rule format. The event-matching checks below are a
small Python interpretation of the two specific selections, not a SIEM
backend conversion or a production execution.
"""
import csv
import re
import unittest
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[1]
SIGMA_PATH = ROOT / "detections" / "sigma" / "proc_creation_win_powershell_encoded_command_lab.yml"
DATA = ROOT / "sample-data" / "windows_4688_synthetic.csv"


def matches_sigma(event, rule):
    """Mirror the selected Sigma predicates on the synthetic Security 4688 feed.

    Logsource category=process_creation is assumed to be mapped to Event ID
    4688 here. Real Sigma backends may map process_creation to other sources.
    """
    if int(event["EventID"]) != 4688:
        return False
    selections = rule["detection"]
    if selections["condition"] != "selection_image and selection_encoded":
        raise ValueError("Unsupported Sigma condition; update fixture test")

    image = event["NewProcessName"]
    allowed_suffixes = selections["selection_image"]["Image|endswith"]
    image_matches = any(image.casefold().endswith(s.casefold()) for s in allowed_suffixes)

    pattern = selections["selection_encoded"]["CommandLine|re"]
    command_matches = re.search(pattern, event["CommandLine"] or "") is not None
    return image_matches and command_matches


class SigmaRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = SIGMA_PATH.read_text(encoding="utf-8")
        cls.rule = yaml.safe_load(text)
        cls.collection = SigmaCollection.from_yaml(text)
        with DATA.open(encoding="utf-8", newline="") as stream:
            cls.events = list(csv.DictReader(stream))
        cls.by_id = {row["CaseID"]: row for row in cls.events}

    def test_pysigma_parses_rule(self):
        self.assertEqual(len(self.collection.rules), 1)
        self.assertEqual(self.rule["status"], "experimental")
        self.assertEqual(self.rule["logsource"]["category"], "process_creation")
        self.assertEqual(self.rule["logsource"]["product"], "windows")
        self.assertIn("attack.t1059.001", self.rule["tags"])

    def test_all_20_curated_fixture_results(self):
        self.assertEqual(len(self.events), 20)
        for event in self.events:
            with self.subTest(case=event["CaseID"]):
                expected = event["ExpectedMatch"].lower() == "true"
                self.assertEqual(matches_sigma(event, self.rule), expected)

    def test_expected_positive_and_negative_sets(self):
        ids = {e["CaseID"] for e in self.events if matches_sigma(e, self.rule)}
        self.assertEqual(
            ids,
            {"S001", "S002", "S003", "S004", "S005", "S015", "S016", "S018", "S019"},
        )
        # Two matching entries are intentionally benign, with no blanket allowlist.
        self.assertTrue(matches_sigma(self.by_id["S004"], self.rule))
        self.assertTrue(matches_sigma(self.by_id["S016"], self.rule))
        # Renamed binary does not match executable image predicate.
        self.assertFalse(matches_sigma(self.by_id["S013"], self.rule))

    def test_flag_boundaries_and_case_insensitive_variant(self):
        event = dict(self.by_id["S001"])
        for cmd in (
            "powershell.exe -EncodedCommandX QQBCAEMA",
            "powershell.exe -encodedsomething QQBCAEMA",
            "powershell.exe -encode QQBCAEMA",
            "powershell.exe /enc QQBCAEMA",
        ):
            with self.subTest(command=cmd):
                event["CommandLine"] = cmd
                self.assertFalse(matches_sigma(event, self.rule))
        for cmd in (
            "powershell.exe -EncodedCommand QQBCAEMA",
            "powershell.exe -ENC QQBCAEMA",
            "powershell.exe -enc:QQBCAEMA",
        ):
            with self.subTest(command=cmd):
                event["CommandLine"] = cmd
                self.assertTrue(matches_sigma(event, self.rule))

    def test_logsource_prevents_wrong_event_id_from_matching(self):
        self.assertFalse(matches_sigma(self.by_id["S012"], self.rule))
        self.assertFalse(matches_sigma(self.by_id["S020"], self.rule))

    def test_parent_process_not_used_as_suppression(self):
        selection = self.rule["detection"]
        self.assertEqual(set(selection), {"selection_image", "selection_encoded", "condition"})
        self.assertNotIn("ParentImage", str(selection))


if __name__ == "__main__":
    unittest.main()
