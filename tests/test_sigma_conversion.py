"""Check REAL pySigma Kusto conversion remains consistent with saved KQL.

This suite runs only in .github/workflows/sigma-conversion.yml with the
separately pinned pysigma==1.5.1 and pysigma-backend-kusto==1.0.1.
It does not execute KQL in Azure Data Explorer or Sentinel.
"""
import csv
import re
import unittest
from pathlib import Path

from tools.convert_sigma_to_kql import convert_rule

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "detections/kql/generated/powershell_sigma_backend_raw.kql"
SCOPED = ROOT / "detections/kql/generated/powershell_sigma_securityevent_4688.kql"
HARNESS = ROOT / "tests/kql/sigma_conversion_validation.kql"
FIXTURE = ROOT / "sample-data/windows_4688_synthetic.csv"


class SigmaKustoBackendConversionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = convert_rule()
        cls.raw = RAW.read_text(encoding="utf-8").strip()
        cls.scoped = SCOPED.read_text(encoding="utf-8")
        cls.harness = HARNESS.read_text(encoding="utf-8")

    def test_real_backend_output_matches_snapshot(self):
        self.assertEqual(self.actual, self.raw)

    def test_raw_output_exposes_missing_event_id_filter(self):
        self.assertTrue(self.actual.startswith("SecurityEvent\n| where "))
        self.assertIn("NewProcessName", self.actual)
        self.assertIn("CommandLine matches regex", self.actual)
        self.assertNotIn("EventID", self.actual)

    def test_scoped_query_preserves_generated_filter_and_adds_4688(self):
        predicate = self.actual.split("\n", 1)[1]
        self.assertIn(
            "SecurityEvent\n| where EventID == 4688\n" + predicate,
            self.scoped,
        )
        # The rule is otherwise a direct pySigma output, not a hand rewrite.
        self.assertEqual(self.scoped.count(predicate), 1)

    def test_kql_validation_harness_contains_exact_scoped_predicate(self):
        predicate = self.actual.split("\n", 1)[1]
        self.assertIn(
            "let Matches = Cases\n| where EventID == 4688\n" + predicate,
            self.harness,
        )
        self.assertIn("ValidationStatus=iff(", self.harness)
        self.assertIn('iff(ActualMatch==ExpectedMatch,"PASS","FAIL")', self.harness)

    def test_labelled_20_event_fixture_coverage(self):
        with FIXTURE.open(encoding="utf-8", newline="") as stream:
            events = list(csv.DictReader(stream))
        self.assertEqual(len(events), 20)
        self.assertEqual(sum(e["ExpectedMatch"] == "true" for e in events), 9)
        self.assertEqual(sum(e["ExpectedMatch"] == "false" for e in events), 11)
        # Every fixture case appears in the KQL datatable with its expected flag.
        for event in events:
            expected_bool = "true" if event["ExpectedMatch"] == "true" else "false"
            with self.subTest(case=event["CaseID"]):
                self.assertRegex(
                    self.harness,
                    re.escape('@"' + event["CaseID"] + '"')
                    + r',\s*\d+,\s*@".*?",\s*@".*?",\s*'
                    + expected_bool
                    + r',',
                )


if __name__ == "__main__":
    unittest.main()
