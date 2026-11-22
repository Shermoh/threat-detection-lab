"""Guard against drift between KQL sample harness and the maintained KQL file.

This checks only text consistency and fixture coverage; it does NOT compile KQL.
Run the inline query in a Kusto environment to validate KQL execution.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = ROOT / "detections" / "kql" / "powershell_session_ip_correlation.kql"
HARNESS = ROOT / "tests" / "kql" / "session_ip_synthetic_validation.kql"


def adapted_query():
    content = PRODUCTION.read_text(encoding="utf-8")
    body = content[content.index("let lookback = 7d;"):].strip()
    return (
        body.replace(
            "ago(lookback + sessionWindow + failureWindow)",
            "(testNow - lookback - sessionWindow - failureWindow)",
        )
        .replace("ago(lookback + sessionWindow)", "(testNow - lookback - sessionWindow)")
        .replace("ago(lookback)", "(testNow - lookback)")
    )


class KqlHarnessContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.query = adapted_query()
        cls.harness = HARNESS.read_text(encoding="utf-8")

    def test_harness_contains_same_core_query(self):
        self.assertIn(self.query, self.harness)

    def test_test_query_has_no_clock_relative_filter(self):
        self.assertIn("let testNow=datetime(2026-11-21T16:00:00Z);", self.harness)
        self.assertNotIn("ago(", self.query)

    def test_fixture_and_expected_cases_are_present(self):
        self.assertIn("let SecurityEvent = datatable(", self.harness)
        self.assertIn("let Expected=datatable(", self.harness)
        table_section = self.harness.split("let SecurityEvent = datatable(", 1)[1].split(
            "let Expected=datatable(", 1
        )[0]
        event_ids = re.findall(r'@"([A-Z]\d{3}(?:-OLD)?)", datetime\(', table_section)
        self.assertEqual(len(event_ids), 29)
        self.assertEqual(len(set(event_ids)), len(event_ids))
        for case_id in ("P001", "P002", "P003", "P004", "P005", "P007", "P008"):
            self.assertIn(f'@"{case_id}",', self.harness)
        self.assertIn('kind=fullouter Expected on Computer, ProcessTime', self.harness)

    def test_harness_reports_pass_or_fail(self):
        self.assertIn('ValidationStatus=iff(', self.harness)
        self.assertIn('"PASS", "FAIL"', self.harness)


if __name__ == "__main__":
    unittest.main()
