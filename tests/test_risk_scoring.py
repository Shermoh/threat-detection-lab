"""Expected results for the illustrative risk-scoring exercise."""
import copy
import unittest
from datetime import datetime

from risk_scoring import (
    count_recent_failures, load_fixture_events, risk_result, score_all,
)


class RiskCorrelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load_fixture_events()
        cls.by_id = {e["CaseID"]: e for e in cls.events}
        cls.scores = score_all(cls.events)

    def test_expected_risk_categories(self):
        # case: prior failures, score, risk band
        expected = {
            "S001": (1, 65, "High"),
            "S002": (3, 70, "High"),
            "S003": (0, 20, "Low"),
            "S004": (0, 5, "Low"),
            "S005": (0, 55, "High"),
            "S015": (0, 55, "High"),
            "S016": (0, 20, "Low"),
            "S018": (0, 30, "Medium"),
            "S019": (0, 55, "High"),
            "R001": (3, 55, "High"),
        }
        self.assertEqual(set(self.scores), set(expected))
        for case, (failed, points, band) in expected.items():
            with self.subTest(case=case):
                actual = self.scores[case]
                self.assertEqual(actual["FailedLogons15m"], failed)
                self.assertEqual(actual["RiskPoints"], points)
                self.assertEqual(actual["RiskBand"], band)

    def test_exact_approved_replay_can_still_escalate(self):
        approved = self.scores["S004"]
        replay = self.scores["R001"]
        self.assertTrue(approved["KnownMaintenance"])
        self.assertTrue(replay["KnownMaintenance"])
        self.assertEqual(approved["RiskBand"], "Low")
        self.assertEqual(replay["RiskBand"], "High")
        self.assertEqual(replay["FailedLogons15m"], 3)

    def test_outside_window_future_and_other_hosts_do_not_join(self):
        replay = self.by_id["R001"]
        self.assertEqual(count_recent_failures(replay, self.events), 3)
        removed = [e for e in self.events if e["CaseID"] not in {"A001", "A002", "A003"}]
        self.assertEqual(count_recent_failures(replay, removed), 0)

    def test_correct_account_join_and_event_id(self):
        sam = self.by_id["S002"]
        self.assertEqual(count_recent_failures(sam, self.events), 3)
        other_account = copy.deepcopy(sam)
        other_account["Account"] = r"LAB\jane"
        self.assertEqual(count_recent_failures(other_account, self.events), 1)
        no_match = self.by_id["S006"]
        self.assertIsNone(risk_result(no_match, self.events))

    def test_fixture_metadata(self):
        self.assertEqual(len(self.events), 34)
        self.assertEqual(len(self.by_id), len(self.events))
        self.assertEqual(sum(e["EventID"] == "4625" for e in self.events), 12)


if __name__ == "__main__":
    unittest.main()
