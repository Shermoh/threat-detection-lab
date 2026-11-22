"""Synthetic validation of session and source-IP correlation rules."""
import copy
import unittest

from session_ip_correlation import (
    linked_success, load_events, prior_failures_for_session, score_event,
    scores_for_fixture,
)


class SessionIpCorrelationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load_events()
        cls.by_id = {event["CaseID"]: event for event in cls.events}
        cls.scores = scores_for_fixture(cls.events)

    def test_process_outcomes(self):
        expected = {
            "P001": ("L001", 0, 5, "Low"),
            "P002": ("L002", 3, 55, "High"),
            "P003": ("L003", 0, 5, "Low"),
            "P004": ("", 0, 15, "Low"),
            "P005": ("L005", 0, 55, "High"),
            "P007": ("L007", 0, 15, "Low"),
            "P008": ("", 0, 15, "Low"),
        }
        self.assertEqual(set(expected), set(self.scores))
        for case_id, (linked_id, failures, points, band) in expected.items():
            with self.subTest(case=case_id):
                result = self.scores[case_id]
                self.assertEqual(result["MatchedSessionId"], linked_id)
                self.assertEqual(result["FailedSameIp15m"], failures)
                self.assertEqual(result["RiskPoints"], points)
                self.assertEqual(result["RiskBand"], band)

    def test_same_command_replay_still_escalates(self):
        self.assertEqual(self.scores["P001"]["RiskPoints"], 5)
        self.assertTrue(self.scores["P002"]["KnownMaintenance"])
        self.assertEqual(self.scores["P002"]["RiskBand"], "High")
        self.assertEqual(self.scores["P002"]["SourceIp"], "203.0.113.77")

    def test_other_ip_failures_are_excluded(self):
        self.assertEqual(self.scores["P003"]["FailedSameIp15m"], 0)
        self.assertEqual(self.scores["P001"]["FailedSameIp15m"], 0)

    def test_wrong_logon_id_and_stale_logon_do_not_link(self):
        self.assertIsNone(linked_success(self.by_id["P004"], self.events))
        self.assertFalse(self.scores["P004"]["SessionLinked"])

    def test_invalid_logon_id_and_missing_ip_are_reviewed(self):
        for case_id in ("P004", "P007", "P008"):
            with self.subTest(case=case_id):
                self.assertEqual(
                    self.scores[case_id]["TriageDisposition"],
                    "Review: identity context incomplete",
                )
        self.assertEqual(self.scores["P007"]["SessionStatus"],
                         "Linked; source IP unavailable")
        self.assertFalse(self.scores["P008"]["SessionLinked"])

    def test_failure_after_success_does_not_correlate(self):
        session = self.by_id["L002"]
        all_count = prior_failures_for_session(session, self.events)
        future_free = [e for e in self.events if e["CaseID"] != "F005"]
        self.assertEqual(all_count, 3)
        self.assertEqual(prior_failures_for_session(session, future_free), 3)

    def test_session_correlation_requires_same_host_and_account(self):
        altered = copy.deepcopy(self.by_id["P002"])
        altered["Computer"] = "LAB-WIN99"
        self.assertIsNone(linked_success(altered, self.events))
        altered = copy.deepcopy(self.by_id["P002"])
        altered["Account"] = r"LAB\someoneelse"
        self.assertIsNone(linked_success(altered, self.events))

    def test_non_encoded_process_is_excluded(self):
        self.assertIsNone(score_event(self.by_id["P006"], self.events))

    def test_fixture_integrity(self):
        self.assertEqual(len(self.events), 29)
        self.assertEqual(len(self.by_id), len(self.events))
        self.assertEqual(sum(x["EventID"] == "4624" for x in self.events), 8)
        self.assertEqual(sum(x["EventID"] == "4625" for x in self.events), 13)


if __name__ == "__main__":
    unittest.main()
