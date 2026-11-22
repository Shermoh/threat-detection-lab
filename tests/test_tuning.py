"""Test a narrow lab-specific maintenance downgrade with synthetic fixtures.

The original detection is unchanged; all encoded-command matches remain visible.
These tests do not execute KQL inside Sentinel.
"""
import copy
import csv
import unittest
from pathlib import Path
from test_detection import matches_detection, triage_category

DATA = Path(__file__).resolve().parents[1] / "sample-data" / "windows_4688_synthetic.csv"


def known_maintenance(event):
    """Mirror the narrowly scoped tuning example in KQL."""
    if not matches_detection(event):
        return False
    return (
        event["Computer"].casefold() == "lab-win04"
        and event["Account"].casefold() == r"lab\svc-maint"
        and (event["ParentProcessName"] or "").casefold().endswith(r"\services.exe")
        and event["CommandLine"].casefold()
        == "powershell.exe -encodedcommand qqbcaema"
    )


def tuned_triage_category(event):
    if known_maintenance(event):
        return "Known maintenance - monitor"
    return triage_category(event)


class NarrowMaintenanceTuningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with DATA.open(newline="", encoding="utf-8") as stream:
            cls.events = {event["CaseID"]: event for event in csv.DictReader(stream)}

    def test_approved_case_is_downgraded_not_silenced(self):
        event = self.events["S004"]
        self.assertTrue(matches_detection(event))
        self.assertTrue(known_maintenance(event))
        self.assertEqual(tuned_triage_category(event), "Known maintenance - monitor")

    def test_other_maintenance_case_remains_reviewable(self):
        # S016 uses the same illustrative payload, but on another host
        # with a short switch; it must not inherit S004's downgrade.
        event = self.events["S016"]
        self.assertTrue(matches_detection(event))
        self.assertFalse(known_maintenance(event))
        self.assertEqual(tuned_triage_category(event), "Review - encoded command")

    def test_all_other_matches_remain_visible(self):
        matches_before = {k for k, e in self.events.items() if matches_detection(e)}
        matches_after = {
            k for k, e in self.events.items() if tuned_triage_category(e) != "No alert"
        }
        self.assertEqual(matches_before, matches_after)
        self.assertEqual(sum(known_maintenance(e) for e in self.events.values()), 1)

    def test_small_context_changes_invalidate_downgrade(self):
        case = self.events["S004"]
        changes = [
            ("Computer", "LAB-WIN99"),
            ("Account", r"LAB\attacker"),
            ("ParentProcessName", r"C:\Windows\explorer.exe"),
            ("CommandLine", "powershell.exe -enc QQBCAEMA"),
        ]
        for field, value in changes:
            with self.subTest(field=field):
                mutated = copy.deepcopy(case)
                mutated[field] = value
                self.assertTrue(matches_detection(mutated))
                self.assertFalse(known_maintenance(mutated))

    def test_important_blind_spot_is_documented(self):
        # If an attacker fully replays indistinguishable telemetry, matching
        # fields cannot establish legitimacy. Keep monitoring / enrich sources.
        replay = copy.deepcopy(self.events["S004"])
        replay["GroundTruth"] = "suspicious"
        self.assertTrue(known_maintenance(replay))


if __name__ == "__main__":
    unittest.main()
