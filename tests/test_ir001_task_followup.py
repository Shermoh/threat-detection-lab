"""Defensive task-execution correlation regression checks for IR-001 follow-up."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from ir001_task_followup import load_events, investigate  # noqa: E402


class IR001TaskFollowupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load_events()
        cls.a = [e for e in cls.events if e["scenario"] == "FOLLOWUP_A"]
        cls.b = [e for e in cls.events if e["scenario"] == "UNRELATED_B"]

    def test_fixture_integrity(self):
        self.assertEqual(len(self.events), 12)
        self.assertEqual(len(self.a), 8)
        self.assertEqual(len(self.b), 4)
        self.assertEqual(len({e["evidence_id"] for e in self.events}), 12)

    def test_confirmed_task_action_process_but_not_success(self):
        result = investigate(self.a)
        self.assertTrue(result["scheduler_action_start_observed"])
        self.assertTrue(result["scheduler_129_process_launch_observed"])
        self.assertTrue(result["correlated_4688_process_observed"])
        self.assertTrue(result["scheduler_action_completion_observed"])
        self.assertEqual(result["task_instance_id"], "RUN-A1")
        self.assertEqual(result["correlated_process_id"], "6200")
        self.assertEqual(result["action_return_code"], "1")
        self.assertFalse(result["script_exit_success_confirmed"])

    def test_registry_change_is_distinct_from_autorun(self):
        result = investigate(self.a)
        self.assertTrue(result["powershell_4104_observed"])
        self.assertTrue(result["registry_4657_observed"])
        self.assertTrue(result["registry_value_present_in_followup"])
        self.assertTrue(result["registry_persistence_configuration_supported"])
        self.assertFalse(result["autorun_triggered_observed"])

    def test_unrelated_host_same_task_name_and_time_does_not_match(self):
        result = investigate(self.b)
        self.assertFalse(result["scheduler_action_start_observed"])
        self.assertFalse(result["correlated_4688_process_observed"])
        self.assertIsNone(result["action_return_code"])
        self.assertIn("No execution observed", result["conclusion"])

    def test_wrong_host_scheduler_event_cannot_fabricate_link(self):
        mixed = [e for e in self.a if e["event_id" if False else "evidence_id"] != "F-002"]
        # A real process exists, but its TaskScheduler 129 launch evidence is absent.
        mixed += [e for e in self.b if e["event_code"] == "129"]
        result = investigate(mixed)
        self.assertTrue(result["scheduler_action_start_observed"])
        self.assertFalse(result["scheduler_129_process_launch_observed"])
        self.assertFalse(result["correlated_4688_process_observed"])
        self.assertFalse(result["registry_persistence_configuration_supported"])

    def test_unmatched_instance_does_not_join(self):
        changed = [dict(e) for e in self.a]
        for e in changed:
            if e["evidence_id"] == "F-002":
                e["instance_id"] = "RUN-WRONG"
        result = investigate(changed)
        self.assertFalse(result["scheduler_129_process_launch_observed"])
        self.assertFalse(result["correlated_4688_process_observed"])

    def test_process_match_requires_command_line(self):
        changed = [dict(e) for e in self.a]
        for e in changed:
            if e["evidence_id"] == "F-003":
                e["command_or_artifact"] = "powershell.exe -NoProfile"
        result = investigate(changed)
        self.assertTrue(result["scheduler_129_process_launch_observed"])
        self.assertFalse(result["correlated_4688_process_observed"])
        self.assertFalse(result["registry_persistence_configuration_supported"])


if __name__ == "__main__":
    unittest.main()
