"""Generate a reproducible timeline for the fictional IR-001 case study.

This script only reads synthetic CSV data. It never executes PowerShell,
contacts an external destination, or modifies an endpoint.
"""
import argparse
import base64
import csv
import json
from datetime import datetime
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parents[1] / "case-studies" / "IR-001-word-powershell"
DATA_PATH = CASE_DIR / "data" / "events.csv"

REQUIRED_FIELDS = {
    "event_id", "timestamp_utc", "source", "host", "account", "logon_id",
    "process_id", "parent_process_id", "source_ip", "artifact", "outcome",
    "details", "correlation_id",
}


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_events(path=DATA_PATH):
    with Path(path).open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not REQUIRED_FIELDS.issubset(reader.fieldnames or []):
            raise ValueError("Missing required case-study fields")
        rows = list(reader)
    ids = [row["event_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate event IDs in IR-001 dataset")
    for row in rows:
        parse_time(row["timestamp_utc"])
    return sorted(rows, key=lambda row: (parse_time(row["timestamp_utc"]), row["event_id"]))


def decode_encoded_powershell(command_line):
    """Decode the lab's EncodedCommand as PowerShell UTF-16LE; never execute it."""
    marker = "-EncodedCommand "
    if marker.casefold() not in command_line.casefold():
        raise ValueError("No EncodedCommand switch in synthetic process")
    position = command_line.casefold().index(marker.casefold()) + len(marker)
    encoded = command_line[position:].strip().split()[0]
    return base64.b64decode(encoded, validate=True).decode("utf-16le")


def summarize(events):
    by_id = {e["event_id"]: e for e in events}
    winword, powershell = by_id["IR-006"], by_id["IR-007"]
    login = by_id["IR-005"]
    matching_failed = [
        e for e in events if e["source"] == "WindowsSecurity4625"
        and e["host"] == login["host"]
        and e["account"] == login["account"]
        and e["source_ip"] == login["source_ip"]
        and parse_time(e["timestamp_utc"]) <= parse_time(login["timestamp_utc"])
    ]
    decoded = decode_encoded_powershell(powershell["details"])
    return {
        "synthetic_event_count": len(events),
        "authentication_failures_before_success": len(matching_failed),
        "logon_id_link": (
            login["logon_id"] == winword["logon_id"] == powershell["logon_id"]
        ),
        "office_parent_link": (
            powershell["parent_process_id"] == winword["process_id"]
            and powershell["host"] == winword["host"]
        ),
        "decoded_matches_scriptblock": decoded == by_id["IR-008"]["details"],
        "decoded_script": decoded,
        "blocked_proxy_request_observed": by_id["IR-010"]["outcome"] == "blocked_403",
        "task_registration_observed": by_id["IR-011"]["outcome"] == "created",
        "script_file_not_found_at_query": by_id["IR-013"]["outcome"] == "not_found",
        "other_host_task_is_unrelated": by_id["IR-012"]["host"] != winword["host"],
        "payload_execution_confirmed": False,
        "task_execution_confirmed": False,
    }


def to_markdown(events):
    lines = [
        "# IR-001 synthetic timeline",
        "",
        "> This is a fictional incident reconstruction, not actual customer telemetry.",
        "",
        "| Time (UTC) | Evidence ID | Source | Host | Observed result |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in events:
        lines.append(
            "| " + " | ".join([
                item["timestamp_utc"][11:19],
                item["event_id"],
                item["source"],
                item["host"],
                item["artifact"].replace("|", "/") + " — " + item["outcome"],
            ]) + " |"
        )
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Summarize fictional IR-001 evidence")
    parser.add_argument("--json", action="store_true", help="Show synthetic facts as JSON")
    args = parser.parse_args()
    events = load_events()
    print(json.dumps(summarize(events), indent=2) if args.json else to_markdown(events))


if __name__ == "__main__":
    main()
