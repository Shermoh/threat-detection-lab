"""IR-001 follow-up: correlate synthetic Task Scheduler execution evidence.

The initial IR-001 dataset remains unchanged. This tool reads a separate,
what-if evidence packet and NEVER executes PowerShell or scheduled tasks.
"""
import argparse
import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "case-studies/IR-001-word-powershell/follow-up-task-execution/events.csv"
TARGET_HOST = "LAB-WIN07"
TARGET_ACCOUNT = r"LAB\jane"
TARGET_TASK = r"\UpdateHealthCheck"
RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
REQUIRED = {
    "scenario", "evidence_id", "timestamp_utc", "provider", "event_code",
    "host", "account", "task_name", "instance_id", "process_id",
    "command_or_artifact", "result_code", "details",
}


def ts(event):
    return datetime.fromisoformat(event["timestamp_utc"].replace("Z", "+00:00"))


def load_events(path=DATA):
    with Path(path).open(newline="", encoding="utf-8") as fd:
        reader = csv.DictReader(fd)
        if not REQUIRED.issubset(set(reader.fieldnames or [])):
            raise ValueError("Required IR-001 follow-up fields missing")
        events = list(reader)
    ids = [e["evidence_id"] for e in events]
    if not events or len(ids) != len(set(ids)):
        raise ValueError("Missing or duplicate follow-up evidence IDs")
    for e in events:
        ts(e)
    return sorted(events, key=lambda e: (ts(e), e["evidence_id"]))


def investigate(events, host=TARGET_HOST, account=TARGET_ACCOUNT, task=TARGET_TASK):
    """Find a linked Task Scheduler 200 -> 129 -> Windows 4688 -> 201.

    TaskScheduler 129 includes a PID; raw 4688 lacks task instance ID.
    Join by same host/account/PID/command and a short time window. This
    is an illustrative correlation, not universal causal proof.
    """
    rows = list(events)
    matches = lambda e: e["host"] == host and e["account"] == account
    starts = sorted(
        (e for e in rows if matches(e) and e["provider"] == "TaskSchedulerOperational"
         and e["event_code"] == "200" and e["task_name"] == task
         and e["instance_id"]),
        key=ts,
    )
    links = []
    for start in starts:
        launch = next((
            e for e in rows
            if matches(e) and e["provider"] == "TaskSchedulerOperational"
            and e["event_code"] == "129" and e["task_name"] == task
            and e["instance_id"] == start["instance_id"]
            and e["process_id"]
            and ts(start) <= ts(e) <= ts(start) + timedelta(seconds=10)
        ), None)
        process = None
        if launch:
            process = next((
                e for e in rows
                if matches(e) and e["provider"] == "WindowsSecurity"
                and e["event_code"] == "4688"
                and e["process_id"] == launch["process_id"]
                and e["command_or_artifact"] == launch["command_or_artifact"]
                and ts(launch) <= ts(e) <= ts(launch) + timedelta(seconds=10)
            ), None)
        completion = next((
            e for e in rows
            if matches(e) and e["provider"] == "TaskSchedulerOperational"
            and e["event_code"] == "201" and e["task_name"] == task
            and e["instance_id"] == start["instance_id"]
            and ts(start) <= ts(e) <= ts(start) + timedelta(hours=1)
        ), None)
        links.append((start, launch, process, completion))

    best = next((x for x in links if x[1] and x[2]), links[0] if links else None)
    if best:
        start, launch, process, complete = best
        pid = process["process_id"] if process else ""
        start_time = ts(start)
    else:
        start = launch = process = complete = None
        pid = ""
        start_time = None

    def same_process(e):
        return bool(process) and matches(e) and e["process_id"] == pid and (
            ts(process) <= ts(e) <= ts(process) + timedelta(minutes=5)
        )

    scriptblocks = [
        e for e in rows if same_process(e)
        and e["provider"] == "PowerShellOperational" and e["event_code"] == "4104"
    ]
    registry_changes = [
        e for e in rows if same_process(e)
        and e["provider"] == "WindowsSecurity" and e["event_code"] == "4657"
        and e["command_or_artifact"].startswith(RUN_KEY + "|")
    ]
    snapshots = [
        e for e in rows
        if matches(e) and e["provider"] == "EDRRegistrySnapshot"
        and e["command_or_artifact"].startswith(RUN_KEY + "|")
        and (not registry_changes or ts(e) >= min(ts(c) for c in registry_changes))
    ]
    confirmed_write = bool(scriptblocks and registry_changes and snapshots)
    return {
        "host": host,
        "task": task,
        "scheduler_action_start_observed": bool(start),
        "scheduler_129_process_launch_observed": bool(launch),
        "correlated_4688_process_observed": bool(process),
        "scheduler_action_completion_observed": bool(complete),
        "task_instance_id": start["instance_id"] if start else None,
        "correlated_process_id": pid or None,
        "action_return_code": complete["result_code"] if complete else None,
        "powershell_4104_observed": bool(scriptblocks),
        "registry_4657_observed": bool(registry_changes),
        "registry_value_present_in_followup": bool(snapshots),
        "registry_persistence_configuration_supported": confirmed_write,
        "autorun_triggered_observed": False,
        "script_exit_success_confirmed": False,
        "conclusion": (
            "Task action start and linked PowerShell process observed; "
            "nonzero result does not negate changes before completion. "
            "Registry Run value was modified and observed later; autorun not observed."
            if process and confirmed_write else
            "Task action and process launch observed; script outcome unresolved."
            if process else
            "Task Scheduler action start observed; corresponding process not verified."
            if start else
            "No execution observed for this host/task in available follow-up telemetry."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze synthetic IR-001 task evidence")
    parser.add_argument("--scenario", choices=["FOLLOWUP_A", "UNRELATED_B"],
                        default="FOLLOWUP_A", help="Which mutually separate evidence packet to use")
    args = parser.parse_args()
    events = [e for e in load_events() if e["scenario"] == args.scenario]
    print(json.dumps(investigate(events), indent=2))


if __name__ == "__main__":
    main()
