"""Offline educational correlation and risk-based triage scoring.

Runs against fictitious fixtures only. It does NOT execute Microsoft Sentinel
KQL, validate production field mappings or prove compromise.
"""
import csv
from datetime import datetime, timedelta
from pathlib import Path

from test_detection import matches_detection
from test_tuning import known_maintenance

ROOT = Path(__file__).resolve().parents[1]
PROCESS_CSV = ROOT / "sample-data" / "windows_4688_synthetic.csv"
CORRELATION_CSV = ROOT / "sample-data" / "rba_auth_correlation.csv"

UNUSUAL_PARENTS = {
    "winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
}
AUTH_WINDOW = timedelta(minutes=15)


def read_csv(path):
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def load_fixture_events():
    return read_csv(PROCESS_CSV) + read_csv(CORRELATION_CSV)


def timestamp(event):
    return datetime.fromisoformat(event["TimeGenerated"].replace("Z", "+00:00"))


def actor_for_auth(event):
    domain = (event.get("TargetDomainName") or "").strip()
    username = (event.get("TargetUserName") or "").strip()
    return (domain + "\\" + username).casefold() if domain and username else ""


def count_recent_failures(process, events):
    start = timestamp(process) - AUTH_WINDOW
    end = timestamp(process)
    host = (process.get("Computer") or "").casefold()
    actor = (process.get("Account") or "").casefold()
    if not host or not actor:
        return 0
    return sum(
        1 for ev in events
        if int(ev["EventID"]) == 4625
        and (ev.get("Computer") or "").casefold() == host
        and actor_for_auth(ev) == actor
        and start <= timestamp(ev) <= end
    )


def risk_result(process, events):
    """Return scoring detail for a matching encoded PowerShell process."""
    if not matches_detection(process):
        return None
    parent = (process.get("ParentProcessName") or "").replace("/", "\\").lower()
    parent_name = parent.rsplit("\\", 1)[-1]
    unusual = parent_name in UNUSUAL_PARENTS
    approved = known_maintenance(process)
    failures = count_recent_failures(process, events)
    base = 20
    adjustment = -15 if approved else 0
    parent_points = 35 if unusual else (10 if not parent else 0)
    auth_points = 50 if failures >= 3 else (10 if failures >= 1 else 0)
    points = base + adjustment + parent_points + auth_points
    band = "High" if points >= 55 else ("Medium" if points >= 30 else "Low")
    return {
        "CaseID": process["CaseID"],
        "FailedLogons15m": failures,
        "KnownMaintenance": approved,
        "ParentPoints": parent_points,
        "AuthPoints": auth_points,
        "RiskPoints": points,
        "RiskBand": band,
    }


def score_all(events):
    return {
        event["CaseID"]: result
        for event in events
        if (result := risk_result(event, events)) is not None
    }


if __name__ == "__main__":
    for case_id, result in sorted(score_all(load_fixture_events()).items()):
        print(
            f"{case_id}: {result['RiskBand']} "
            f"({result['RiskPoints']} points), "
            f"prior failed logons={result['FailedLogons15m']}"
        )
