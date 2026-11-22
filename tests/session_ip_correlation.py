"""Standalone offline session-aware correlation lab.

Uses only synthetic Windows event fixtures. KQL is NOT executed by these tests.
"""
import csv
from datetime import datetime, timedelta
from pathlib import Path

from test_detection import matches_detection
from test_tuning import known_maintenance

DATA_PATH = Path(__file__).resolve().parents[1] / "sample-data" / "session_ip_correlation.csv"
SESSION_WINDOW = timedelta(minutes=30)
FAILURE_WINDOW = timedelta(minutes=15)
UNUSUAL_PARENTS = {
    "winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
}
UNUSABLE_IPS = {"", "-", "127.0.0.1", "::1", "0.0.0.0"}
INVALID_SESSION_IDS = {"", "-", "0x0", "0"}


def load_events():
    with DATA_PATH.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def instant(event):
    return datetime.fromisoformat(event["TimeGenerated"].replace("Z", "+00:00"))


def target_actor(event):
    domain = (event.get("TargetDomainName") or "").strip()
    user = (event.get("TargetUserName") or "").strip()
    return (domain + "\\" + user).casefold() if domain and user else ""


def linked_success(process, events):
    """Link 4688 SubjectLogonId to prior 4624 TargetLogonId on same host/account.

    The link identifies an observed session candidate, not proof of causality.
    """
    key = (process.get("SubjectLogonId") or "").casefold()
    if key in INVALID_SESSION_IDS:
        return None
    host = (process.get("Computer") or "").casefold()
    actor = (process.get("Account") or "").casefold()
    candidates = [
        event for event in events
        if event["EventID"] == "4624"
        and (event.get("Computer") or "").casefold() == host
        and target_actor(event) == actor
        and (event.get("TargetLogonId") or "").casefold() == key
        and timedelta(0) <= instant(process) - instant(event) <= SESSION_WINDOW
    ]
    return max(candidates, key=instant, default=None)


def prior_failures_for_session(session, events):
    """4625 shares host, account, and source IP in preceding 15 minutes."""
    if session is None:
        return 0
    ip = (session.get("IpAddress") or "").strip().casefold()
    if ip in UNUSABLE_IPS:
        return 0
    start = instant(session) - FAILURE_WINDOW
    end = instant(session)
    host = (session.get("Computer") or "").casefold()
    actor = target_actor(session)
    return sum(
        1 for event in events
        if event["EventID"] == "4625"
        and (event.get("Computer") or "").casefold() == host
        and target_actor(event) == actor
        and (event.get("IpAddress") or "").strip().casefold() == ip
        and start <= instant(event) <= end
    )


def score_event(process, events):
    if not matches_detection(process):
        return None
    session = linked_success(process, events)
    source_ip = (session.get("IpAddress") or "").strip() if session else ""
    usable_ip = source_ip.casefold() not in UNUSABLE_IPS
    status = (
        "No reliable 4624 session match" if session is None
        else "Linked; source IP unavailable" if not usable_ip
        else "Linked with source IP"
    )
    parent = (process.get("ParentProcessName") or "").replace("/", "\\").lower()
    parent_name = parent.rsplit("\\", 1)[-1]
    parent_points = 35 if parent_name in UNUSUAL_PARENTS else (10 if not parent else 0)
    maintenance = known_maintenance(process)
    failures = prior_failures_for_session(session, events)
    auth_points = 50 if failures >= 3 else (10 if failures >= 1 else 0)
    points = 20 - (15 if maintenance else 0) + parent_points + auth_points
    points += 0 if usable_ip else 10
    band = "High" if points >= 55 else ("Medium" if points >= 30 else "Low")
    return {
        "CaseID": process["CaseID"],
        "SessionLinked": session is not None,
        "SessionStatus": status,
        "SourceIp": source_ip if usable_ip else "",
        "MatchedSessionId": session["CaseID"] if session else "",
        "FailedSameIp15m": failures,
        "KnownMaintenance": maintenance,
        "RiskPoints": points,
        "RiskBand": band,
        "TriageDisposition": band if usable_ip else "Review: identity context incomplete",
    }


def scores_for_fixture(events):
    return {
        event["CaseID"]: result
        for event in events
        if (result := score_event(event, events)) is not None
    }


if __name__ == "__main__":
    for case, result in sorted(scores_for_fixture(load_events()).items()):
        print(f"{case}: {result['RiskBand']} ({result['RiskPoints']} pts), "
              f"linked session={result['MatchedSessionId'] or 'none'}, "
              f"same-IP prior failures={result['FailedSameIp15m']}, "
              f"disposition={result['TriageDisposition']}")
