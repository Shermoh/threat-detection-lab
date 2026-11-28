# IR-001 — Suspicious document-to-PowerShell execution

**Case type:** Fictional, evidence-driven incident-response investigation  
**Status:** Synthetic investigation documented; no real endpoint or organization was affected  
**Priority recommendation:** High-priority suspected incident; confirm authorization and scope  
**Case date:** 2026-11-18 UTC (fictional)

## Executive synopsis

An externally delivered document, `Review_Nov2026.docm`, was followed by three failed remote logons and a successful logon to **LAB-WIN07**. Windows process-creation records show Word launching encoded PowerShell within the same recorded logon session. A 4104 script-block record shows a command attempting to download `stage.ps1` from a fictional domain. A proxy returned **403 / zero bytes delivered for that request**, while a scheduled task pointing to that script path was registered shortly afterward.

**Confirmed observations:** suspicious process chain, PowerShell script-block content, blocked proxy request, and scheduled task registration.  
**Not established:** whether the remote logon was unauthorized, whether a payload executed successfully, whether the scheduled task ever ran, or whether additional hosts were compromised.

Do **not** infer that one blocked request closes the incident.

## Evidence package

| Resource | Purpose |
| --- | --- |
| [Synthetic event records](data/events.csv) | Fifteen source-labelled events, including unrelated control records |
| [Chronological timeline](docs/timeline.md) | UTC order, host and session relationships |
| [Evidence and hypotheses](docs/evidence-matrix.md) | Fact-versus-inference analysis, confidence and gaps |
| [Investigation report](docs/incident-report.md) | Executive summary, findings, scope, MITRE mapping and assessment |
| [Containment decisions](docs/response-decisions.md) | Authorized actions, preservation steps and closure conditions |
| [Analyst questions](docs/analyst-exercise.md) | Practice investigation decisions without reading the answer first |
| [Timeline generator](../../tools/ir001_timeline.py) | Standard-library Python script to reproduce a timeline/summary |
| [Automated tests](../../tests/test_ir001_case.py) | Checks chronology, identity correlation and evidence consistency |

## Optional follow-up: Task execution and registry persistence

The [IR-001 task-execution follow-up](follow-up-task-execution/README.md) adds **two clearly separate, fictional evidence packets** without changing the original 15-event investigation. One packet contains Task Scheduler action/launch/completion events, corroborating PowerShell process execution and registry Run-key modification; the other contains same-name decoys on a different host. [Python correlation checks](../../tests/test_ir001_task_followup.py) cover both.

This is a **what-if extension**, not retrospective proof that the original task ran. The corresponding data and conclusions must not be merged with the original intake evidence.

## Reproduce the analysis

Requires Python 3.11+; no external packages for this case-study script:

```bash
python tools/ir001_timeline.py
python tools/ir001_timeline.py --json
python -m unittest discover -s tests -p test_ir001_case.py -v
```

This prints the fictional timeline and an evidence summary, safely **decoding** (not executing) the synthetic PowerShell Base64 string.

## Investigation boundaries

- Windows 4625 = failed logon; 4624 = successful logon, type 10 = RemoteInteractive in this fictional example.
- Windows 4688 = process creation; parent PID and matching logon ID help connect Word to PowerShell.
- PowerShell 4104 = script-block log **when that telemetry is collected**.
- Windows 4698 = scheduled task **creation**, not proof the task ran.
- DNS, proxy, EDR and email fields in the dataset are **invented normalized records**, not direct exports of vendor-specific log schemas.

All accounts, hostnames, documents, IP addresses, and detections are fabricated. The domain `example.invalid` and reserved documentation IP ranges cannot be used as evidence about real infrastructure. No real phishing artifact, live malware, actual customer event, or employer telemetry is involved.

## Professional takeaway

A credible incident investigation distinguishes **observed telemetry**, **analyst hypotheses**, **missing evidence**, and **proposed response actions**. It reports uncertainty rather than declaring complete compromise or safe closure based on one control's verdict.
