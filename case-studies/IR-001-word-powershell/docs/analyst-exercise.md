# IR-001 — Analyst decision exercise

Before reading the [case report](incident-report.md), review only the [synthetic evidence](../data/events.csv) and [timeline](timeline.md).

Record brief, evidence-backed answers:

1. **Intake:** What is the strongest observed indicator that merits escalation? Cite the event IDs.
2. **Authentication:** Do the 4625/4624 records establish credential theft? What additional information would change your conclusion?
3. **Process and script:** Is `WINWORD.EXE → powershell.exe` directly supported? Decode the encoded command safely and compare it with 4104.
4. **Outcome:** Can you conclude the downloader succeeded or failed *everywhere* because one proxy recorded a 403?
5. **Persistence:** What does 4698 establish about the scheduled task, and what would prove execution?
6. **Scope:** Should the LAB-WIN08 task be included? What about the second email recipient?
7. **Response:** What will you contain immediately, under what authority, and what evidence must be preserved first?
8. **Classification:** Is this suspicious, a confirmed malicious incident, or confirmed full-system compromise? Separate certainty about recorded events from uncertainty about authorization and impact.

## Review rubric

A strong answer names **specific event IDs**, differentiates **facts from hypotheses**, acknowledges **telemetry gaps**, orders response steps according to evidence-preservation and authority, and avoids inventing attacker identity, malicious file hashes, confirmed exfiltration, or lateral movement.

When done, compare with the [evidence matrix](evidence-matrix.md), [report](incident-report.md), and [response decisions](response-decisions.md).
