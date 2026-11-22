# Investigating encoded-command PowerShell alerts

**Detection:** [PowerShell encoded-command KQL](../detections/kql/powershell_encoded_command.kql)

## Analyst triage workflow

1. **Verify the event.** Check Event ID, process image, command line, account, device and timestamp.
2. **Review the parent context.** Inspect `ParentProcessName` and the assigned `TriageCategory`. Office and script-host ancestry deserve attention, but don't by themselves prove compromise.
3. **Confirm the actual process tree.** Correlate with endpoint data and other process-creation events, especially if the parent field is missing or inconsistent.
4. **Analyze command content safely.** If authorized, extract Base64 content and decode as UTF-16LE for inspection only; **do not execute decoded output**. Preserve evidence and respect sensitive-data handling requirements.
5. **Correlate supporting events.** Review additional process starts, sign-ins, script block logging (if available), network connections and endpoint detections.
6. **Evaluate legitimacy and scope.** Compare with change records and approved automation. An encoded argument or unusual parent is a hypothesis to investigate.
7. **Record and escalate appropriately.** Document evidence, assumptions, impact, uncertainty and recommendations. Follow actual incident-response authority.

## Outcomes in our fictional dataset

- 20 sample events; **9** match the filter (4 elevated, 4 routine review, 1 parent unavailable).
- **2** matched events represent legitimate maintenance (intentional false positives).
- **1** suspicious renamed executable is missed (intentional false negative).

The numbers illustrate test cases, **not actual customer environments or production detection metrics**.

## Technical and operational limitations

- The KQL covers `SecurityEvent` event 4688 and requires collected command-line arguments.
- The parent-process name is a single field, not a complete validated process tree; it may be absent or misleading.
- Renamed executables, alternate invocations and PowerShell without an identifiable process are not covered.
- No aggressive service-account or host exclusion has been applied. First demonstrate that exclusions are safe and monitor their effect.
- The Python test suite checks a mirror of the KQL filtering. **Actual Sentinel integration remains untested.**
- Command-line evidence may contain sensitive information; avoid posting real events or authentication details publicly.

## Next tuning exercise

Compare cases where unusual parent processes occur legitimately against suspicious parent-child chains. Add corroborating telemetry and narrowly justified tuning, not blanket suppression.
