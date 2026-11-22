# First lab plan: suspicious PowerShell process creation

**Status:** Design — no detection implemented or validated yet.

## Detection question

Can we identify PowerShell executions with suspicious launch patterns that warrant investigation, without classifying all scripted administration as malicious?

## Telemetry and assumptions

- Windows Security Event 4688 can record process creation; command-line information depends on auditing configuration.
- Sysmon Event 1 is another process-creation option when Sysmon is deployed.
- Data field names differ between SIEM platforms. A later KQL rule will name a specific table/schema instead of implying universal compatibility.

## Synthetic scenarios to build

| Case | Example behaviour | Expected handling |
| --- | --- | --- |
| P1 | PowerShell launched with `-EncodedCommand` | Investigate; possible positive |
| P2 | PowerShell launched with a hidden window and unusual command line | Investigate; possible positive |
| N1 | Administrator runs a simple `Get-Service` query | Generally benign |
| N2 | Routine scripted maintenance uses PowerShell | Context-dependent; avoid broad over-alerting |

An encoded command or hidden window is **not inherently malicious**. Actual detection design should use corroborating context such as process ancestry, user, host, script content, and frequency where available.

## Validation checklist

1. Create synthetic sample records with known ground-truth labels.
2. Implement KQL query against an explicitly defined event schema.
3. Run positive and negative tests and record outcomes.
4. Identify likely false positives and tune logic.
5. Explain how an analyst would triage a matching event.

## Next step

Create the synthetic event dataset and establish an explicit table/field schema before writing the first KQL detection.
