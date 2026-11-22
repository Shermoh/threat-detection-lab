# Investigating PowerShell encoded-command detections

**Detection:** [`detections/kql/powershell_encoded_command.kql`](../detections/kql/powershell_encoded_command.kql)

## Triage workflow

1. **Verify the event.** Confirm event ID 4688, full process image, command line, host, account, timestamp and event source.
2. **Examine execution context.** Review parent process, user session, process ancestry and whether the process fits documented administration or automation. Note: parent process is not included in the current KQL output.
3. **Inspect the encoded argument safely.** If authorized, decode the Base64 text as UTF-16LE for inspection, **never execute it**, and retain the original evidence.
4. **Correlate telemetry.** Look for related sign-ins, process creations, script block events (if collected), network connections, endpoint alerts and persistence indicators.
5. **Assess scope and intent.** A flag alone is insufficient to conclude compromise. Check for legitimate orchestration, scheduled jobs and approved management software.
6. **Document and escalate.** Record the evidence, confidence, affected assets and recommended next actions under the organization's response procedures.

## What the lab shows

The synthetic fixture contains **14** events. The filter raises **5** matches: **4** labeled suspicious and **1** benign (an expected false positive). It misses **1** suspicious event with a renamed executable. These values are fixture examples, **not** production precision, recall or benchmark results.

## Limitations

- `-EncodedCommand` is not inherently malicious. Legitimate administrative tools can use it.
- Renamed PowerShell binaries, alternate switch abbreviations, and other execution mechanisms are outside the current rule's scope.
- If Windows does not capture process command lines, this detection cannot evaluate the argument.
- `SecurityEvent` is not the same table as `DeviceProcessEvents` or `WindowsEvent`; field mappings require separate queries.
- The Python tests verify an offline logical equivalent using curated fixtures. **The KQL has not been executed in an Azure/Sentinel workspace** and needs platform validation before operational use.
- Command-line logs can contain secrets or personal data. Apply access controls and retention policies; do not publish raw enterprise events.

## Suggested next iteration

Add parent-process enrichment and tested context-based exclusions after collecting representative benign and malicious scenarios. Avoid suppressing an entire admin account or host without evidence.
