# Detection tuning exercise — S004 approved maintenance

## Reason for tuning

The baseline rule detects PowerShell with encoded-command arguments. In the synthetic dataset, **S004** is authorized maintenance launched under a service account. Excluding all encoded commands or the service account would create unacceptable visibility gaps.

**Important:** Several synthetic events share the same Base64 argument, so suppressing just the encoded string would also hide suspicious examples.

## Demonstration

- [Monitored KQL tuning variant](../detections/kql/powershell_encoded_command_tuned.kql)
- [Offline tests](../tests/test_tuning.py)

The tuned variant keeps every encoded-command match in the result set. It marks **S004 only** as \`Known maintenance - monitor\` when **all** of these lab-specific facts match:

1. Host \`LAB-WIN04\`.
2. Service account \`LAB\\svc-maint\`.
3. Immediate parent-process path ending in \`\\services.exe\`.
4. Exact case-insensitive command line \`powershell.exe -EncodedCommand QQBCAEMA\`.

Other executions, including **S016**, are still reviewed. This is a **triage downgrade**, not a production suppression rule or a definitive benign verdict.

## Why this still has risk

A compromised account or process could replay the same command and produce identical visible fields. **An event that is indistinguishable on these fields cannot be reliably adjudicated as benign by this rule.** We retain the event for review and recommend additional corroboration: approved scheduled task identity, executable/script signatures or hashes, change tickets, timing, process ancestry and subsequent activity. Such telemetry is not present in the current synthetic dataset.

Before applying a real-world tuning change, analysts should:
- Confirm the task, owner, scope and expected behavior.
- Establish a limited review period and measurable criteria.
- Review sampled downgraded events and monitor unexpected drift.
- Check for additional detections covering abuse of the same service account.
- Document who approved the change and how to reverse it.

## Testing limitations

The Python tests check synthetic logical equivalence; they do not run KQL in Sentinel. The example is not a safe production allowlist template, and its fictional parameters must be replaced only after local validation.
