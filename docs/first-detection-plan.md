# Lab 1 — Suspicious PowerShell process creation

**State:** KQL drafted and offline fixtures/tests prepared. **KQL has not been run in Microsoft Sentinel.**

## Detection question

Which PowerShell process-creation events use the encoded-command argument and merit investigation? Can immediate parent-process context help prioritize review without assuming that every encoded command is malicious?

## Data source

The query targets Microsoft Sentinel / Azure Monitor **SecurityEvent**, using Windows Security **Event ID 4688**.

Required fields: `TimeGenerated`, `EventID`, `Computer`, `Account`, `NewProcessName`, and `CommandLine`. The optional `ParentProcessName` field provides the immediate parent-process name.

**Important:** Windows **Audit Process Creation** and **Include command line in process creation events** must be configured for command-line content to be available. Command-line collection can expose sensitive arguments, so protect it appropriately.

## Triage categories

| Category | Logic | Interpretation |
| --- | --- | --- |
| Elevated - unusual parent | Encoded PowerShell child of Office or selected script-host processes | Higher-priority investigation cue, not proof of compromise |
| Review - encoded command | Encoded PowerShell with a different parent | Assess authorized automation and related activity |
| Review - parent unavailable | Encoded PowerShell but missing `ParentProcessName` | Obtain additional context; don't silently dismiss |
| No alert | Process name, flag or event ID does not match | Outside the scope of this query |

Unusual-parent list: `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe`, `wscript.exe`, `cscript.exe` and `mshta.exe`. These are heuristic indicators, **not reliable standalone indicators of compromise**.

## Synthetic fixture observations

Dataset: [20 fictional events](../sample-data/windows_4688_synthetic.csv).

- **9 expected matches:** four elevated, four review, one parent unavailable.
- **2 benign matches:** approved maintenance service uses encoded PowerShell (false positives by ground-truth label).
- **1 missed suspicious case:** renamed executable `psrunner.exe` falls outside exact process-name matching.
- An Office parent without the encoded-command flag must not alert, and a non-4688 event must not alert even if its sample command line contains the switch.

These cases were deliberately constructed and do not measure real-world efficacy.

## Offline validation

Run:

```bash
python -m unittest discover -s tests -v
```

Tests execute a **Python interpretation** of the detection predicate and triage categories against the synthetic CSV. This verifies internal fixture expectations, **not KQL compilation, table mapping, or results in Sentinel**.

## References

- [Microsoft SecurityEvent reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent)
- [Windows security event 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Command-line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [KQL regular expression syntax](https://learn.microsoft.com/en-us/kusto/query/re2)
- [MITRE ATT&CK: T1059.001](https://attack.mitre.org/techniques/T1059/001/)

See [investigation guide](investigation-guide.md) for analyst workflow and tuning considerations.
