# First lab: suspicious PowerShell process creation

**Status:** KQL drafted, synthetic fixtures created, offline logic checks passing. **Not executed in Microsoft Sentinel.**

## Question

Which PowerShell process-creation events use the `-EncodedCommand` or `-enc` switch and should be examined further?

## Telemetry

This version is explicitly written for **Microsoft Sentinel's `SecurityEvent` table**, using Windows Security Event ID **4688** and the fields `TimeGenerated`, `EventID`, `Computer`, `Account`, `NewProcessName` and `CommandLine`.

Windows must enable **Audit Process Creation** and **Include command line in process creation events** to populate command-line details. Do not enable this without considering that arguments can contain sensitive information.

## Synthetic dataset and expected results

- 14 made-up Windows events in [`sample-data/windows_4688_synthetic.csv`](../sample-data/windows_4688_synthetic.csv).
- Five expected matches (S001–S005), including one benign legitimate encoded command (S004).
- One known miss: S013 uses a renamed executable (`psrunner.exe`).
- The detection matches suspicious *behaviour to investigate*, not a confirmed incident.

## Verification

Run the Python standard-library tests from the repository root:

```bash
python -m unittest discover -s tests -v
```

The tests mirror the KQL filters in Python and assert expected fixture results. They **do not execute the KQL**. Test in a Microsoft Sentinel workspace with appropriate, non-sensitive data before considering production use.

## Sources

- [Microsoft SecurityEvent schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent)
- [Windows event 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Windows command-line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)

For the analyst workflow and caveats, see [investigation guide](investigation-guide.md).
