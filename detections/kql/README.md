# Microsoft Sentinel KQL detection

[PowerShell encoded-command rule](powershell_encoded_command.kql) filters `SecurityEvent` records for Event ID 4688 and `-EncodedCommand` / `-enc` use, and categorizes matches using `ParentProcessName`.

The parent-process category supports triage; it is **not a determination of maliciousness**.

See [design notes](../../docs/first-detection-plan.md) and the [investigation guide](../../docs/investigation-guide.md).

**Validation:** Offline Python parity tests only. The KQL query has not been executed in a Microsoft Sentinel workspace.
