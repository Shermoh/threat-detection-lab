# Microsoft Sentinel KQL detection

[PowerShell encoded-command rule](powershell_encoded_command.kql) filters `SecurityEvent` records for Event ID 4688 and `-EncodedCommand` / `-enc` use, and categorizes matches using `ParentProcessName`.

The parent-process category supports triage; it is **not a determination of maliciousness**.

See [design notes](../../docs/first-detection-plan.md) and the [investigation guide](../../docs/investigation-guide.md).

**Validation:** Offline Python parity tests only. The KQL query has not been executed in a Microsoft Sentinel workspace.

## Tuning demonstration

[`powershell_encoded_command_tuned.kql`](powershell_encoded_command_tuned.kql) shows a **monitored** narrow maintenance downgrade for one synthetic case. It does not drop events. See the [S004 tuning exercise](../../docs/tuning-s004.md).

## Authentication correlation example

[`powershell_risk_correlation.kql`](powershell_risk_correlation.kql) joins encoded PowerShell process-creation records with recent 4625 logon failures on normalized host/account, then scores the combined signals. See the [full explanation](../../docs/risk-based-triage.md). **Not executed in Sentinel.**

### Session-aware source-IP experiment

[`powershell_session_ip_correlation.kql`](powershell_session_ip_correlation.kql) links 4688 process `SubjectLogonId` with prior 4624 `TargetLogonId` before counting 4625 failed logons from the successful session's source IP. See [lab 1D](../../docs/session-ip-correlation.md). **Not validated in Sentinel.**

### KQL-native validation instructions

The [session/IP synthetic validation query](../../tests/kql/session_ip_synthetic_validation.kql) is ready to run in a Kusto engine with an inline `datatable`; expected results: seven PASS rows, no failures. See the [validation playbook](../../docs/kql-validation-playbook.md). **KQL execution has not yet been completed.**
