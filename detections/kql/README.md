# Microsoft Sentinel KQL

- [`powershell_encoded_command.kql`](powershell_encoded_command.kql) — filters Windows process-creation Event ID 4688 for encoded PowerShell command arguments.

**Target schema:** `SecurityEvent` in Azure Monitor / Microsoft Sentinel. This query has **not** been executed in a live Sentinel workspace; the provided Python tests mirror its logic offline and do not validate KQL execution.

See the [design notes](../../docs/first-detection-plan.md) and [investigation guide](../../docs/investigation-guide.md).
