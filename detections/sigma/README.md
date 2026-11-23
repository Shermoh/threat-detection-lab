# Sigma detection lab

- [PowerShell EncodedCommand process creation (YAML)](proc_creation_win_powershell_encoded_command_lab.yml)
- [Detailed methodology and validation limits](../../docs/sigma-detection.md)
- [Offline pySigma parser and fixture tests](../../tests/test_sigma_rule.py)

The Sigma rule uses `logsource: {category: process_creation, product: windows}` and requires both the PowerShell image name and a standalone encoded-command switch. The parser/fixture checks expect **9 matched** and **11 nonmatched** synthetic events, including **two benign matches**.

**Status:** pySigma YAML parsing and offline fixture tests are automated by GitHub Actions. The rule has **not** been converted through an environment-specific backend and executed against real SIEM event telemetry. Treat the rule as experimental and investigate matches rather than assuming compromise.

## Kusto conversion

The same Sigma YAML has been [converted with a real pySigma Kusto backend](../../docs/sigma-to-kql-conversion.md). Read the [raw generated KQL](../kql/generated/powershell_sigma_backend_raw.kql) and the [reviewed SecurityEvent 4688-scoped version](../kql/generated/powershell_sigma_securityevent_4688.kql). Backend conversion and snapshot checks passed in CI; the [20-case KQL harness](../../tests/kql/sigma_conversion_validation.kql) has **not yet been run in Azure Data Explorer**.
