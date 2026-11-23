# Lab 1G — Real pySigma-to-KQL conversion and SecurityEvent scoping

**State:** Actual pySigma Kusto backend conversion executed successfully in GitHub Actions, and the output has been saved. A **KQL-native synthetic test is prepared but has not yet been executed in Azure Data Explorer**. Real Microsoft Sentinel telemetry ingestion and production alerting remain unvalidated.

## Objective

Convert our [Sigma PowerShell encoded-command rule](../detections/sigma/proc_creation_win_powershell_encoded_command_lab.yml) to executable Kusto Query Language using a real conversion backend, not a manual reimplementation, then inspect field mappings and event source selection before attempting deployment.

## Backend and environment

- **Library:** pySigma **1.5.1**
- **Converter:** [pySigma Kusto backend](https://github.com/AttackIQ/pySigma-backend-kusto) **1.0.1**
- **Pipeline:** \`azure_monitor_pipeline(query_table="SecurityEvent")\`
- **Execution:** [GitHub Actions conversion run](https://github.com/Shermoh/threat-detection-lab/actions/runs/45110806730), **successful**, 2026-11-23 04:16 UTC.
- **Reproducer:** [\`tools/convert_sigma_to_kql.py\`](../tools/convert_sigma_to_kql.py)
- **Conversion CI:** [\`.github/workflows/sigma-conversion.yml\`](../.github/workflows/sigma-conversion.yml)
- **Snapshot consistency checks:** [\`tests/test_sigma_conversion.py\`](../tests/test_sigma_conversion.py)

The converter executes the pySigma rule parser and the backend; it isn't a hand-written Sigma-to-KQL converter.

## Result 1 — Actual generated query

The exact backend-generated KQL is saved here:

[\`detections/kql/generated/powershell_sigma_backend_raw.kql\`](../detections/kql/generated/powershell_sigma_backend_raw.kql)

\`\`\`kusto
SecurityEvent
| where (NewProcessName endswith "\\powershell.exe" or NewProcessName endswith "\\pwsh.exe") and CommandLine matches regex "(?i)(?:^|\\s)-(?:encodedcommand|enc)(?:\\s|:|$)"
\`\`\`

The Azure Monitor mapping correctly translates Sigma's:
- \`Image\` -> \`NewProcessName\`
- \`CommandLine\` -> \`CommandLine\`
- \`process_creation\` -> \`SecurityEvent\` (table)

**Important conversion gap:** The generated query **does not filter on EventID 4688**. That means a generic \`process_creation\` rule was translated to a table and field predicates, but the backend did not fully constrain the Windows Security event type. This is exactly the kind of gap a detection engineer must identify before deployment.

## Result 2 — Event-source-aware query

A separately reviewed, SecurityEvent-specific version is saved as:

[\`detections/kql/generated/powershell_sigma_securityevent_4688.kql\`](../detections/kql/generated/powershell_sigma_securityevent_4688.kql)

It preserves the backend-generated filter but adds:

\`\`\`kusto
| where EventID == 4688
\`\`\`

**This is an explicitly documented manual scoping step.** We are not claiming that the backend automatically produced the final 4688 filter. Other sources (Sysmon 1, Microsoft Defender XDR DeviceProcessEvents) need their own mapping/validation; this wrapper is not universally portable.

## Result 3 — Synthetic KQL validation harness

[\`tests/kql/sigma_conversion_validation.kql\`](../tests/kql/sigma_conversion_validation.kql) includes:

- A KQL \`datatable\` with the **20** existing fictional Windows event samples.
- The **same generated KQL predicate**, with \`EventID == 4688\` added for this source.
- Expected-match labels and a \`ValidationStatus\` column that checks the actual KQL results.
- A final result table designed to show **20 PASS / 0 FAIL**, with **9 matches and 11 nonmatches**.

**This test is ready but not yet run in the Kusto query engine.** The earlier **7 PASS / 0 FAIL** result in this repository relates to a *different session/IP correlation query*, not this Sigma-converted rule.

### How to run the test

1. Open [the test KQL file](../tests/kql/sigma_conversion_validation.kql) in GitHub.
2. Click **Raw** and copy the *entire* query.
3. In your authorized **Azure Data Explorer** query editor, paste and **Run**.
4. Confirm that **20 records** appear, all with **\`ValidationStatus = PASS\`**, with no FAILs.
5. Share a screenshot showing \`TestCase\`, \`ValidationStatus\`, \`ExpectedMatch\`, and \`ActualMatch\`. Record the UTC execution time and outcome.

The inline \`datatable\` means this test does not need real security logs or a paid Sentinel workspace.

## Verification and reproducibility

The conversion workflow uses the dedicated **pySigma 1.x + Kusto backend** environment. The earlier [Sigma YAML/parser tests](../tests/test_sigma_rule.py) use an independent pySigma 2.x environment; versions are intentionally isolated because the pinned Kusto backend requires pySigma 1.x.

The backend conversion's Python contract test checks:
- Actual backend output still matches the committed raw KQL snapshot.
- \`NewProcessName\` and \`CommandLine\` mapping is present.
- The raw output has no \`EventID\` restriction.
- The scoped version contains \`EventID == 4688\` followed by the unchanged backend predicate.
- The KQL test harness contains all 20 labelled fixture cases and the same predicate.

These static and Python tests do **not** execute the KQL engine. A completed Kusto test run will provide separate query-engine evidence.

## Remaining limitations

- Conversion was successful, but it does not establish production detection accuracy.
- A nonmatching suspicious renamed binary remains a known gap.
- Legitimate administrative encoded commands still match and need triage.
- This Sigma rule contains **no parent-process risk scoring or authentication correlation**; those are separate KQL exercises.
- KQL matching case sensitivity, regex engine compatibility, and actual \`SecurityEvent\` field availability must be verified in a target environment.
- There is no authorized live Microsoft Sentinel data or scheduled detection deployment included here.

## References

- [pySigma Kusto backend documentation](https://github.com/AttackIQ/pySigma-backend-kusto)
- [Microsoft SecurityEvent schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent)
- [Sigma conversion documentation](https://sigmahq.io/docs/digging-deeper/convert.html)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
