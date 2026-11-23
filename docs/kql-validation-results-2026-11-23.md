# KQL synthetic validation — observed results (2026-11-23)

## Outcome

**PASS — seven of seven expected cases, zero failed cases.**

A user-run KQL datatable test returned seven result rows with `ValidationStatus = PASS`. The results were verified from a user-provided screenshot of the KQL query editor, timestamped **2026-11-23 04:04 UTC** (November 22 in Edmonton, Alberta). The interface showed **Done (0.198 s)** and **7 records**.

**Execution environment:** Azure Data Explorer / Kusto query editor, as used in this project's validation workflow. The test uses *inline synthetic data*, not collected endpoint logs. This is **KQL-engine validation of the synthetic harness**, not Microsoft Sentinel ingestion or a production analytics-rule deployment.

**Query under test:** [`tests/kql/session_ip_synthetic_validation.kql`](../tests/kql/session_ip_synthetic_validation.kql), originally committed in [6c310e6](https://github.com/Shermoh/threat-detection-lab/commit/6c310e6a898a084cb84663b1f5f32d6a6a2c3e5e).

## Observed comparison

The screenshot visibly shows these values:

| Test case | Validation | Expected failures | Actual failures | Expected points | Actual points | Expected band | Actual band |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| P001 | PASS | 0 | 0 | 5 | 5 | Low | Low |
| P002 | PASS | 3 | 3 | 55 | 55 | High | High |
| P003 | PASS | 0 | 0 | 5 | 5 | Low | Low |
| P004 | PASS | 0 | 0 | 15 | 15 | Low | Low |
| P005 | PASS | 0 | 0 | 55 | 55 | High | High |
| P007 | PASS | 0 | 0 | 15 | 15 | Low | Low |
| P008 | PASS | 0 | 0 | 15 | 15 | Low | Low |

The KQL harness computes `PASS` only if failed-logon counts, risk points, risk bands, **and triage dispositions** match expected values. The screenshot does **not** visibly display the disposition columns, but it does display the resulting PASS status for each row.

## What this proves

- The complete synthetic test ran successfully in a Kusto-compatible query engine.
- The seven fixture scenarios produced the expected risk counts and bands.
- The different-source-IP test (P003) did not inflate the failed-logon count.
- The replay-with-correlated-failures test (P002) was escalated to High.
- The query returned no unexpected or missing cases according to the full-outer-join validation query.

## What this does **not** prove

- That the live `SecurityEvent` table has the same field types or values as the inline `datatable`.
- That Windows event auditing, Microsoft Sentinel ingestion, source-IP attribution, and logon-session correlations work in a real environment.
- That the illustrative risk scores accurately estimate maliciousness or that production alerting performance has been measured.
- That earlier KQL variants in this repository have been validated.

No tenant identifiers, real customer telemetry, or private workspace details are included in this record. The screenshot was reviewed in the conversation; it has **not** been posted to the public repository.

## Next validation gate

Run [the actual session/IP KQL](../detections/kql/powershell_session_ip_correlation.kql) against authorized `SecurityEvent` telemetry in a properly configured test environment, inspect data quality and event mappings, and evaluate real false-positive/false-negative behaviour before considering operational deployment.
