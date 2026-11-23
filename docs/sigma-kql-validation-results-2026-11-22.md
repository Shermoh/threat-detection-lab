# Sigma-to-KQL validation results — 2026-11-22

## Observed outcome

**20 PASS / 0 FAIL** for the synthetic Sigma-to-KQL validation harness, verified from **two user-provided Azure Data Explorer/Kusto results screenshots** covering cases S001–S020.

- **Date recorded:** November 22, 2026 (local screenshot filenames / conversation date). The screenshots do **not** show a reliable UTC query-execution timestamp, so no exact UTC timestamp is asserted.
- **Environment:** Azure Data Explorer / Kusto query editor, as used in this portfolio's validation workflow.
- **Input:** Twenty fully fictional Windows-event rows declared inline using KQL `datatable`.
- **Test harness:** [`tests/kql/sigma_conversion_validation.kql`](../tests/kql/sigma_conversion_validation.kql).
- **Rule:** [PowerShell encoded-command Sigma YAML](../detections/sigma/proc_creation_win_powershell_encoded_command_lab.yml).
- **Source-scoped converted KQL:** [`detections/kql/generated/powershell_sigma_securityevent_4688.kql`](../detections/kql/generated/powershell_sigma_securityevent_4688.kql).
- **Actual backend output:** [`detections/kql/generated/powershell_sigma_backend_raw.kql`](../detections/kql/generated/powershell_sigma_backend_raw.kql).
- **Converter:** pySigma 1.5.1 + Kusto backend 1.0.1, with an explicitly added `EventID == 4688` filter (not automatically emitted by the backend).

## Results from the supplied screenshots

The screenshots show every case S001 through S020 and its `ValidationStatus`, `ExpectedMatch`, `ActualMatch`, `GroundTruth` and event details.

| Cases | Expected | Observed | Status |
| --- | --- | --- | --- |
| S001–S005 | Match | Match | 5 PASS |
| S006–S014 | No match | No match | 9 PASS |
| S015–S016 | Match | Match | 2 PASS |
| S017 | No match | No match | 1 PASS |
| S018–S019 | Match | Match | 2 PASS |
| S020 | No match | No match | 1 PASS |
| **Total** | **9 matches, 11 nonmatches** | **9 matches, 11 nonmatches** | **20 PASS, 0 FAIL** |

**Important cases:** S004 and S016 are labelled **benign** and are still detected; S013 is labelled **suspicious** but is not detected because it uses a renamed executable (`psrunner.exe`). The label-based PASS result means the query behaved as designed, **not** that the detection recognized every malicious scenario.

The query's `PASS` condition compares the **actual Kusto predicate result** to the test fixture's `ExpectedMatch` value. Its event-source-aware wrapper correctly excludes S012 and S020 (non-4688 events). The KQL test covers both the positive and negative selections, including case-insensitive command flags and executable-path matching.

## What was validated

1. Actual Kusto execution of the **backend-generated encoded-command selection**, with a documented **manual Windows Security 4688 filter**.
2. Expected matches and nonmatches across all twenty curated synthetic fixtures.
3. Independent Python/pySigma conversion snapshot checks and test workflows: [conversion CI](https://github.com/Shermoh/threat-detection-lab/actions/runs/45111002576) and [offline detection tests](https://github.com/Shermoh/threat-detection-lab/actions/runs/45111002558).

## What remains unvalidated

- The live Microsoft Sentinel `SecurityEvent` table's ingestion, schema, process-creation auditing, query schedules and data quality.
- Production effectiveness, detection rates, false-positive rates, and handling of additional real-world PowerShell switch variants.
- Any claim that `-EncodedCommand` alone proves malicious activity.
- The more advanced parent-process, risk scoring and session-correlation KQL rules; these are **separate** from this Sigma conversion harness.

**Evidence handling:** The two result screenshots were reviewed in the conversation but **not uploaded to the public repository**. This report records their visible outcomes without real tenant data or customer telemetry.

## Next portfolio milestone

The synthetic Kusto-engine check is complete. The next useful project is a **simulated identity-compromise investigation** with an incident timeline, hypothesis/evidence matrix, detection logic, containment recommendations and a clearly documented synthetic evidence set. If real Sentinel telemetry becomes available under explicit authorization, that can become a separate integration-validation exercise.
