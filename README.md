# Threat Detection Lab

A hands-on security portfolio project covering **SIEM detection engineering, security investigation, and detection validation**. All data is synthetic.

## Lab 1: PowerShell encoded-command execution with process context

**Status:** Query, synthetic data, and offline Python tests available. **The KQL has not been executed in a live Microsoft Sentinel workspace.**

| Resource | Contents |
| --- | --- |
| [KQL detection](detections/kql/powershell_encoded_command.kql) | Queries Windows Security Event 4688 and adds parent-process triage context |
| [Synthetic events](sample-data/windows_4688_synthetic.csv) | 20 illustrative benign, suspicious, and incomplete-context cases |
| [Python tests](tests/test_detection.py) | Tests a Python mirror of filtering and triage decisions |
| [Detection design](docs/first-detection-plan.md) | Schema, assumptions, test cases, limitations and references |
| [Investigation guide](docs/investigation-guide.md) | Analyst triage workflow and tuning considerations |

### Detection workflow

1. Filter the Microsoft Sentinel `SecurityEvent` table for Windows **Event ID 4688**.
2. Identify `powershell.exe` or `pwsh.exe` launched with `-EncodedCommand` or `-enc`.
3. Examine `ParentProcessName` to prioritize unexpected parents (Office applications and selected script hosts), with a separate category for missing parent information.
4. Investigate and correlate further evidence. **Encoded PowerShell or an unusual parent does not establish maliciousness.**

**Data prerequisite:** Process creation auditing with command-line capture and correctly mapped `SecurityEvent` data.

### Run offline tests

Requires Python 3.8+; no third-party packages.

```bash
python -m unittest discover -s tests -v
```

The curated dataset has **20** fictional events, including **9** expected matches: **4 elevated**, **4 standard review**, and **1 with parent information unavailable**. Among the matches, two are deliberately benign (false positives), while one suspicious renamed executable is not matched (false negative). **These synthetic counts are not production performance metrics.**

**Test limitation:** Python tests mirror the query's predicate and triage logic; they **do not execute KQL**. Live Sentinel validation is still required.

## Lab 1B — Narrow maintenance tuning

The [tuning exercise](docs/tuning-s004.md) explores your suggestion to match a specific verified command rather than ignore all encoded PowerShell. It includes a [monitored KQL variant](detections/kql/powershell_encoded_command_tuned.kql) and [offline tests](tests/test_tuning.py).

**S004** is labeled `Known maintenance - monitor` only when its host, service account, parent process and exact command match. It **remains visible** in results; the original detection is unchanged. **S016** and all other matches still receive their ordinary investigation categories.

The example also demonstrates a limitation: an attacker able to reproduce all the same observable fields cannot be distinguished by this simple allowlist. It is not a recommended production suppression rule.

## Lab 1C — Correlated authentication risk signals

This [risk-based triage exercise](docs/risk-based-triage.md) combines encoded-PowerShell process events with **Windows 4625 failed logons** for the same host/account during the preceding 15 minutes. It includes:

- [Sentinel KQL correlation query](detections/kql/powershell_risk_correlation.kql)
- [Additional synthetic authentication and replay events](sample-data/rba_auth_correlation.csv)
- [Offline scoring implementation](tests/risk_scoring.py) and [unit tests](tests/test_risk_scoring.py)

**Key example:** S004 remains **Low (5 points)** as routine maintenance; **R001**, which uses the *same approved host, account, parent and command*, becomes **High (55 points)** when three prior failed logons are correlated. The score is an illustrative triage heuristic, **not a measured probability of compromise**. Field mappings, correlation quality and KQL syntax require platform testing.

[View automated test runs](https://github.com/Shermoh/threat-detection-lab/actions).

## Lab 1D — Session-aware source-IP correlation

The [session and IP correlation exercise](docs/session-ip-correlation.md) improves on the earlier account/host-only join by linking a **4624 successful logon** to a **4688 process** using a recent, same-host/account logon ID, then checking **4625 failures** from the same source IP before the successful logon.

- [KQL demonstration](detections/kql/powershell_session_ip_correlation.kql)
- [29 synthetic Windows logon/process events](sample-data/session_ip_correlation.csv)
- [Python correlation model](tests/session_ip_correlation.py) and [offline tests](tests/test_session_ip_correlation.py)

**Example:** P001 (approved maintenance) remains **Low (5 points)**; P002 (same approved command, three same-IP failures preceding its linked logon) is **High (55 points)**. P003's failures come from a different IP, so they **do not** count. Missing or invalid session/IP context is explicitly marked **for review**, even when the numeric score is low. This is a teaching model, not a production-grade risk score or proof of compromise.

## Lab 1E — KQL-native synthetic validation

The [KQL validation playbook](docs/kql-validation-playbook.md) provides a self-contained [Kusto datatable test query](tests/kql/session_ip_synthetic_validation.kql) with **29 fictional events** and **seven expected cases**. It tests the **actual KQL correlation logic** on inline data (rather than only relying on a Python mirror) when executed in a Kusto-compatible query editor.

**Expected upon execution:** 7 `PASS`, 0 `FAIL`. **Actual KQL execution: pending.** The [test-harness contract checks](tests/test_kql_harness_contract.py) passed in GitHub Actions and guard against text drift, but they do **not** compile or execute KQL.

## Roadmap

- [x] Structure repository and document safe data use
- [x] Implement initial encoded-command detection
- [x] Enrich detection with immediate parent-process context
- [x] Add synthetic positive, negative, missing-data, and false-positive cases
- [x] Add an automated Python test workflow
- [x] Prepare a KQL-native synthetic test harness and repeatable validation checklist
- [ ] Execute the KQL harness in Sentinel/Kusto and capture PASS/FAIL evidence
- [ ] Validate actual workspace field mappings with authorized telemetry
- [x] Demonstrate risk-based triage with correlated failed authentication events
- [x] Demonstrate session-ID and source-IP correlation with defensive negative tests
- [ ] Validate and harden field mappings in a Sentinel workspace and enrich identity-provider evidence
- [ ] Develop and test a Sigma rule as a separate detection
- [ ] Build a simulated identity-compromise investigation

## Safety and data handling

Do not commit employer/client telemetry, proprietary detection logic, incident artifacts, secrets or personal information. Hosts, accounts, and command lines in this repository are invented for training.

## Purpose

Connect practical MDR/SOC investigation experience with reproducible detection engineering: explicit assumptions, readable detection logic, test cases, and documented uncertainty.
