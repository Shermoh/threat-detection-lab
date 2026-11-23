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

For the complete suite, use Python 3.11+ and install the pinned pySigma dependency with `python -m pip install -r requirements-dev.txt`.

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

**Observed KQL execution:** **7 `PASS`, 0 `FAIL`** on **2026-11-23 04:04 UTC**, using an inline synthetic dataset in the Azure Data Explorer/Kusto editor. See [recorded validation results](docs/kql-validation-results-2026-11-23.md). The [test-harness contract checks](tests/test_kql_harness_contract.py) also passed in GitHub Actions. **Real Microsoft Sentinel `SecurityEvent` integration remains untested.**

## Lab 1F — Sigma encoded-command detection

The [Sigma rule](detections/sigma/proc_creation_win_powershell_encoded_command_lab.yml) expresses the **baseline encoded PowerShell execution logic** using a vendor-neutral Windows process-creation logsource. Its [pySigma parser and fixture tests](tests/test_sigma_rule.py) compare the rule's image and command-line selections against the **20 synthetic process events** (expected: **9 matches, 11 nonmatches**, including two benign matches).

The [Sigma lab write-up](docs/sigma-detection.md) documents why Sigma is not the same as the Sentinel-specific KQL implementation, how source mapping works, and why **parsing plus offline tests do not establish SIEM-backend correctness**. GitHub Actions runs pySigma parsing and unit tests, but converted searches have not yet been executed in a target SIEM.

**Local test setup (Python 3.11+):**

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

## Lab 1G — Actual Sigma-to-KQL backend conversion

The [pySigma-to-KQL conversion report](docs/sigma-to-kql-conversion.md) documents conversion through the **pySigma 1.5.1 / Kusto backend 1.0.1**, using the Azure Monitor `SecurityEvent` pipeline. It includes:

- [Exact KQL output generated by the backend](detections/kql/generated/powershell_sigma_backend_raw.kql).
- [Reviewed SecurityEvent/4688-scoped query](detections/kql/generated/powershell_sigma_securityevent_4688.kql).
- [20-case synthetic KQL validation harness](tests/kql/sigma_conversion_validation.kql), successfully executed in Azure Data Explorer ([observed results](docs/sigma-kql-validation-results-2026-11-22.md)).
- [Reproducible converter](tools/convert_sigma_to_kql.py), [conversion snapshot tests](tests/test_sigma_conversion.py), and [passing backend conversion CI](https://github.com/Shermoh/threat-detection-lab/actions/runs/45111002576).

**Important finding:** The Kusto backend mapped Sigma's `Image` to `NewProcessName` and preserved the command-line regex, but **did not automatically add `EventID == 4688`**. The reviewed query explicitly adds this source-specific condition. **Kusto synthetic execution now verified: 20 `PASS`, 0 `FAIL`**, confirmed from two user-provided result screenshots on November 22, 2026. See the [Sigma conversion validation report](docs/sigma-kql-validation-results-2026-11-22.md). The earlier 7-pass result relates to the separate session/IP lab. **Live Microsoft Sentinel telemetry remains untested.**

## IR-001 — Simulated incident-response investigation

The first [incident-response case study](case-studies/IR-001-word-powershell/README.md) reconstructs a **fictional document-to-PowerShell incident** using **15 synthetic events** from email security, Windows authentication (4624/4625), process creation (4688), PowerShell script-block logging (4104), DNS/proxy, task registration (4698), and EDR review.

This portfolio artifact includes:

- [Synthetic event records](case-studies/IR-001-word-powershell/data/events.csv) and a [chronological timeline](case-studies/IR-001-word-powershell/docs/timeline.md).
- [Evidence/hypothesis matrix](case-studies/IR-001-word-powershell/docs/evidence-matrix.md) separating facts, confidence and unresolved questions.
- [Structured investigation report](case-studies/IR-001-word-powershell/docs/incident-report.md) and [proposed containment decisions](case-studies/IR-001-word-powershell/docs/response-decisions.md).
- [Interview-style analyst questions](case-studies/IR-001-word-powershell/docs/analyst-exercise.md).
- [Reproducible Python timeline](tools/ir001_timeline.py) and [automated consistency checks](tests/test_ir001_case.py).

**Crucial distinction:** Word-to-PowerShell execution and a registered task are recorded in the simulated evidence; unauthorized remote access, payload execution and working persistence are **not established**. No real incident, malware execution or containment is claimed.

Reproduce the timeline:

```bash
python tools/ir001_timeline.py
python tools/ir001_timeline.py --json
```

## Roadmap

- [x] Structure repository and document safe data use
- [x] Implement initial encoded-command detection
- [x] Enrich detection with immediate parent-process context
- [x] Add synthetic positive, negative, missing-data, and false-positive cases
- [x] Add an automated Python test workflow
- [x] Prepare a KQL-native synthetic test harness and repeatable validation checklist
- [x] Execute synthetic KQL harness in Kusto/Azure Data Explorer and record 7 PASS, 0 FAIL
- [ ] Validate actual workspace field mappings with authorized telemetry
- [x] Demonstrate risk-based triage with correlated failed authentication events
- [x] Demonstrate session-ID and source-IP correlation with defensive negative tests
- [ ] Validate and harden field mappings in a Sentinel workspace and enrich identity-provider evidence
- [x] Develop a Sigma rule and validate YAML parsing plus offline fixture behaviour
- [x] Convert Sigma using the real pySigma Azure Monitor/Kusto backend and verify mapped query snapshots
- [x] Identify and document missing EventID scoping and add a source-aware wrapper
- [x] Execute converted Sigma KQL test harness in Azure Data Explorer (20 PASS, 0 FAIL observed)
- [ ] Validate converted KQL against authorized live Sentinel SecurityEvent telemetry
- [x] Build a synthetic incident-response investigation with correlated identity activity, document execution, task registration, decision log and tests
- [ ] Expand the case with additional identity-provider evidence and independently verified scope

## Safety and data handling

Do not commit employer/client telemetry, proprietary detection logic, incident artifacts, secrets or personal information. Hosts, accounts, and command lines in this repository are invented for training.

## Purpose

Connect practical MDR/SOC investigation experience with reproducible detection engineering: explicit assumptions, readable detection logic, test cases, and documented uncertainty.
