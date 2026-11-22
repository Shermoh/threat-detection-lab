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

## Roadmap

- [x] Structure repository and document safe data use
- [x] Implement initial encoded-command detection
- [x] Enrich detection with immediate parent-process context
- [x] Add synthetic positive, negative, missing-data, and false-positive cases
- [x] Add an automated Python test workflow
- [ ] Validate KQL in Microsoft Sentinel with safe test events
- [ ] Expand detection coverage and tune using corroborating telemetry
- [ ] Develop and test a Sigma rule as a separate detection
- [ ] Build a simulated identity-compromise investigation

## Safety and data handling

Do not commit employer/client telemetry, proprietary detection logic, incident artifacts, secrets or personal information. Hosts, accounts, and command lines in this repository are invented for training.

## Purpose

Connect practical MDR/SOC investigation experience with reproducible detection engineering: explicit assumptions, readable detection logic, test cases, and documented uncertainty.
