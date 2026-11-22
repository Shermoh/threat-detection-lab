# Threat Detection Lab

A practical security portfolio repository focused on **SIEM detection engineering, log analysis and investigation methodology**. All demonstration data is synthetic.

## Lab 1: Suspicious PowerShell encoded-command execution

**Current status:** Detection query and synthetic fixture published; offline predicate tests implemented. **Not executed in a live Microsoft Sentinel workspace.**

| Component | Where to find it |
| --- | --- |
| Sentinel KQL detection | [`detections/kql/powershell_encoded_command.kql`](detections/kql/powershell_encoded_command.kql) |
| Synthetic Windows 4688 events | [`sample-data/windows_4688_synthetic.csv`](sample-data/windows_4688_synthetic.csv) |
| Offline test suite | [`tests/test_detection.py`](tests/test_detection.py) |
| Design notes & sources | [`docs/first-detection-plan.md`](docs/first-detection-plan.md) |
| Investigation guide | [`docs/investigation-guide.md`](docs/investigation-guide.md) |

### What it detects

The query examines Windows **Event ID 4688** process-creation records in Microsoft Sentinel's `SecurityEvent` table, selects `powershell.exe` and `pwsh.exe`, and looks for `-EncodedCommand` or `-enc` switches. These are indicators for **investigation**, not proof of malware.

**Prerequisite:** command-line auditing must be enabled for event 4688 and the events ingested into `SecurityEvent`.

### Reproduce the offline checks

Requires Python 3.8+; no external packages.

```bash
python -m unittest discover -s tests -v
```

**Fixture results:** 14 synthetic events, 5 detection matches, including 1 legitimate use (false positive). One suspicious fixture using a renamed executable is deliberately not detected (false negative). **These are not real-world performance metrics.**

The Python tests check an equivalent detection predicate against CSV records; they are **not a KQL execution test**. Platform integration testing is still required.

## Roadmap

- [x] Structure repository and explain methodology
- [x] Create synthetic positive and negative Windows process events
- [x] Write initial Sentinel KQL detection for a specified schema
- [x] Verify predicate against offline fixtures
- [x] Document false positives, limitations and investigation steps
- [ ] Validate KQL in a Sentinel workspace using safe test data
- [ ] Add context enrichment and refine detection logic
- [ ] Develop and test a separate Sigma variant
- [ ] Build an identity-compromise investigation lab

## Scope and safety

**No production logs, employer/customer information, private detection rules or credentials.** All hostnames, accounts and events are fictional. The lab prioritizes transparent testing and documented limitations over unverified claims.

## Background

Built to demonstrate and deepen hands-on skills in SOC/MDR investigations, threat detection, security analytics and detection improvement.
