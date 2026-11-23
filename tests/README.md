# Offline detection tests

Install the pinned dependency from `requirements-dev.txt` before running the full suite. Run from the repository root:

```bash
python -m unittest discover -s tests -v
```

This Python standard-library suite checks all **20** synthetic fixtures, expected match flags, process-parent-based triage categories, missing parent information, known benign matches and a known missed renamed executable.

**Important:** This tests an offline Python mirror of the detection. It does **not** run KQL or prove the detection works in Sentinel.

[`test_tuning.py`](test_tuning.py) checks that the proposed S004 downgrade does not silence other encoded-command matches, and illustrates the risk of an attacker replaying indistinguishable telemetry.

## Correlated risk-scoring tests

[`risk_scoring.py`](risk_scoring.py) and [`test_risk_scoring.py`](test_risk_scoring.py) check risk categories and 15-minute auth correlation, including attempted maintenance-command replay. GitHub Actions runs the suite on relevant changes. These tests validate a Python mirror, not KQL execution.

### Session/IP correlation suite

[`test_session_ip_correlation.py`](test_session_ip_correlation.py) validates a Python model of 4688-to-4624 session links and 4625 same-IP failures. It also verifies time windows, account/host mismatch, invalid IDs, missing IPs, and the safe handling of unmatched sessions. GitHub Actions runs these tests on changes. The tests **do not execute KQL**.

### KQL-native validation (manual execution)

[`kql/session_ip_synthetic_validation.kql`](kql/session_ip_synthetic_validation.kql) contains an inline KQL `datatable` with 29 fake events, the same session/IP correlation query logic, and seven expected outcomes. Run the **entire** file in a Kusto query editor to check for 7 PASS and 0 FAIL. Follow the [playbook](../docs/kql-validation-playbook.md).

[`test_kql_harness_contract.py`](test_kql_harness_contract.py) verifies the inline test remains synchronized with the maintained KQL logic. **The contract and Python tests are not a live KQL run.**

### Sigma rule validation

Install pinned parser dependency with `python -m pip install -r requirements-dev.txt` (requires Python 3.11+), then run `python -m unittest discover -s tests -v`.

[`test_sigma_rule.py`](test_sigma_rule.py) parses the [Sigma YAML](../detections/sigma/proc_creation_win_powershell_encoded_command_lab.yml) using pySigma and checks the image and regex selections against 20 curated synthetic events. This is *not* SIEM-backend query execution. See [Sigma methodology](../docs/sigma-detection.md).
