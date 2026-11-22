# Offline detection tests

Run from the repository root:

```bash
python -m unittest discover -s tests -v
```

This Python standard-library suite checks all **20** synthetic fixtures, expected match flags, process-parent-based triage categories, missing parent information, known benign matches and a known missed renamed executable.

**Important:** This tests an offline Python mirror of the detection. It does **not** run KQL or prove the detection works in Sentinel.

[`test_tuning.py`](test_tuning.py) checks that the proposed S004 downgrade does not silence other encoded-command matches, and illustrates the risk of an attacker replaying indistinguishable telemetry.

## Correlated risk-scoring tests

[`risk_scoring.py`](risk_scoring.py) and [`test_risk_scoring.py`](test_risk_scoring.py) check risk categories and 15-minute auth correlation, including attempted maintenance-command replay. GitHub Actions runs the suite on relevant changes. These tests validate a Python mirror, not KQL execution.
