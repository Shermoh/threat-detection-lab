# Synthetic Windows event 4688 fixtures

[`windows_4688_synthetic.csv`](windows_4688_synthetic.csv) contains 14 made-up event records for the encoded-command detection. No employer/customer telemetry is included.

Each row includes `ExpectedMatch` (whether the detection *should fire*) and `GroundTruth` (the scenario's intended benign/suspicious label). A match does **not** automatically mean malicious.

Use `python -m unittest discover -s tests -v` from the repository root to validate the offline predicate against these fixtures.
