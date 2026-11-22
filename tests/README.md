# Offline detection tests

Run from the repository root:

```bash
python -m unittest discover -s tests -v
```

This Python standard-library suite checks all **20** synthetic fixtures, expected match flags, process-parent-based triage categories, missing parent information, known benign matches and a known missed renamed executable.

**Important:** This tests an offline Python mirror of the detection. It does **not** run KQL or prove the detection works in Sentinel.
