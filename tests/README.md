# Offline tests

Run from the repository root:

```bash
python -m unittest discover -s tests -v
```

Tests use Python's standard library and compare the expected flags in [synthetic CSV fixtures](../sample-data/windows_4688_synthetic.csv) to a Python mirror of the KQL's filter. They include a known false positive and renamed-executable false negative. They **do not** execute the KQL engine.
