# Threat Detection Lab

A hands-on cybersecurity portfolio project focused on developing, testing, and documenting security detections using **synthetic event data**.

## Purpose

This repository demonstrates a practical detection-engineering workflow: define suspicious behaviour, identify the necessary telemetry, write detection logic, test against benign and suspicious examples, and document limitations and false positives.

The project is being built incrementally. **Detection rules and test results will be published as they are implemented and validated.**

## First scenario: Suspicious PowerShell execution

Our first lab will examine suspicious PowerShell process execution, such as encoded commands and unusual launch arguments, using simulated Windows process-creation events. The goal is to detect activity worth investigating, **not** to treat any single PowerShell flag as proof of compromise.

- **MITRE ATT&CK:** [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- **Proposed data sources:** Windows process creation (e.g., Security Event ID 4688 with command-line logging enabled) or Sysmon Event ID 1
- **Planned formats:** KQL and Sigma
- **Validation plan:** Positive test cases, benign counterexamples, expected results, and false-positive analysis

## Repository structure

```text
threat-detection-lab/
├── README.md
├── detections/
│   ├── kql/           # KQL detections and query notes
│   └── sigma/         # Sigma rules
├── sample-data/       # Synthetic, non-sensitive sample events
├── tests/             # Test cases and expected outcomes
└── docs/              # Investigation notes, assumptions and methodology
```

## Roadmap

- [x] Establish a public, structured lab repository
- [ ] Define and generate benign and suspicious synthetic events
- [ ] Write the first detection rule and record its assumptions
- [ ] Validate the rule against positive and negative cases
- [ ] Document false positives and investigative follow-up
- [ ] Add an identity-focused detection scenario

## Safety and scope

All examples will use synthetic data or datasets explicitly licensed for public use. No employer or customer telemetry, internal detection content, credentials, or proprietary incident details will be published.

## Background

This project supports my work in security operations, incident investigation, and SIEM detection tuning, and my continued development in practical detection engineering.
