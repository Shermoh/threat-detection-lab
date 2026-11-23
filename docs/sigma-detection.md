# Lab 1F — Sigma rule for encoded PowerShell process creation

## Goal

Represent the **base PowerShell encoded-command detection** in [Sigma](https://sigmahq.io/), a vendor-neutral YAML detection format, and verify its behaviour with existing synthetic Windows process events.

- [Sigma rule](../detections/sigma/proc_creation_win_powershell_encoded_command_lab.yml)
- [Python rule tests](../tests/test_sigma_rule.py)
- [Existing labelled events](../sample-data/windows_4688_synthetic.csv)
- [Related baseline Sentinel KQL](../detections/kql/powershell_encoded_command.kql)

**Scope:** This Sigma rule covers the **base encoded-command condition only**, not the KQL lab's parent-process triage, scheduled maintenance scoring, authentication correlation, or session joins. Those are separate exercises.

## Detection logic

The rule's logsource is:

\`\`\`yaml
logsource:
    category: process_creation
    product: windows
\`\`\`

It requires both:

1. **Image suffix:** \`\\powershell.exe\` or \`\\pwsh.exe\`.
2. **Command line:** a standalone \`-EncodedCommand\` or \`-enc\` switch, regardless of case, using Sigma's \`CommandLine|re\` modifier.

The regex checks **argument boundaries**, so \`-EncodedCommandX\` does not match. This is intentionally narrower than searching for any substring \`-enc\`.

### Why the rule has no EventID constraint

Sigma's generic \`process_creation\` category abstracts telemetry such as **Windows Security 4688**, **Sysmon 1**, or appropriately mapped EDR process data. The source-specific Event ID selection is generally a responsibility of the Sigma backend/pipeline. Our offline dataset is a Security 4688 fixture; the Python tests explicitly limit matching to Event ID 4688 to emulate that source selection.

### Field mapping to the current synthetic fixture

| Sigma field | Synthetic Security 4688 field | Notes |
| --- | --- | --- |
| \`Image\` | \`NewProcessName\` | Executable path |
| \`CommandLine\` | \`CommandLine\` | Full command line, if collected |
| \`logsource: process_creation\` | \`EventID == 4688\` | **Test harness mapping only**, not inherent Sigma syntax |

A Sigma conversion backend needs appropriate field mappings for its specific data source. **Do not paste the Sigma YAML directly into a Sentinel Logs editor**; use the existing KQL query or an appropriately configured Sigma-to-KQL conversion pipeline.

## Fixture results

The dataset contains **20 fictional events** with explicit \`ExpectedMatch\` labels.

Expected: **9 matches**, **11 nonmatches**. The nine matches include **two benign encoded-command maintenance runs (S004, S016)**; the rule deliberately does not suppress them. An intentionally renamed executable (S013) remains a **known detection gap**.

The tests additionally cover:
- Both PowerShell Windows and PowerShell 7 executable names.
- Mixed-case switch spellings and the short \`-enc\` form.
- \`-EncodedCommandX\`, other unsupported switches, and incomplete arguments.
- Process telemetry source selection, so the 4624 records in this fixture are excluded.

**These are constructed learning cases, not production false-positive rates or effectiveness measurements.**

## Run the checks

Requires **Python 3.11+** and the pinned [pySigma](https://pypi.org/project/pySigma/) parser:

\`\`\`bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
\`\`\`

The Sigma-specific tests:
1. Parse the YAML through the **pySigma** library (format and modifier handling).
2. Interpret the two detection selections in Python against all 20 synthetic events.
3. Compare those results with the expected labels.

**Limit:** pySigma parsing and a Python approximation are not the same as converting the rule with a particular SIEM backend and executing the converted search. Regex modifier support, field mappings, case-handling and telemetry ingestion must be validated for each backend.

## Operational considerations

- Encoded PowerShell commands are common in some approved administrative automation.
- The rule has no parent-process or identity context; an alert requires investigation.
- The exact image-path suffix could miss renamed binaries or process telemetry without a full path.
- \`CommandLine|re\` uses an inline case-insensitive flag. Confirm that your conversion backend supports this regex and produces equivalent matching semantics.
- Windows Security Event 4688 needs command-line auditing enabled; Sysmon/EDR data also must include command lines.
- Exclusions should be narrowly scoped and preserve visibility to abnormal activity.

## Sources

- [Sigma specification and regex modifiers](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma logsource documentation](https://sigmahq.io/docs/basics/log-sources.html)
- [pySigma documentation](https://sigmahq-pysigma.readthedocs.io/en/stable/getting_started.html)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)

## Next validation gate

Convert the rule with a chosen Sigma backend plus a documented logsource and field mapping, then test the resulting query in the corresponding platform using safe representative data. Until then, the YAML is **not validated as a production detection**.
