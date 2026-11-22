# Lab 1C — Risk-based triage with authentication correlation

**Status:** Educational Microsoft Sentinel query, synthetic events and offline Python tests prepared. **Not validated in a live Sentinel workspace**.

## Objective

Improve alert priority when multiple independent signals coincide: encoded PowerShell execution (Windows Event ID **4688**) with unusual parent-process context and failed Windows logons (Event ID **4625**) for a corresponding account/host in the **preceding 15 minutes**.

This is a **hand-crafted triage score**, not production-grade Risk-Based Alerting, a learned model, calibrated probability, or a determination of maliciousness.

## Inputs and assumptions

- Uses Microsoft's **SecurityEvent** table for both Windows event types.
- For process records, uses \`Account\`, \`Computer\`, \`NewProcessName\`, \`CommandLine\`, \`ParentProcessName\`, \`EventRecordId\`.
- For failed logons, uses \`TargetDomainName\` and \`TargetUserName\` combined into \`domain\\username\`, with \`Computer\` and \`TimeGenerated\`.
- **Join is approximate.** Account and host equality do not prove the failures were part of the same process session. If failures occur on a domain controller or a different system, this simple host join may miss them. Verify domain, field mappings, and source host meanings in your environment.
- A failed logon could be caused by a stale password, scheduled task, or ordinary user mistake. It is an additional signal, not proof of attack.

## Transparent scoring scheme

| Signal | Points |
| --- | ---: |
| Encoded PowerShell event matching original rule | +20 |
| Exact synthetic approved maintenance context (\`LAB-WIN04\`, \`LAB\\svc-maint\`, service parent, exact command) | -15 |
| Parent is Office app or selected script host | +35 |
| Parent is missing (if not unusual) | +10 |
| 1–2 failed logons for same host+account in prior 15 minutes | +10 |
| 3+ failed logons for same host+account in prior 15 minutes | +50 |

Bands: **Low** (under 30), **Medium** (30–54), **High** (55 or higher). Points are **not percentages**. These weights and cutoffs are illustrative, **not empirically tuned**.

Importantly, the maintenance adjustment does **not** veto the other signals. It cannot prevent a high-risk band if correlated behaviour warrants escalation.

## Demonstration events

[The correlation fixture](../sample-data/rba_auth_correlation.csv) adds 13 fictional logon records and one intentionally suspicious **R001** process. It combines with the existing [20 process fixtures](../sample-data/windows_4688_synthetic.csv).

| Case | Context | Recent failed logons | Risk points | Band |
| --- | --- | ---: | ---: | --- |
| S004 | Exact approved maintenance, no new auth signals | 0 | 5 | Low |
| R001 | **Exact same host/account/parent/command**; three preceding failures | 3 | 55 | **High** |
| S002 | Encoded PowerShell + three preceding failures | 3 | 70 | **High** |
| S001 | Word-parent encoded PowerShell + one preceding failure | 1 | 65 | **High** |
| S018 | Encoded PowerShell, missing parent | 0 | 30 | Medium |

The fixture deliberately includes a failure **after** R001, a failure on another host, an older failure, a different account, and a successful 4624 event. None should increase R001's preceding 15-minute failure count.

## Reproduce local verification

From the repo root:

\`\`\`bash
python -m unittest discover -s tests -v
python tests/risk_scoring.py
\`\`\`

The tests emulate the correlation and scoring in Python. **They do not execute KQL**.

## Detection engineering limitations

- Risk scoring only prioritizes review; it does not prove that an account is compromised.
- This minimal rule does not correlate logon sessions, source IPs, endpoint process lineage, account risk state, or network connections.
- The host-account equality check is intentionally narrow and can miss distributed authentication attacks.
- The query joins all failures on account and host before filtering the 15-minute window. Use time-window optimized joins and careful event deduplication for scale.
- The example maintenance adjustment is an instructional exception; do not copy sample hostnames or account allowlists to production.
- Reassess thresholds against a representative, authorized dataset before enabling alerting.

## Technical references

- [SecurityEvent table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent)
- [Example SecurityEvent queries](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/securityevent)
- [Joining events in a time window](https://learn.microsoft.com/en-us/kusto/query/join-time-window)
- [Windows event 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)

## Interview takeaway

A narrow known-benign exception is not sufficient protection. An attacker can replay the same command and context. Independent authentication anomalies can raise risk while leaving the approved command visible; the best next improvement is stronger **identity/session correlation** and more representative validation.
