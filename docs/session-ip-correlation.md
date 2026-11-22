# Lab 1D — Correlating Windows logon sessions and source IPs

**Status:** Synthetic fixtures, an illustrative Microsoft Sentinel KQL query, and offline Python tests published. **KQL has NOT been executed in a live Microsoft Sentinel workspace.**

## Why this matters

The previous experiment linked **4625 failed logons** to **4688 PowerShell process creation** by host and account within a time window. That correlation is useful but weak: failures could come from a different source address, or the execution could belong to a different logon session.

Here we add **4624 successful logons** as a bridge between authentication activity and process creation:

1. **4688 process**: read its creator's \`SubjectLogonId\`, account and host.
2. **4624 successful logon**: look back up to **30 minutes** for \`TargetLogonId\` matching the process's session ID, plus the **same host and account**. Select the most recent eligible 4624.
3. **Source address**: take the successful 4624 event's \`IpAddress\`, if usable.
4. **4625 failures**: count failures only for the **same host, target account and source IP**, occurring in the **15 minutes before the successful 4624 logon**.
5. **Risk points**: combine encoded-PowerShell baseline, parent context, narrowly monitored maintenance context, and linked failed-logon count.
6. **Missing evidence**: mark processes without a reliable 4624 or usable source IP as **Review: identity context incomplete**.

### Why not match 4625 by logon ID?

A failed logon does not necessarily establish a successful user logon session, and the subject logon ID on a 4625 can refer to the account/process requesting authentication rather than the target session. Therefore this project **does not** treat 4625 logon IDs as a join key to the process.

**Even a matching 4624/4688 logon ID is not absolute proof of causation.** Logon IDs are scoped to a system and may be reused after reboot; same account and host do not identify which client action led to a process. The 30-minute bound is instructional and may miss long-lived sessions.

## Inputs

All rows in [\`session_ip_correlation.csv\`](../sample-data/session_ip_correlation.csv) are fictional. The dataset uses the fields \`EventID\`, \`TimeGenerated\`, \`Computer\`, \`Account\`, \`TargetDomainName\`, \`TargetUserName\`, \`NewProcessName\`, \`CommandLine\`, \`ParentProcessName\`, \`SubjectLogonId\`, \`TargetLogonId\`, and \`IpAddress\`. \`CaseID\` and \`Scenario\` are *fixture-only* labels.

Source IP examples use **documentation-only address ranges** (192.0.2.x, 198.51.100.x, 203.0.113.x); they are not attributed to real systems.

## Scoring (illustrative, NOT calibrated)

| Signal | Points |
| --- | ---: |
| Encoded-command PowerShell process | +20 |
| Exact synthetic maintenance command and approved context | -15 |
| Office/script-host parent | +35 |
| Missing parent | +10 |
| 1–2 prior same-IP failures associated with linked 4624 | +10 |
| 3+ prior same-IP failures associated with linked 4624 | +50 |
| No linked 4624 or usable source IP | +10 and mandatory review flag |

**Bands:** Low: under 30; Medium: 30–54; High: 55 or higher. These are arbitrary educational weights, not probabilities, incident severities, or statistically calibrated risk scores.

## Expected fixture outcomes

| Process | Observation | Linked 4624 | Matching prior failures | Score | Disposition |
| --- | --- | --- | ---: | ---: | --- |
| P001 | Approved maintenance, one failure from *different IP* | L001 | 0 | 5 | Low |
| P002 | Same maintenance command, three failures from *same IP* | L002 | 3 | **55** | **High** |
| P003 | Three failures for same host/account, but *other IP* | L003 | 0 | 5 | Low |
| P004 | Recent login has wrong session ID; matching session is too old | None | 0 | 15 | **Review: identity context incomplete** |
| P005 | Word-parent encoded PowerShell | L005 | 0 | **55** | **High** |
| P006 | Ordinary PowerShell, without encoded switch | n/a | n/a | n/a | Not matched |
| P007 | Matching logon but \`IpAddress\` is unavailable | L007 | 0 | 15 | **Review: identity context incomplete** |
| P008 | Invalid process logon ID \`0x0\` | None | 0 | 15 | **Review: identity context incomplete** |

**Important:** No session evidence is not evidence of safety. We explicitly separate the *numeric band* from the **triage disposition**, which requires review when identity context is incomplete.

## Files and verification

- [Source-IP/session correlation KQL](../detections/kql/powershell_session_ip_correlation.kql)
- [Synthetic 29-event dataset](../sample-data/session_ip_correlation.csv)
- [Python reference implementation](../tests/session_ip_correlation.py)
- [Python tests](../tests/test_session_ip_correlation.py)

Run from the repository root:

\`\`\`bash
python -m unittest discover -s tests -v
python tests/session_ip_correlation.py
\`\`\`

Tests validate an **offline Python mirror**, not Sentinel's query engine or real data mappings.

## Operational limitations

- 4624 \`IpAddress\` may be \`-\`, local, proxy/NAT-shared, absent, or misleading depending on logon type and configuration.
- Logon IDs are host-scoped and not globally unique; this lab does not handle host reboot boundaries.
- 4625 events might be recorded on a domain controller rather than the endpoint. The same-host join can undercount and should **not** be interpreted as evidence there were no failed authentications.
- One process may be associated with a long-lived logon session more than 30 minutes old. Missing a match should trigger additional investigation, not automatic clearing.
- Reused account credentials, delegated tokens, impersonation and token theft can invalidate simple joins.
- Real deployments should enrich logon type, source host, session lifetime, client IP trust, identity-provider events, process identifiers and EDR process trees.
- The 4625-to-4624 association is only a correlation of matching host, account, source IP and time. It does **not** prove the same actor performed both.
- These joins are optimized for clarity, **not high-volume production efficiency**. Time-bucket joins, event deduplication, and measured detection quality would be needed for deployment.
- The synthetic maintenance downgrade is **not** a production allowlist, and no events are discarded by the educational detection.

## Sources

- [Microsoft SecurityEvent table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent)
- [Microsoft event 4688: process creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft event 4624: successful logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft event 4625: failed logon](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [MITRE ATT&CK PowerShell T1059.001](https://attack.mitre.org/techniques/T1059/001/)

## Interview-ready insight

Instead of suppressing an approved command, retain it with a lower baseline score and incorporate independently sourced context. Validate identity/session links carefully, report missing context transparently, and avoid using correlated events as proof of malicious intent.
