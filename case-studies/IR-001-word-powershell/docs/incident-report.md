# IR-001 — Incident investigation report (synthetic)

**Classification:** High-priority *suspected* security incident; malicious authorization status and full compromise **not confirmed**  
**Reporting period:** 2026-11-18 09:00–09:07 UTC (fictional)  
**Affected host under investigation:** LAB-WIN07  
**Associated identity:** LAB\\jane  
**Additional recipient in scope check:** LAB\\lee; exposure only  
**All evidence:** Synthetic, invented for the portfolio; no actual victims or real organizations

## 1. Executive summary

Fifteen synthetic events depict an external document delivery followed by anomalous remote logons, a Word-to-encoded-PowerShell process chain and a blocked attempt to retrieve a script. A scheduled task pointing to the script's expected path was registered. The available records justify urgent investigation and potential containment, **but do not prove** the remote logon was unauthorized, a payload executed, or the scheduled task ran.

## 2. Investigation objective

Establish the sequence, determine what was executed, assess possible persistence and account misuse, identify affected assets, and recommend safe response steps without overstating what the evidence proves.

## 3. Key observations

- **Email exposure:** IR-001 and IR-015 show the same external attachment delivered to two recipients. Only LAB\\jane has related endpoint telemetry.
- **Authentication:** IR-002–004 show 4625 failures from `203.0.113.91`, then IR-005 shows a 4624 type-10 success with LogonId `0x7A91`. The source IP is from a documentation-only range.
- **Execution lineage:** IR-006 Word PID `4400` and IR-007 PowerShell PID `5112` share host/account/logon ID; PowerShell reports Word's PID as parent.
- **Decoded content:** IR-007's UTF-16LE encoded argument matches IR-008's 4104 script block, an `Invoke-WebRequest` attempt to a fictional `stage.ps1`.
- **Network control:** IR-009 DNS NXDOMAIN and IR-010 proxy 403/0 bytes support a blocked **specific path**. IR-013 later did not find the script; this is not comprehensive proof of no execution.
- **Task activity:** IR-011 shows scheduled task creation on LAB-WIN07, pointing to the script path. IR-012 records an unrelated approved task on another endpoint.

Full details: [UTC timeline](timeline.md) and [evidence/hypothesis matrix](evidence-matrix.md).

## 4. Assessment

**Supported:** Suspicious document-associated PowerShell execution occurred in this fictional sequence; task registration and attempted remote retrieval were recorded.

**Unresolved:** Document's maliciousness/mechanism, authorization of RemoteInteractive logon, payload delivery through any other path, task execution, file deletion, lateral movement and final affected scope.

**Risk posture:** High-priority suspected incident. A successful payload download is not necessary for an event to meet some organizations' incident definitions, but classification must follow the applicable policy and verified evidence. Treat the observed chain seriously even if its one proxy request was blocked.

## 5. MITRE ATT&CK alignment

| Technique | Status in this case | Evidence |
| --- | --- | --- |
| [T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) | **Hypothesis**: suspicious external document delivered | IR-001, IR-015; intent not proven |
| [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/) | **Observed** PowerShell process/script-block execution | IR-007, IR-008 |
| [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) | **Observed** task creation; malicious purpose/activation unproven | IR-011 |

Avoid assigning technique codes as proof of attacker identity or intent.

## 6. Response recommendations

Initiate a priority investigation under authorized procedures. Preserve process and script-block telemetry, obtain the actual attachment and task XML, validate the remote logon source and MFA, and consider endpoint/network containment proportionate to evidence and business impact. Scope all affected recipients and check for related activity. Do not permanently block IOCs solely from a synthetic or unverified reputation signal.

Detailed proposed decisions: [response decisions](response-decisions.md).

## 7. Lessons learned / detection improvements

1. Correlate email exposure, 4624/4625 authentication, 4688 process lineage, 4104 content, egress and 4698 task creation.
2. Treat **blocked download** and **no file found** as scoped negative observations, not blanket clearance.
3. Use session IDs together with host, account and time context, not as universal global identifiers.
4. Preserve narrow detection exceptions: approved accounts and tasks can be abused.
5. Explicitly state telemetry coverage, confidence and unverified causal links in an incident report.

## 8. Limitations and references

This is a fictional investigation, not a real-case report. Email, DNS, proxy and EDR records use normalized synthetic fields, not the schema of any specific deployed product. There was no malware execution, investigation of a real host, or actual containment.

References: [Microsoft 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624), [Microsoft 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698), [PowerShell script-block logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1), [MITRE T1059.001](https://attack.mitre.org/techniques/T1059/001/).
