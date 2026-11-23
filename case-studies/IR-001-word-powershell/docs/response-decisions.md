# IR-001 — Response decisions and containment authority

This is a **fictional decision log**. Actions below are **proposed**, not performed. They are contingent on the organization's incident-response procedures and authority.

| Decision | Trigger / rationale | Recommended action | Risk / safeguard |
| --- | --- | --- | --- |
| High-priority triage | Type-10 logon anomalies followed by Word → encoded PowerShell and suspicious task | Escalate as a **suspected security incident** and start the incident clock | Do not declare credential theft without verification |
| Host containment | Active suspicious execution or credible risk of follow-on code/C2 | If authorized, isolate LAB-WIN07 from network while preserving forensic access | Consider critical business dependencies and approved response authority |
| Identity containment | Evidence indicates unauthorized session or stolen credentials | Revoke sessions, rotate affected credentials, enforce MFA and inspect other sessions as authorized | Do not lock the account indiscriminately without operational coordination |
| Email scope | Same attachment sent to another recipient | Search and quarantine matching messages, inspect other recipient endpoints | Delivered does not equal opened or compromised |
| Persistence control | IR-011 confirms task registration for unverified script | Capture task XML, owner/context and file metadata; disable/remove after preservation and approval | Deleting too early can destroy forensic evidence |
| Indicator blocking | Suspicious destination observed in IR-008–010 | Review and apply narrowly scoped temporary/managed blocks for **confirmed malicious** IOCs | IPs can be shared or reassigned; avoid indefinite blanket blocks |
| Impact assessment | Proxy 403 and file not found | Verify alternate network paths, file copies, script block/AMSI and endpoint history | A blocked request does **not** justify automatic closure |
| Scope verification | IR-015 second recipient; IR-012 unrelated host task | Inspect additional recipient; separate genuine control events from related activity | Avoid both missed victims and over-scoping unrelated systems |
| Recovery | Validated containment and eradication | Reimage or remediate if compromise is confirmed, rotate necessary secrets, monitor recurrence | Root cause and recovery validation required |

## Evidence-preservation priorities

Maintain case ID, event/source provenance, UTC timestamps, log collection window, host and user scope, hash values for collected artifacts, and a custody record. Preserve volatile and disk evidence according to authorization and urgency; record each response action and its impact.

## Classification and closure criteria

- **At intake:** High-priority **suspected incident**, because suspicious activity is corroborated across email, authentication, process, PowerShell and task telemetry.
- **Confirmed execution:** The creation of PowerShell and its recorded script block is observed in the synthetic events. Whether it was **unauthorized malicious execution** still requires validation of intent/authorization.
- **Compromise conclusion:** Not proven. A blocked proxy request and file nonexistence at a later lookup do not settle the incident.
- **Close only when:** host/user scope is established, task and payload disposition are explained, relevant accounts/sessions are validated, required response actions are complete, and the analyst documents residual uncertainty.

## Questions for an incident commander

- Is the external RDP logon authorized for this user and host?
- Can endpoint isolation be approved immediately without unacceptable business disruption?
- Was the task created by the same actor/process as the suspicious PowerShell?
- Has the suspicious script ever existed or executed via another path?
- Which additional recipients or hosts might be affected?
- What validated evidence justifies closure versus escalation?
