# IR-001 — Evidence matrix and competing hypotheses

**Method:** Each conclusion cites specific synthetic `event_id` values. Confidence refers to the **quality of the simulated evidence**, not an empirically calibrated probability.

| Question / hypothesis | Supporting evidence | Alternative explanation / gap | Assessment |
| --- | --- | --- | --- |
| Was external email delivered? | IR-001, IR-015 | Delivery does not prove the message was malicious or opened by both users | **Observed:** two deliveries |
| Was remote access established? | IR-002–005, three failures then type-10 success from same source IP; `0x7A91` | Could be an authorized user with mistyped password, VPN gateway or legitimate remote workflow | **Observed logon; authorization unresolved** |
| Did Word launch PowerShell? | IR-006 PID 4400, IR-007 parent PID 4400, same account/host/logon ID | Parent PID can be reused; corroborate with EDR process tree and timestamps | **High confidence observed chain in fixture** |
| Was the encoded command readable and suspicious? | IR-007 Base64 decodes as UTF-16LE; IR-008 captures same decoded script | Query is an attempted download, not proof of completed payload retrieval | **Observed script content** |
| Was the remote script downloaded? | IR-009 NXDOMAIN; IR-010 proxy 403/0 bytes; IR-013 file not found later | Other URLs, alternate transports, earlier file copies, or deletion might be outside scope | **Not confirmed; one path blocked** |
| Was persistence established? | IR-011 registers task pointing at `stage.ps1` | A registered task might never execute, and ownership/intent may differ from PowerShell process | **Task registered; persistence execution unconfirmed** |
| Was there lateral movement? | None in supplied data | Other systems/account logs not collected | **No conclusion possible** |
| Is the second recipient compromised? | IR-015 shows delivery to `LAB\\lee` | No opening, process, logon or endpoint evidence supplied for that recipient | **Exposure possible; compromise unproven** |
| Is another task on LAB-WIN08 related? | IR-012 is a scheduled task near the same time | Different host/account and an approved change ticket | **Do not conflate without evidence** |

## Hypothesis status

**H1 — Malicious document or document-triggered mechanism initiated PowerShell.** Supported by Word's command-line document path and direct parent-child relationship with encoded PowerShell (IR-006–008). The method (macro, DDE, exploitation, legitimate automation, or another path) is **not established**.

**H2 — Account misuse preceded document execution.** Three failed logons followed by successful type-10 logon and a matching user session support investigation (IR-002–007). **No proof** that credentials were stolen or that the remote IP belongs to an attacker. Validate VPN/RDP exposure, authorized location, MFA evidence and user confirmation.

**H3 — Remote payload successfully executed.** IR-008 shows an attempted retrieval, but IR-009–010 indicate one route was blocked and IR-013 lacks a file. There is **insufficient evidence** to confirm payload delivery or execution.

**H4 — Scheduled-task persistence was successfully activated.** IR-011 confirms task *registration*. The task references an apparently missing script and has no recorded execution result. **Persistence mechanism is suspicious; operational persistence unconfirmed.**

## Evidence to request next

1. EDR full process ancestry, command-line argument capture and process GUIDs; correlate Office document hashes and exact file-open time.
2. Identity provider/RDP gateway logs, successful 4624 logon context, source IP ownership, MFA outcome and user/asset-owner validation.
3. Original document provenance, email headers, attachment hash, sandbox analysis and related-recipient searches.
4. PowerShell script-block/AMSI telemetry, file writes/deletes, proxy requests across alternate paths, network destination records.
5. Task XML, actor/token, schedule, first-run result, on-disk script contents, file hashes, registry and other autoruns.
6. Broader scope across endpoints, account sessions and recipients.

## Important evidence-handling rule

Evidence absence is not evidence of absence. Record which searches were performed, collection coverage, time range, and whether telemetry could have been lost. Do not publicly submit internal document hashes, private URLs, or uploaded artifacts to third-party reputation services without authorization.
