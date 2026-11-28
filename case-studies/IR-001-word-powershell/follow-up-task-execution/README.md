# IR-001 follow-up — Did the scheduled task actually execute?

**Type:** Two mutually exclusive, fictional follow-up evidence packets.  
**Original case remains unchanged:** [IR-001 investigation](../README.md)  
**Data:** [12 normalized synthetic event records](events.csv) — eight in follow-up A and four unrelated-host controls in B.

## Why this follow-up exists

The original [IR-011](../data/events.csv) is a **Windows 4698 task-creation record**, not proof that `\\UpdateHealthCheck` ran. The question is whether additional telemetry would raise that conclusion to **task action observed**, **process launch observed**, and **persistence configuration changed**, without falsely claiming successful payload execution or confirmed attacker control.

### Follow-up A: Task execution and registry change supported

| Time UTC | ID | Synthetic evidence | What it supports |
| --- | --- | --- | --- |
| 09:05:10 | F-001 | TaskScheduler/Operational **200** for `\\UpdateHealthCheck`, `RUN-A1`, LAB-WIN07 | Task action started |
| 09:05:10.500 | F-002 | TaskScheduler/Operational **129** records launched PID **6200**, same task instance | Scheduler-associated process launch |
| 09:05:11 | F-003 | Windows Security **4688**: PID 6200, expected PowerShell `-File` command, matching host/account | A PowerShell process was created |
| 09:05:11.500 | F-004 | PowerShell **4104** logs script text requesting a Registry Run-key write | The command/script content was observed |
| 09:05:12 | F-005 | Windows Security **4657** records Run-value modification, PID 6200 | Registry value was modified, subject to valid audit mapping |
| 09:05:13 | F-006 | TaskScheduler/Operational **201**, same instance, return code **1** | Task action completion reported, with a nonzero result |
| 09:05:14 | F-007 | TaskScheduler/Operational **102**, same instance | Task instance completion observed |
| 09:06:10 | F-008 | Invented EDR registry snapshot finds the Run value still configured | Persistence *configuration* present at the time of the snapshot |

**Supported conclusion:** The matching task action ran, Windows PowerShell launched, and a registry autorun value was written and subsequently observed. This supports **configured registry-based persistence**, *not proof the Run value fired on login/reboot*, that the scheduled task's intended objective succeeded, or that the broader endpoint was fully compromised.

**Important contradiction to investigate:** Earlier IR-010 showed a proxy-blocked attempted download, and IR-013 later reported no `stage.ps1` file. Yet this *hypothetical new evidence* includes process/script-block activity and a registry write. Do **not** invent how the script arrived: request file creation/deletion, hashes, AMSI/4104, task action results and alternate-source evidence. A task action's return code `1` is not sufficient to establish zero side effects.

### Follow-up B: Same task name, **different host**

F-009–F-012 record task and PowerShell events on **LAB-WIN08** with the same task name, command text and near-identical timestamps. They must **not** establish execution on **LAB-WIN07**.

Expected conclusion for the LAB-WIN07 target: **No execution observed in this follow-up packet**. The original 4698 still supports only registration. This is a *negative correlation control*, not evidence that no execution ever occurred.

## How to reproduce

Run these from the repository root (Python standard library only):

```bash
python tools/ir001_task_followup.py --scenario FOLLOWUP_A
python tools/ir001_task_followup.py --scenario UNRELATED_B
python -m unittest discover -s tests -p test_ir001_task_followup.py -v
```

The [analysis script](../../../tools/ir001_task_followup.py) matches on **host + account + task name + Task Scheduler run instance**, correlates Task Scheduler Event 129's PID to Windows 4688 in a short window, then checks process-level 4104/4657 and a later snapshot. [Automated tests](../../../tests/test_ir001_task_followup.py) verify the expected positive path, a wrong-host decoy, a mismatched task instance, and command-line mismatch.

### Important data-model caveats

The CSV is a **normalized teaching fixture**, not native XML from Task Scheduler, Windows Security or EDR. Scheduler event 129/PID availability and fields depend on Windows version, configuration and ingestion. Process IDs can be reused. Real analysis should corroborate with process GUIDs, user security identifiers, machine identity, process creation time and EDR lineage.

Event 4657 requires appropriate registry auditing and SACL configuration; absence of 4657 does not establish no modification. Event 201 records the action's reported return code; this is not a reliable standalone verdict on script success. An EDR registry snapshot of an autorun value does not show that the auto-start was ever triggered.

## Investigator decision

Given follow-up A, would you **escalate for containment**? What *specific* evidence would you preserve before an authorized isolation or remediation action? What do you still need to decide whether credentials were compromised, whether the scheduled task's script obtained its contents, and whether other hosts were affected?

## References

- [Microsoft Windows Security event 4698: Scheduled task created](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698)
- [Microsoft Windows Security event 4657: Registry value modified](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [Microsoft Windows auditing overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Task Scheduler operational events](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
