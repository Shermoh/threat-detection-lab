# IR-001 — UTC timeline and correlation

The [source of truth](../data/events.csv) consists of **15 synthetic events** dated **2026-11-18 UTC**. Rebuild the full ordered timeline with `python tools/ir001_timeline.py`.

| UTC | Evidence | Observed event | Interpretation |
| --- | --- | --- | --- |
| 09:00:00 | IR-001 | External document delivered to `LAB\\jane` | Possible phishing initial access; message legitimacy unverified |
| 09:00:03 | IR-015 | Same document delivered to `LAB\\lee` | Campaign reach beyond one recipient; no evidence of opening |
| 09:01:20–09:02:02 | IR-002–004 | Three 4625 failures on LAB-WIN07, same account and source IP | Suspicious authentication pattern, not proof of attack |
| 09:02:20 | IR-005 | 4624 success, LogonType 10, LogonId `0x7A91` | RemoteInteractive logon recorded; authorization unknown |
| 09:03:06 | IR-006 | Word created with PID `4400`, same logon ID; document path in command line | Document opened in that user context |
| 09:03:11 | IR-007 | PowerShell created with PID `5112` and parent PID `4400` | Confirms Word-to-PowerShell process chain |
| 09:03:12 | IR-008 | PowerShell 4104 records an `Invoke-WebRequest` to fictional staging URL | Code attempted to fetch a remote script; downstream success unknown |
| 09:03:13 | IR-009 | Synthetic DNS returned NXDOMAIN for staging domain | One indicator that domain resolution did not succeed |
| 09:03:15 | IR-010 | Proxy rejected staging URL, 403; zero bytes delivered | Confirms **this specific** proxy transfer was blocked |
| 09:04:05 | IR-011 | 4698 created `\\UpdateHealthCheck` task on LAB-WIN07 | Task registration confirmed; execution and intent uncertain |
| 09:04:12 | IR-012 | Separate approved task created on LAB-WIN08 | Unrelated control: do not sweep into incident merely due to timing |
| 09:06:12 | IR-013 | EDR lookup did not find `stage.ps1` on LAB-WIN07 | No file observed at lookup time; not proof no earlier execution |
| 09:06:30 | IR-014 | EDR query found no other suspicious egress in scoped window | Limited negative evidence, not full exoneration |

## Process/session link

```text
LAB-WIN07 / LAB\jane / 4624 LogonId 0x7A91
    WINWORD.EXE  (4688 PID 4400)
       └── powershell.exe  (4688 PID 5112, ParentPID 4400)
             ├── script-block event 4104: attempted external retrieval
             ├── synthetic DNS / proxy denial
             └── scheduled task created later on same host (causal link NOT proven)
```

The session link is strengthened by **same host + account + logon ID + chronology**. Logon ID alone is not globally unique. The scheduled task must not be attributed to PID 5112 without additional creation or process evidence.

The DNS and proxy records are synthetic artifacts that represent separate controls, not evidence that the remote domain existed or a real packet traversed the Internet.
