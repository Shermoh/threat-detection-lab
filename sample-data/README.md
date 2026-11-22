# Synthetic Windows 4688 event fixtures

[Download or review the synthetic CSV](windows_4688_synthetic.csv). It includes **20** fictional events for testing encoded PowerShell detection and optional parent-process context.

The columns `ExpectedMatch`, `ExpectedPriority`, `GroundTruth` and `Scenario` are **lab labels**, not fields that exist in the Microsoft Sentinel `SecurityEvent` table.

The data includes benign administrative encoded commands, missing parent context, Office/script-host launch patterns and a known missed renamed executable.

No employer/client logs, names or proprietary detection content were used.
