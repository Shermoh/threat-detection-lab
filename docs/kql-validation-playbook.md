# KQL validation playbook — Lab 1D

**Validation update (2026-11-23):** The synthetic KQL harness **executed successfully in Azure Data Explorer/Kusto** with **7 PASS and 0 FAIL**, verified from a user-provided results screenshot. See [the observed-results report](kql-validation-results-2026-11-23.md). **Live Microsoft Sentinel/Log Analytics `SecurityEvent` integration and production analytics-rule deployment are not validated.** GitHub Actions separately runs Python unit tests and a static fixture/query contract check.

## Purpose

Move beyond "the Python version passes" by asking the **Kusto query engine** to evaluate the real session/IP-correlation logic against representative synthetic events. The test uses an inline [\`datatable\`](https://learn.microsoft.com/en-us/kusto/query/datatable-operator), so you do not have to ingest the sample CSV into a workspace.

## Step 1 — Run the KQL-native synthetic test

1. Open a Log Analytics workspace you are authorized to query in the **Azure portal → Log Analytics workspaces → your workspace → Logs**. If you use the Microsoft Defender portal with Sentinel connected, the documented Sentinel Logs experience is under **Investigation & response → Hunting → Advanced hunting**; available tables and query features may depend on your environment.
2. Open [\`tests/kql/session_ip_synthetic_validation.kql\`](../tests/kql/session_ip_synthetic_validation.kql) and select **Raw** to copy its entire contents.
3. Paste it into the query editor and choose **Run**.
4. Expect **7 rows with \`ValidationStatus = PASS\` and 0 rows with \`FAIL\`**. Confirm the case IDs P001, P002, P003, P004, P005, P007 and P008 all appear.
5. If you see a parse error or a different result, **do not mark the KQL as validated**. Preserve the error message (redact tenant/workspace details), correct the actual query and fixture together, and rerun.

This test defines a *local* query variable named \`SecurityEvent\` containing 29 fabricated events; it does **not** depend on collecting security events from a Windows host. The fixed clock prevents the 2026 examples from aging out of \`ago(7d)\`.

### Why run this?

The repository's unit tests validate a Python mirror of the algorithm. This KQL harness is needed to catch errors in KQL **parsing, joins, null handling, aggregations, case logic, or field projections** that Python cannot detect.

The harness is **not production telemetry validation**: every column is supplied via a hand-authored synthetic schema, not a real collector or connector mapping.

## Step 2 — Check your workspace schema separately (optional)

Only if you have permission and a workspace that collects relevant Windows security events:

\`\`\`kusto
SecurityEvent
| getschema
| where ColumnName in (
    "TimeGenerated", "EventID", "Computer", "Account", "NewProcessName",
    "CommandLine", "ParentProcessName", "SubjectLogonId", "TargetLogonId",
    "TargetDomainName", "TargetUserName", "IpAddress", "_ItemId"
)
| project ColumnName, DataType
| order by ColumnName asc
\`\`\`

Then check which relevant event types are actually ingested:

\`\`\`kusto
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID in (4688, 4624, 4625)
| summarize RecordCount = count() by EventID
| order by EventID asc
\`\`\`

**Interpret correctly:** A missing table, field, or event type indicates an ingestion/configuration or mapping limitation. It does **not** establish that the detection logic is correct or incorrect.

## Step 3 — Run the real-data query safely (optional, authorized environments only)

After verifying that the fields exist and auditing is appropriately enabled, review the [actual query](../detections/kql/powershell_session_ip_correlation.kql) and run it in a **nonproduction or otherwise authorized workspace**. Use a suitably scoped time window and avoid exposing real accounts, IP addresses, command lines, or tenant information in a public repository.

Review results with an analyst: Are the returned 4624/4688 session links credible? Are 4625 failures on domain controllers or other hosts, rather than the endpoint? Do missing source IPs and long-lived sessions cause unexpected nonmatches? Are false positives visible?

**Do not deploy as a scheduled production analytics rule without technical testing, approved governance, and operational performance evaluation.**

## Evidence checklist

Only mark a validation stage complete when you have actual observed results.

| Stage | Expected | Recorded result |
| --- | --- | --- |
| Python GitHub Actions | Offline suite passes | Check the Actions tab |
| KQL datatable execution | 7 PASS, 0 FAIL | **Verified: 7 PASS, 0 FAIL** in Azure Data Explorer/Kusto, 2026-11-23 04:04 UTC ([record](kql-validation-results-2026-11-23.md)) |
| Workspace schema check | Required fields available | Not checked |
| Real SecurityEvent integration | Queries run on representative authorized events | Not checked |
| Security review and tuning | False positives/negatives, safeguards documented | Not checked |

The completed [validation record](kql-validation-results-2026-11-23.md) documents the execution date, query commit SHA, visible results, and remaining limitations. For subsequent runs, record the same evidence. Do not publish workspace secrets or raw organizational logs.

## Limitations

- Successful inline KQL test execution establishes that the query runs on its test schema, **not that a Sentinel rule reliably detects real adversaries**.
- The synthetic examples are designed to exercise positive and negative scenarios; they do not support precision/recall claims on a production population.
- Source IPs may be absent, shared through NAT, or recorded on another system.
- Event 4624 and 4688 session IDs should be correlated within host and time context; 4625 failures should **not** be joined by a presumed successful session ID.
- A score or priority band is a heuristic. An allowlisted command remains reviewable when corroborating risk signals appear.

## References

- [Microsoft SecurityEvent table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityevent)
- [Microsoft KQL datatable operator](https://learn.microsoft.com/en-us/kusto/query/datatable-operator)
- [Microsoft KQL getschema operator](https://learn.microsoft.com/en-us/kusto/query/getschema-operator)
- [Microsoft Sentinel in the Defender portal](https://learn.microsoft.com/en-us/azure/sentinel/microsoft-sentinel-defender-portal)
