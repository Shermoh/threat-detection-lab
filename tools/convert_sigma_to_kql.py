"""Convert the repository's Sigma rule with an actual pySigma Kusto backend.

Target: Azure Monitor's SecurityEvent table. This creates a QUERY STRING
only. Deployment in Sentinel is a separate approval/validation step.
"""
from pathlib import Path

from sigma.backends.kusto import KustoBackend
from sigma.pipelines.azuremonitor.azuremonitor import azure_monitor_pipeline
from sigma.rule import SigmaRule


ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = ROOT / "detections/sigma/proc_creation_win_powershell_encoded_command_lab.yml"


def convert_rule() -> str:
    rule = SigmaRule.from_yaml(RULE_PATH.read_text(encoding="utf-8"))
    backend = KustoBackend(
        processing_pipeline=azure_monitor_pipeline(query_table="SecurityEvent")
    )
    results = backend.convert_rule(rule)
    if len(results) != 1 or not isinstance(results[0], str):
        raise RuntimeError("Expected exactly one KQL query from the Sigma backend")
    query = results[0].strip()
    for required in ("SecurityEvent", "NewProcessName", "CommandLine"):
        if required not in query:
            raise RuntimeError(
                "Incomplete Azure Monitor mapping: missing " + required + " in " + query
            )
    return query


if __name__ == "__main__":
    print("-----BEGIN-PYSIGMA-GENERATED-KQL-----")
    print(convert_rule())
    print("-----END-PYSIGMA-GENERATED-KQL-----")
