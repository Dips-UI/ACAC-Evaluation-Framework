"""V1 grading-result and N/A metric schema validation."""
from decimal import Decimal
from .strict_json import parse_rfc3339_timestamp


class ResultError(ValueError):
    pass


_METRICS = {"correct_target_count", "correct_replacement_count", "missed_corrections", "unauthorized_edits", "scope_violations", "collateral_changes", "preservation_accuracy"}


def _hash(value: object) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(ch in "0123456789abcdef" for ch in value[7:])


def validate_result(result: dict) -> None:
    required = {"schema_version", "case_id", "run_id", "contract_valid", "exact_edit_set_valid", "metrics", "diagnostics", "provenance"}
    if not isinstance(result, dict) or set(result) != required or result["schema_version"] != "acac-1.3":
        raise ResultError("result_members")
    if not isinstance(result["case_id"], str) or not result["case_id"] or not isinstance(result["run_id"], str) or not result["run_id"]:
        raise ResultError("result_identity")
    if type(result["contract_valid"]) is not bool or type(result["exact_edit_set_valid"]) is not bool:
        raise ResultError("result_flags")
    if result["exact_edit_set_valid"] and not result["contract_valid"]:
        raise ResultError("invalid_exact_validity_without_contract")
    if not isinstance(result["metrics"], dict) or set(result["metrics"]) != _METRICS or not isinstance(result["diagnostics"], list):
        raise ResultError("result_metrics")
    if not result["contract_valid"] and not result["diagnostics"]:
        raise ResultError("structural_failure_diagnostics_required")
    for name, value in result["metrics"].items():
        if value is None:
            raise ResultError("null_metric")
        if isinstance(value, dict):
            if set(value) != {"status", "reason"} or value["status"] != "not_applicable" or not isinstance(value["reason"], str) or not value["reason"].strip():
                raise ResultError("invalid_na_metric")
        elif isinstance(value, Decimal):
            if name != "preservation_accuracy" or not value.is_finite() or not (Decimal(0) <= value <= Decimal(1)):
                raise ResultError("invalid_metric")
        elif type(value) is int:
            if value < 0 or value > 2**63 - 1 or (name == "preservation_accuracy" and value not in (0, 1)):
                raise ResultError("invalid_metric")
        elif isinstance(value, float) or isinstance(value, bool):
            raise ResultError("invalid_metric")
        else:
            raise ResultError("invalid_metric")
    count_metrics = _METRICS - {"preservation_accuracy"}
    if result["contract_valid"]:
        if any(isinstance(result["metrics"][name], dict) for name in count_metrics):
            raise ResultError("ledger_metric_not_applicable_for_valid_contract")
        preservation = result["metrics"]["preservation_accuracy"]
        if isinstance(preservation, dict) and preservation["reason"] != "empty_preservation_denominator":
            raise ResultError("invalid_preservation_na_reason")
    else:
        if result["exact_edit_set_valid"]:
            raise ResultError("invalid_exact_validity_without_contract")
        for name, value in result["metrics"].items():
            if not isinstance(value, dict) or value["reason"] != "structural_invalidity":
                raise ResultError("structural_invalidity_metrics_must_be_na")
    provenance = result["provenance"]
    base_provenance = {"case_exact_hash", "authorization_spec_hash", "reference_hash", "approval_event_hash", "reference_governance_status", "raw_output_hash", "prompt_hash", "configuration_hash", "grader_version"}
    if not isinstance(provenance, dict) or provenance.get("grader_version") != "acac-grader-1.3" or set(provenance) not in (base_provenance, base_provenance | {"freeze_event_hash"}):
        raise ResultError("result_provenance")
    if provenance["reference_governance_status"] not in {"approved_unfrozen", "frozen"}:
        raise ResultError("invalid_governance_status")
    frozen = provenance["reference_governance_status"] == "frozen"
    if frozen != ("freeze_event_hash" in provenance):
        raise ResultError("freeze_event_hash_conditional")
    for name, value in provenance.items():
        if name.endswith("_hash") and not _hash(value):
            raise ResultError("invalid_provenance_hash")
