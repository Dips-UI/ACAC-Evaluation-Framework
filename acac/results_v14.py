"""Validation for immutable ACAC v1.4 grading results."""

from fractions import Fraction
from typing import Any

from .metrics_v14 import RationalMetricError, validate_rational


class ResultV14Error(ValueError):
    pass


_METRICS = {
    "correct_target_count", "correct_replacement_count", "missed_corrections",
    "unauthorized_edits", "scope_violations", "collateral_changes",
    "preservation_accuracy",
}
_PROVENANCE = {
    "case_exact_hash", "authorization_input_hash", "review_submission_hashes",
    "final_authorization_sidecar_hash", "reference_hash", "adjudication_hash",
    "approval_event_hash", "reference_governance_status", "raw_output_hash",
    "prompt_hash", "configuration_hash", "grader_version",
}


def _hash(value: Any) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise ResultV14Error("invalid_result_hash")


def _id(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise ResultV14Error(f"invalid_{label}")


def validate_result_v14(value: Any) -> None:
    required = {"schema_version", "case_id", "run_id", "contract_valid", "exact_edit_set_valid", "metrics", "diagnostics", "provenance"}
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value) or set(value) != required:
        raise ResultV14Error("result_members")
    if value["schema_version"] != "acac-1.4":
        raise ResultV14Error("result_version")
    _id(value["case_id"], "case_id")
    _id(value["run_id"], "run_id")
    if type(value["contract_valid"]) is not bool or type(value["exact_edit_set_valid"]) is not bool:
        raise ResultV14Error("result_validity_flags")
    if value["exact_edit_set_valid"] and not value["contract_valid"]:
        raise ResultV14Error("exact_validity_requires_contract_validity")
    metrics = value["metrics"]
    if not isinstance(metrics, dict) or set(metrics) != _METRICS:
        raise ResultV14Error("result_metric_members")
    if not isinstance(value["diagnostics"], list) or any(not isinstance(item, str) for item in value["diagnostics"]):
        raise ResultV14Error("result_diagnostics")
    if not value["contract_valid"] and not value["diagnostics"]:
        raise ResultV14Error("structural_failure_diagnostics_required")
    for name, item in metrics.items():
        if isinstance(item, dict):
            if name == "preservation_accuracy" and set(item) == {"numerator", "denominator"}:
                try:
                    validate_rational(item, minimum=Fraction(0), maximum=Fraction(1))
                except (RationalMetricError, TypeError) as exc:
                    raise ResultV14Error("invalid_ratio_metric") from exc
                continue
            if set(item) != {"status", "reason"} or item["status"] != "not_applicable" or not isinstance(item["reason"], str) or not item["reason"]:
                raise ResultV14Error("invalid_na_metric")
            continue
        if name == "preservation_accuracy":
            try:
                validate_rational(item, minimum=Fraction(0), maximum=Fraction(1))
            except (RationalMetricError, TypeError) as exc:
                raise ResultV14Error("invalid_ratio_metric") from exc
        elif type(item) is not int or item < 0 or item > 2**63 - 1:
            raise ResultV14Error("invalid_count_metric")
    if value["contract_valid"]:
        if any(isinstance(metrics[name], dict) for name in _METRICS - {"preservation_accuracy"}):
            raise ResultV14Error("valid_contract_count_metric_na")
        if (
            isinstance(metrics["preservation_accuracy"], dict)
            and set(metrics["preservation_accuracy"]) == {"status", "reason"}
            and metrics["preservation_accuracy"]["reason"] != "empty_preservation_denominator"
        ):
            raise ResultV14Error("invalid_preservation_na")
    else:
        if value["exact_edit_set_valid"] or any(
            not isinstance(item, dict) or item.get("status") != "not_applicable" or item.get("reason") != "structural_invalidity"
            for item in metrics.values()
        ):
            raise ResultV14Error("structural_invalidity_metric_shape")
    provenance = value["provenance"]
    if not isinstance(provenance, dict) or set(provenance) not in (_PROVENANCE, _PROVENANCE | {"freeze_event_hash"}):
        raise ResultV14Error("result_provenance_members")
    if provenance["grader_version"] != "acac-grader-1.4":
        raise ResultV14Error("result_grader_version")
    if provenance["reference_governance_status"] not in {"approved_unfrozen", "frozen"}:
        raise ResultV14Error("result_governance_status")
    if (provenance["reference_governance_status"] == "frozen") != ("freeze_event_hash" in provenance):
        raise ResultV14Error("freeze_hash_conditional")
    for name, digest in provenance.items():
        if name.endswith("_hash"):
            _hash(digest)
    reviews = provenance["review_submission_hashes"]
    if not isinstance(reviews, list) or not reviews or len(reviews) != len(set(reviews)):
        raise ResultV14Error("result_review_hashes")
    for digest in reviews:
        _hash(digest)
