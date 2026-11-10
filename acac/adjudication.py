"""Structural adjudication and AI-audit artifact validation."""
from decimal import Decimal
from .strict_json import parse_rfc3339_timestamp


class AdjudicationError(ValueError):
    pass


def _valid_hash(value):
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(char in "0123456789abcdef" for char in value[7:])


def _validate_model_setting(value):
    if value is None or isinstance(value, float):
        raise AdjudicationError("invalid_model_setting_value")
    if isinstance(value, bool) or isinstance(value, str):
        return
    if isinstance(value, int):
        if value < -(2**63) or value > 2**63 - 1:
            raise AdjudicationError("model_setting_integer_out_of_range")
        return
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise AdjudicationError("invalid_model_setting_decimal")
        return
    if isinstance(value, list):
        for item in value:
            _validate_model_setting(item)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise AdjudicationError("model_setting_keys_must_be_strings")
        for item in value.values():
            _validate_model_setting(item)
        return
    raise AdjudicationError("invalid_model_setting_value")


def validate_adjudication(value: dict) -> None:
    required = {"review_id", "case_id", "reviewer_role", "source_case_hash", "authorization_spec_hash", "reference_content_hash", "considered_review_hashes", "disagreement_disposition", "decision_rationale", "adjudicator_id", "independence_declaration", "independence_basis", "completed_at"}
    if not isinstance(value, dict) or set(value) != required or value["reviewer_role"] != "adjudicator":
        raise AdjudicationError("invalid_adjudication")
    if type(value["independence_declaration"]) is not bool or not isinstance(value["considered_review_hashes"], list) or not value["considered_review_hashes"] or not isinstance(value["disagreement_disposition"], list) or not value["disagreement_disposition"]:
        raise AdjudicationError("invalid_adjudication_fields")
    for name in ("source_case_hash", "authorization_spec_hash", "reference_content_hash"):
        if not _valid_hash(value[name]):
            raise AdjudicationError("invalid_adjudication_hash")
    for review in value["considered_review_hashes"]:
        if not _valid_hash(review):
            raise AdjudicationError("invalid_considered_review_hash")
    for name in ("review_id", "case_id", "adjudicator_id", "decision_rationale", "independence_basis"):
        if not isinstance(value[name], str) or not value[name].strip():
            raise AdjudicationError(f"invalid_{name}")
    parse_rfc3339_timestamp(value["completed_at"])


def validate_ai_audit(value: dict) -> None:
    if not isinstance(value, dict) or value.get("reviewer_role") != "ai_auditor" or "model_metadata" not in value:
        raise AdjudicationError("invalid_ai_audit")
    required = {"provider", "family", "model_id", "version", "runtime_version", "prompt_hash", "settings", "run_timestamp"}
    model = value["model_metadata"]
    if not isinstance(model, dict) or set(model) != required:
        raise AdjudicationError("invalid_model_metadata")
    if any(not isinstance(model[name], str) or not model[name] for name in ("provider", "family", "model_id", "version", "runtime_version")) or not isinstance(model["settings"], dict):
        raise AdjudicationError("invalid_model_metadata")
    if not _valid_hash(model["prompt_hash"]):
        raise AdjudicationError("invalid_model_metadata")
    _validate_model_setting(model["settings"])
    parse_rfc3339_timestamp(model["run_timestamp"])
