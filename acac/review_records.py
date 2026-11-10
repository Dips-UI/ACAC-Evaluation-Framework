"""Structural validation for immutable V1 review artifacts."""
from .strict_json import parse_rfc3339_timestamp


class ReviewRecordError(ValueError):
    pass


def _hash(value: object) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(char in "0123456789abcdef" for char in value[7:])


def validate_human_review(value: dict) -> None:
    required = {"review_id", "case_id", "reviewer_id", "reviewer_role", "independence_declaration", "independence_basis", "source_case_hash", "authorization_spec_hash", "reference_content_hash", "review_scope", "eligible_keys", "proposed_edits", "ambiguity_notes", "decision_reason", "completed_at"}
    if not isinstance(value, dict) or not set(value) <= required | {"supersedes_review_id"} or not required <= set(value) or value["reviewer_role"] != "human_reviewer":
        raise ReviewRecordError("invalid_human_review")
    if type(value["independence_declaration"]) is not bool or not isinstance(value["independence_basis"], str) or not value["independence_basis"].strip():
        raise ReviewRecordError("invalid_independence")
    if "supersedes_review_id" in value and (not isinstance(value["supersedes_review_id"], str) or not value["supersedes_review_id"].strip() or value["supersedes_review_id"] == value["review_id"]):
        raise ReviewRecordError("invalid_supersedes_review_id")
    for name in ("review_id", "case_id", "reviewer_id"):
        if not isinstance(value[name], str) or not value[name] or value[name].strip() != value[name] or not value[name].isprintable():
            raise ReviewRecordError("invalid_review_identity")
    for name in ("source_case_hash", "authorization_spec_hash", "reference_content_hash"):
        if not _hash(value[name]):
            raise ReviewRecordError("invalid_review_hash")
    parse_rfc3339_timestamp(value["completed_at"])
    if not isinstance(value["review_scope"], list) or not isinstance(value["eligible_keys"], list) or not isinstance(value["proposed_edits"], list) or not isinstance(value["ambiguity_notes"], list):
        raise ReviewRecordError("invalid_review_arrays")
    if not isinstance(value["decision_reason"], str) or not value["decision_reason"].strip():
        raise ReviewRecordError("decision_reason_required")
    for key in value["eligible_keys"]:
        if not isinstance(key, list) or len(key) != 3 or any(not isinstance(part, str) or not part for part in key):
            raise ReviewRecordError("invalid_review_eligible_key")
