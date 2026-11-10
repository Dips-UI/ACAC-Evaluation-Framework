"""Validation of immutable ACAC v1.4 human review submissions."""

from dataclasses import dataclass
import hashlib
from typing import Any

from .case_validation import validate_case
from .patches import validate_patch
from .strict_json import is_integer, loads_bytes, parse_rfc3339_timestamp


class ReviewRecordV14Error(ValueError):
    pass


@dataclass(frozen=True)
class ReviewValidationResult:
    valid: bool
    review_hash: str | None
    errors: tuple[str, ...]


_REQUIRED = {
    "schema_version", "review_id", "case_id", "reviewer_id", "reviewer_role",
    "independence_declaration", "independence_basis", "authorization_input_hash",
    "reference_id", "reference_revision", "reference_content_hash", "review_scope",
    "eligible_keys", "proposed_edits", "ambiguity_notes", "decision_reason", "completed_at",
}


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise ReviewRecordV14Error(f"invalid_{label}")
    return value


def _hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise ReviewRecordV14Error(f"invalid_{label}")


def _same_json_value(left: Any, right: Any) -> bool:
    if isinstance(left, dict) or isinstance(right, dict):
        return isinstance(left, dict) and isinstance(right, dict) and set(left) == set(right) and all(_same_json_value(left[k], right[k]) for k in left)
    if isinstance(left, list) or isinstance(right, list):
        return isinstance(left, list) and isinstance(right, list) and len(left) == len(right) and all(_same_json_value(a, b) for a, b in zip(left, right))
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left is right
    if is_integer(left) or is_integer(right):
        return is_integer(left) and is_integer(right) and int(left) == int(right)
    return type(left) is type(right) and left == right


def _canonical_key_scope(value: Any, label: str) -> list[tuple[str, str, str]]:
    if not isinstance(value, list):
        raise ReviewRecordV14Error(f"{label}_array_required")
    keys: list[tuple[str, str, str]] = []
    for key in value:
        if not isinstance(key, list) or len(key) != 3:
            raise ReviewRecordV14Error(f"{label}_invalid_key")
        parts = tuple(_identifier(part, f"{label}_key") for part in key)
        keys.append(parts)
    if len(keys) != len(set(keys)):
        raise ReviewRecordV14Error(f"{label}_duplicate_key")
    return sorted(keys)


def validate_human_review_v14(
    value: Any,
    *,
    review_bytes: bytes,
    case: Any,
    authorization_input: Any,
    authorization_input_bytes: bytes,
    reference: Any,
    reference_bytes: bytes,
) -> ReviewValidationResult:
    """Validate review structure and exact upstream artifact bindings.

    This checks identity, schema, retained bytes, and proposed-patch shape. It
    does not decide whether a review's authorization interpretation is correct.
    """
    try:
        if not all(isinstance(raw, bytes) for raw in (review_bytes, authorization_input_bytes, reference_bytes)):
            raise ReviewRecordV14Error("retained_exact_bytes_required")
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
            raise ReviewRecordV14Error("review_object_required")
        if set(value) not in (_REQUIRED, _REQUIRED | {"supersedes_review_id"}):
            raise ReviewRecordV14Error("review_members")
        try:
            parsed_review = loads_bytes(review_bytes)
            parsed_input = loads_bytes(authorization_input_bytes)
            parsed_reference = loads_bytes(reference_bytes)
        except Exception as exc:
            raise ReviewRecordV14Error("retained_artifact_json_invalid") from exc
        if not _same_json_value(parsed_review, value):
            raise ReviewRecordV14Error("review_bytes_content_mismatch")
        if not isinstance(authorization_input, dict) or not _same_json_value(parsed_input, authorization_input):
            raise ReviewRecordV14Error("authorization_input_bytes_content_mismatch")
        if not isinstance(reference, dict) or not _same_json_value(parsed_reference, reference):
            raise ReviewRecordV14Error("reference_bytes_content_mismatch")
        if value["schema_version"] != "acac-review-1.1" or value["reviewer_role"] != "human_reviewer":
            raise ReviewRecordV14Error("review_version_or_role")
        if not validate_case(case).valid or value["case_id"] != case["case_id"]:
            raise ReviewRecordV14Error("review_case_mismatch")
        input_hash = "sha256:" + hashlib.sha256(authorization_input_bytes).hexdigest()
        reference_hash = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
        if value["authorization_input_hash"] != input_hash:
            raise ReviewRecordV14Error("authorization_input_hash_mismatch")
        if value["reference_content_hash"] != reference_hash:
            raise ReviewRecordV14Error("reference_content_hash_mismatch")
        if value["reference_id"] != reference.get("reference_id") or value["reference_revision"] != reference.get("revision"):
            raise ReviewRecordV14Error("review_reference_identity_mismatch")
        for name in ("review_id", "case_id", "reviewer_id", "reference_id"):
            _identifier(value[name], name)
        if "supersedes_review_id" in value:
            _identifier(value["supersedes_review_id"], "supersedes_review_id")
        if type(value["independence_declaration"]) is not bool:
            raise ReviewRecordV14Error("independence_declaration_must_be_boolean")
        for name in ("independence_basis", "decision_reason"):
            if not isinstance(value[name], str) or not value[name]:
                raise ReviewRecordV14Error(f"{name}_required")
        if not is_integer(value["reference_revision"]) or int(value["reference_revision"]) <= 0:
            raise ReviewRecordV14Error("reference_revision_must_be_positive_integer")
        for name in ("authorization_input_hash", "reference_content_hash"):
            _hash(value[name], name)
        for name in ("review_scope", "eligible_keys", "proposed_edits", "ambiguity_notes"):
            if not isinstance(value[name], list) or any(item is None for item in value[name]):
                raise ReviewRecordV14Error(f"{name}_array_required")
        for note in value["ambiguity_notes"]:
            if not isinstance(note, str):
                raise ReviewRecordV14Error("ambiguity_notes_must_be_strings")
        input_scope = _canonical_key_scope(authorization_input.get("eligible_keys"), "authorization_input_scope")
        reference_scope = _canonical_key_scope(reference.get("eligible_keys"), "reference_scope")
        if input_scope != reference_scope:
            raise ReviewRecordV14Error("authorization_input_reference_scope_mismatch")
        review_scope = _canonical_key_scope(value["review_scope"], "review_scope")
        review_keys = _canonical_key_scope(value["eligible_keys"], "review_eligible_keys")
        if review_scope != input_scope:
            raise ReviewRecordV14Error("review_scope_mismatch")
        if review_keys != input_scope:
            raise ReviewRecordV14Error("review_eligible_keys_mismatch")
        try:
            timestamp = parse_rfc3339_timestamp(value["completed_at"])
        except Exception as exc:
            raise ReviewRecordV14Error("invalid_completed_at") from exc
        if not isinstance(value["completed_at"], str) or timestamp.original != value["completed_at"]:
            raise ReviewRecordV14Error("invalid_completed_at")
        declarations = {(item["table"], item["field"]): item for item in case["payload"]["field_declarations"]}
        patch = validate_patch(
            {"schema_version": "acac-1.3", "edits": value["proposed_edits"]},
            case["payload"]["ledger"], declarations, case["profile"],
        )
        if not patch.valid:
            raise ReviewRecordV14Error("invalid_review_proposed_edits:" + ",".join(patch.errors))
        digest = "sha256:" + hashlib.sha256(review_bytes).hexdigest()
        return ReviewValidationResult(True, digest, ())
    except Exception as exc:
        return ReviewValidationResult(False, None, (str(exc),))
