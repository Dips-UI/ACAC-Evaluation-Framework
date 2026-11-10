"""Validation for ACAC v1.4 final authorization sidecars and review bindings."""

from dataclasses import dataclass
import hashlib
from typing import Any

from .authorization_input import (
    _RESOLUTION,
    _TEMPORAL,
    _verify_registry,
    _validate_issues,
    validate_authorization_input,
)
from .case_validation import validate_case
from .review_records_v14 import validate_human_review_v14
from .strict_json import is_integer, loads_bytes, parse_rfc3339_timestamp


class AuthorizationSidecarV14Error(ValueError):
    pass


@dataclass(frozen=True)
class SidecarValidationResult:
    valid: bool
    status: str | None
    sidecar_hash: str | None
    errors: tuple[str, ...]


_COMMON = {
    "spec_version", "case_id", "source_case_hash", "authorization_input_hash",
    "review_submission_hashes", "resolution_status", "profile", "resolution_issues",
    "resolved_by", "resolution_note",
}


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


def _hash_shape(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise AuthorizationSidecarV14Error(f"invalid_{label}")


def _validate_resolved_by(value: Any, listed_hashes: set[str], reviews: dict[str, dict]) -> None:
    if not isinstance(value, list) or not value:
        raise AuthorizationSidecarV14Error("resolved_by_required")
    seen: set[str] = set()
    for provenance in value:
        required = {"reviewer_id", "role", "reviewed_at", "independence_declaration", "review_submission_hash"}
        if not isinstance(provenance, dict) or set(provenance) != required:
            raise AuthorizationSidecarV14Error("resolved_by_shape")
        digest = provenance["review_submission_hash"]
        if digest not in listed_hashes or digest in seen or digest not in reviews:
            raise AuthorizationSidecarV14Error("resolved_by_review_binding")
        review = reviews[digest]
        if (
            provenance["reviewer_id"] != review["reviewer_id"]
            or provenance["role"] != review["reviewer_role"]
            or provenance["reviewed_at"] != review["completed_at"]
            or type(provenance["independence_declaration"]) is not bool
            or provenance["independence_declaration"] is not review["independence_declaration"]
        ):
            raise AuthorizationSidecarV14Error("resolved_by_review_provenance_mismatch")
        seen.add(digest)


def validate_final_sidecar_v14(
    value: Any,
    *,
    sidecar_bytes: bytes,
    case: Any,
    case_bytes: bytes,
    authorization_input: Any,
    authorization_input_bytes: bytes,
    reference: Any,
    reference_bytes: bytes,
    reviews_by_hash: dict[str, tuple[dict, bytes]],
    retained_artifacts: dict[str, bytes] | None = None,
) -> SidecarValidationResult:
    """Validate exact input/review/sidecar identity and status-dependent shape.

    This is a component validator. It does not by itself approve a reference or
    authorize grading; lifecycle, reference integrity, and manifest gates are
    still required by the integrated coordinator.
    """
    status = value.get("resolution_status") if isinstance(value, dict) else None
    try:
        if not isinstance(sidecar_bytes, bytes) or not isinstance(case_bytes, bytes) or not isinstance(authorization_input_bytes, bytes) or not isinstance(reference_bytes, bytes):
            raise AuthorizationSidecarV14Error("retained_exact_bytes_required")
        parsed = loads_bytes(sidecar_bytes)
        if not _same_json_value(parsed, value):
            raise AuthorizationSidecarV14Error("sidecar_bytes_content_mismatch")
        case_result = validate_case(case)
        if not case_result.valid or not _same_json_value(loads_bytes(case_bytes), case):
            raise AuthorizationSidecarV14Error("invalid_or_mismatched_case")
        input_result = validate_authorization_input(
            authorization_input, case,
            authorization_input_bytes=authorization_input_bytes,
            case_bytes=case_bytes,
            retained_artifacts=retained_artifacts,
        )
        if not input_result.valid:
            raise AuthorizationSidecarV14Error("invalid_authorization_input:" + ",".join(input_result.errors))
        if not isinstance(reference, dict) or not _same_json_value(loads_bytes(reference_bytes), reference):
            raise AuthorizationSidecarV14Error("reference_bytes_content_mismatch")
        if not isinstance(reviews_by_hash, dict):
            raise AuthorizationSidecarV14Error("review_artifact_map_required")
        temporal = bool(case["payload"].get("temporal_conditions"))
        resolved_members = _RESOLUTION | (_TEMPORAL if temporal else set()) | ({"temporal_reconciliation"} if temporal else set())
        expected = _COMMON | (resolved_members if status == "resolved" else set()) | ({"evidence_registry"} if status != "resolved" and "evidence_registry" in value else set())
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value) or set(value) != expected:
            raise AuthorizationSidecarV14Error("sidecar_members")
        if value["spec_version"] != "acac-auth-1.2":
            raise AuthorizationSidecarV14Error("unsupported_sidecar_version")
        if value["case_id"] != case["case_id"] or value["profile"] != case["profile"]:
            raise AuthorizationSidecarV14Error("sidecar_case_identity_mismatch")
        exact_case_hash = "sha256:" + hashlib.sha256(case_bytes).hexdigest()
        exact_input_hash = "sha256:" + hashlib.sha256(authorization_input_bytes).hexdigest()
        if value["source_case_hash"] != exact_case_hash:
            raise AuthorizationSidecarV14Error("source_case_hash_mismatch")
        if value["authorization_input_hash"] != exact_input_hash:
            raise AuthorizationSidecarV14Error("authorization_input_hash_mismatch")
        if not isinstance(value["resolution_note"], str):
            raise AuthorizationSidecarV14Error("resolution_note_must_be_string")
        issues = value["resolution_issues"]
        issue_ids = _validate_issues(issues)
        if status not in {"resolved", "ambiguous", "quarantined"}:
            raise AuthorizationSidecarV14Error("unsupported_resolution_status")
        if status == "resolved" and issues:
            raise AuthorizationSidecarV14Error("resolved_sidecar_issues_must_be_empty")
        if status != "resolved" and not issues:
            raise AuthorizationSidecarV14Error("unresolved_status_requires_issue")
        hashes = value["review_submission_hashes"]
        if not isinstance(hashes, list) or not hashes:
            raise AuthorizationSidecarV14Error("review_submission_hashes_required")
        if any(not isinstance(digest, str) for digest in hashes):
            raise AuthorizationSidecarV14Error("invalid_review_submission_hash")
        for digest in hashes:
            _hash_shape(digest, "review_submission_hash")
        listed_hashes = set(hashes)
        if len(listed_hashes) != len(hashes):
            raise AuthorizationSidecarV14Error("duplicate_review_submission_hash")
        validated_reviews: dict[str, dict] = {}
        for digest in hashes:
            pair = reviews_by_hash.get(digest)
            if not isinstance(pair, tuple) or len(pair) != 2:
                raise AuthorizationSidecarV14Error("review_artifact_missing")
            review, raw = pair
            review_result = validate_human_review_v14(
                review, review_bytes=raw, case=case,
                authorization_input=authorization_input,
                authorization_input_bytes=authorization_input_bytes,
                reference=reference, reference_bytes=reference_bytes,
            )
            if not review_result.valid or review_result.review_hash != digest:
                raise AuthorizationSidecarV14Error("review_artifact_invalid:" + ",".join(review_result.errors))
            validated_reviews[digest] = review

        if status == "resolved":
            for name in _RESOLUTION | (_TEMPORAL if temporal else set()):
                expected_value = authorization_input[name]
                if name not in value or not _same_json_value(value[name], expected_value):
                    raise AuthorizationSidecarV14Error("sidecar_resolution_differs_from_input")
            _validate_resolved_by(value["resolved_by"], listed_hashes, validated_reviews)
            if temporal:
                reconciliation = value["temporal_reconciliation"]
                if not isinstance(reconciliation, dict) or set(reconciliation) != {"status", "review_submission_hashes", "checked_at"}:
                    raise AuthorizationSidecarV14Error("temporal_reconciliation_shape")
                if reconciliation["status"] != "succeeded":
                    raise AuthorizationSidecarV14Error("temporal_reconciliation_not_succeeded")
                reconciliation_hashes = reconciliation["review_submission_hashes"]
                if not isinstance(reconciliation_hashes, list) or not reconciliation_hashes or any(not isinstance(item, str) for item in reconciliation_hashes):
                    raise AuthorizationSidecarV14Error("temporal_reconciliation_review_hashes_required")
                if len(set(reconciliation_hashes)) != len(reconciliation_hashes) or not set(reconciliation_hashes) <= listed_hashes:
                    raise AuthorizationSidecarV14Error("temporal_reconciliation_review_hash_mismatch")
                try:
                    parse_rfc3339_timestamp(reconciliation["checked_at"])
                except Exception as exc:
                    raise AuthorizationSidecarV14Error("temporal_reconciliation_checked_at_invalid") from exc
        else:
            unresolved_forbidden = (
                (_RESOLUTION - {"evidence_registry"})
                | _TEMPORAL
                | {"temporal_reconciliation"}
            )
            if any(name in value for name in unresolved_forbidden):
                raise AuthorizationSidecarV14Error("unresolved_sidecar_has_resolved_members")
            expected_ids = {eid for issue in issues for eid in issue["evidence_ids"]}
            if expected_ids:
                registry_ids = _verify_registry(value.get("evidence_registry", []), retained=retained_artifacts or {})
                if registry_ids != expected_ids:
                    raise AuthorizationSidecarV14Error("issue_evidence_registry_mismatch")
            elif value.get("evidence_registry", []) not in ([],):
                raise AuthorizationSidecarV14Error("unresolved_evidence_registry_forbidden")

        sidecar_hash = "sha256:" + hashlib.sha256(sidecar_bytes).hexdigest()
        return SidecarValidationResult(True, status, sidecar_hash, ())
    except Exception as exc:
        return SidecarValidationResult(False, status, None, (str(exc),))
