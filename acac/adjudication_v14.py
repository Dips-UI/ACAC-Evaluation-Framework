"""Validation of v1.4 adjudication evidence, separate from human reviews."""

from dataclasses import dataclass
import hashlib
from typing import Any

from .strict_json import is_integer, loads_bytes, parse_rfc3339_timestamp


class AdjudicationV14Error(ValueError):
    pass


@dataclass(frozen=True)
class AdjudicationValidationResult:
    valid: bool
    adjudication_hash: str | None
    errors: tuple[str, ...]
    unauthorized_exceptions: tuple[tuple[str, str, tuple[str, str, str], str], ...] = ()


_FIELDS = {
    "review_id", "case_id", "reviewer_role", "source_case_hash",
    "authorization_input_hash", "reference_id", "reference_revision",
    "reference_content_hash", "considered_review_hashes", "disagreement_disposition",
    "decision_rationale", "exception_decisions", "adjudicator_id", "independence_declaration",
    "independence_basis", "completed_at",
}
_EXCEPTION_DECISION_FIELDS = {
    "exception_id", "exclusion_id", "key", "decision", "instruction_ids",
    "source_locations", "evidence_ids", "rationale",
}


def _hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise AdjudicationV14Error(f"invalid_{label}")


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise AdjudicationV14Error(f"invalid_{label}")
    return value


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, dict) or isinstance(right, dict):
        return isinstance(left, dict) and isinstance(right, dict) and set(left) == set(right) and all(_same(left[k], right[k]) for k in left)
    if isinstance(left, list) or isinstance(right, list):
        return isinstance(left, list) and isinstance(right, list) and len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left is right
    if is_integer(left) or is_integer(right):
        return is_integer(left) and is_integer(right) and int(left) == int(right)
    return type(left) is type(right) and left == right


def _exception_decisions(
    records: Any,
    *,
    candidates: tuple[tuple[str, str, tuple[str, str, str]], ...],
    case: dict,
    authorization_input: dict,
) -> tuple[tuple[str, str, tuple[str, str, str], str], ...]:
    if not isinstance(records, list):
        raise AdjudicationV14Error("exception_decisions_array_required")
    expected = set(candidates)
    seen: set[tuple[str, str, tuple[str, str, str]]] = set()
    unauthorized: list[tuple[str, str, tuple[str, str, str], str]] = []
    exceptions = {
        item["exception_id"]: item
        for item in authorization_input.get("exceptions_applied", [])
    }
    input_evidence = {
        item["evidence_id"] for item in authorization_input.get("evidence_registry", [])
    }
    update_locations = {
        update["update_id"]: f"/payload/updates/{index}/text"
        for index, update in enumerate(case["payload"]["updates"])
    }
    instruction_locations = {"original": "/payload/original_guideline", **update_locations}
    instruction_locations[case["payload"]["notice"]["notice_id"]] = "/payload/notice/authority_text"

    for record in records:
        if not isinstance(record, dict) or any(not isinstance(key, str) for key in record) or set(record) != _EXCEPTION_DECISION_FIELDS:
            raise AdjudicationV14Error("exception_decision_members")
        for name in ("exception_id", "exclusion_id"):
            _id(record[name], name)
        key_value = record["key"]
        if not isinstance(key_value, list) or len(key_value) != 3:
            raise AdjudicationV14Error("exception_decision_key_invalid")
        key = tuple(_id(part, "exception_decision_key") for part in key_value)
        identity = (record["exception_id"], record["exclusion_id"], key)
        if identity not in expected:
            raise AdjudicationV14Error("exception_decision_unexpected_tuple")
        if identity in seen:
            raise AdjudicationV14Error("exception_decision_duplicate_tuple")
        seen.add(identity)
        if not isinstance(record["decision"], str) or record["decision"] not in {"authorized", "not_authorized", "unresolved"}:
            raise AdjudicationV14Error("exception_decision_value_invalid")
        if record["decision"] != "authorized":
            unauthorized.append((record["exception_id"], record["exclusion_id"], key, record["decision"]))
        exception = exceptions.get(record["exception_id"])
        if exception is None:
            raise AdjudicationV14Error("exception_decision_unknown_exception")
        ids = record["instruction_ids"]
        if not isinstance(ids, list) or not ids or any(not isinstance(item, str) for item in ids):
            raise AdjudicationV14Error("exception_decision_instruction_ids_required")
        for instruction_id in ids:
            _id(instruction_id, "exception_decision_instruction_id")
        if set(ids) != set(exception["instruction_ids"]):
            raise AdjudicationV14Error("exception_decision_instruction_binding_mismatch")
        locations = record["source_locations"]
        if not isinstance(locations, list) or not locations or any(not isinstance(item, str) for item in locations):
            raise AdjudicationV14Error("exception_decision_source_locations_required")
        allowed_locations = {instruction_locations[item] for item in ids if item in instruction_locations}
        if not set(locations) <= allowed_locations or len(locations) != len(set(locations)):
            raise AdjudicationV14Error("exception_decision_source_location_mismatch")
        evidence = record["evidence_ids"]
        if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
            raise AdjudicationV14Error("exception_decision_evidence_ids_invalid")
        if len(evidence) != len(set(evidence)) or not set(evidence) <= input_evidence:
            raise AdjudicationV14Error("exception_decision_evidence_binding_mismatch")
        if not isinstance(record["rationale"], str) or not record["rationale"]:
            raise AdjudicationV14Error("exception_decision_rationale_required")
    if seen != expected:
        raise AdjudicationV14Error("exception_decision_coverage_mismatch")
    return tuple(unauthorized)


def validate_adjudication_v14(
    value: Any,
    *,
    adjudication_bytes: bytes,
    case_id: str,
    source_case_hash: str,
    authorization_input_hash: str,
    reference: dict,
    reference_bytes: bytes,
    review_hashes: set[str],
    case: dict,
    authorization_input: dict,
    exception_decision_candidates: tuple[tuple[str, str, tuple[str, str, str]], ...],
) -> AdjudicationValidationResult:
    """Validate immutable adjudication provenance and exact upstream bindings."""
    try:
        if not isinstance(adjudication_bytes, bytes) or not isinstance(reference_bytes, bytes):
            raise AdjudicationV14Error("retained_exact_bytes_required")
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value) or set(value) != _FIELDS:
            raise AdjudicationV14Error("adjudication_members")
        if not _same(loads_bytes(adjudication_bytes), value):
            raise AdjudicationV14Error("adjudication_bytes_content_mismatch")
        if not isinstance(reference, dict) or not _same(loads_bytes(reference_bytes), reference):
            raise AdjudicationV14Error("reference_bytes_content_mismatch")
        if value["reviewer_role"] != "adjudicator":
            raise AdjudicationV14Error("adjudication_role_mismatch")
        for name in ("review_id", "case_id", "reference_id", "adjudicator_id"):
            _id(value[name], name)
        if value["case_id"] != case_id or value["case_id"] != reference.get("case_id"):
            raise AdjudicationV14Error("adjudication_case_mismatch")
        if value["reference_id"] != reference.get("reference_id") or value["reference_revision"] != reference.get("revision"):
            raise AdjudicationV14Error("adjudication_reference_mismatch")
        if not is_integer(value["reference_revision"]) or int(value["reference_revision"]) <= 0:
            raise AdjudicationV14Error("invalid_reference_revision")
        for name, expected in (("source_case_hash", source_case_hash), ("authorization_input_hash", authorization_input_hash)):
            _hash(value[name], name)
            if value[name] != expected:
                raise AdjudicationV14Error(f"{name}_mismatch")
        ref_hash = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
        _hash(value["reference_content_hash"], "reference_content_hash")
        if value["reference_content_hash"] != ref_hash:
            raise AdjudicationV14Error("reference_content_hash_mismatch")
        if type(value["independence_declaration"]) is not bool:
            raise AdjudicationV14Error("independence_declaration_must_be_boolean")
        for name in ("decision_rationale", "independence_basis"):
            if not isinstance(value[name], str) or not value[name]:
                raise AdjudicationV14Error(f"{name}_required")
        considered = value["considered_review_hashes"]
        if not isinstance(considered, list) or not considered:
            raise AdjudicationV14Error("considered_review_hashes_required")
        for digest in considered:
            _hash(digest, "considered_review_hash")
        if len(considered) != len(set(considered)):
            raise AdjudicationV14Error("duplicate_considered_review_hash")
        if not isinstance(review_hashes, set) or not set(considered) <= review_hashes:
            raise AdjudicationV14Error("considered_review_not_retained")
        if not isinstance(value["disagreement_disposition"], list) or not value["disagreement_disposition"]:
            raise AdjudicationV14Error("disagreement_disposition_required")
        unauthorized = _exception_decisions(
            value["exception_decisions"],
            candidates=exception_decision_candidates,
            case=case,
            authorization_input=authorization_input,
        )
        parse_rfc3339_timestamp(value["completed_at"])
        digest = "sha256:" + hashlib.sha256(adjudication_bytes).hexdigest()
        return AdjudicationValidationResult(True, digest, (), unauthorized_exceptions=unauthorized)
    except Exception as exc:
        return AdjudicationValidationResult(False, None, (str(exc),))
