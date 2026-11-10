"""Structural validation for trusted V1 authorization sidecars.

Authorization meaning remains human-resolved; this module validates structure,
identity, hashes, namespaces, and resolved-key coverage only.
"""
from dataclasses import dataclass
from typing import Any
import hashlib
from .strict_json import matches_type, parse_rfc3339_timestamp
from .temporal import reconcile as reconcile_temporal
from .predicates import PredicateContext, evaluate as evaluate_predicate, validate_definition
from .case_validation import validate_case


class AuthorizationError(ValueError):
    pass


@dataclass(frozen=True)
class AuthorizationResult:
    valid: bool
    status: str | None
    errors: tuple[str, ...]


_COMMON = {"spec_version", "case_id", "source_case_hash", "resolution_status", "profile", "resolution_issues", "resolved_by", "resolution_note"}
_RESOLVED = {"governing_instruction_ids", "predicate_definitions", "evidence_registry", "eligible_keys", "eligibility_rationale", "exclusions", "exceptions_applied", "required_final_values", "preservation_keys", "rationale_by_key"}


def _id(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise AuthorizationError(f"invalid_{label}")


def _hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise AuthorizationError(f"invalid_{label}")


def _verify_hash(value: Any, label: str, retained: dict[str, bytes] | None) -> None:
    _hash(value, label)
    if retained is None or value not in retained:
        raise AuthorizationError(f"retained_{label}_required")
    raw = retained[value]
    if not isinstance(raw, bytes) or "sha256:" + hashlib.sha256(raw).hexdigest() != value:
        raise AuthorizationError(f"{label}_mismatch")


def _keys(obj: Any, required: set[str], optional: set[str] = set()) -> None:
    if not isinstance(obj, dict):
        raise AuthorizationError("object_required")
    keys = set(obj)
    if any(not isinstance(k, str) for k in keys):
        raise AuthorizationError("string_keys_required")
    if keys - required - optional or required - keys:
        raise AuthorizationError("invalid_members")


def _issues(value: Any) -> None:
    if not isinstance(value, list):
        raise AuthorizationError("resolution_issues_array_required")
    for issue in value:
        _keys(issue, {"issue_id", "category", "source_location", "description", "evidence_ids"})
        _id(issue["issue_id"], "issue_id"); _id(issue["category"], "category"); _id(issue["source_location"], "source_location")
        if not isinstance(issue["description"], str) or not isinstance(issue["evidence_ids"], list):
            raise AuthorizationError("invalid_resolution_issue")
        for evidence_id in issue["evidence_ids"]: _id(evidence_id, "evidence_id")


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AuthorizationError(f"{label}_array_required")
    if any(item is None for item in value):
        raise AuthorizationError(f"{label}_null_forbidden")
    return value


def _unique_ids(entries: list[Any], member: str, label: str) -> None:
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get(member), str):
            raise AuthorizationError(f"invalid_{label}")
        _id(entry[member], member)
        if entry[member] in seen:
            raise AuthorizationError(f"duplicate_{label}")
        seen.add(entry[member])


def _temporal_rules(value: Any) -> None:
    rules = _array(value, "temporal_rules")
    required = {"rule_id", "source_condition_id", "source_location", "occurrence_index", "instruction_id", "predicate_id", "effective_at", "effective_boundary"}
    seen_pairs, seen_conditions = set(), set()
    for rule in rules:
        _keys(rule, required)
        for name in ("rule_id", "source_condition_id", "instruction_id", "predicate_id"):
            _id(rule[name], name)
        if not isinstance(rule["source_location"], str) or (rule["source_location"] and not rule["source_location"].startswith("/")):
            raise AuthorizationError("invalid_source_location")
        if type(rule["occurrence_index"]) is not int or rule["occurrence_index"] != 0:
            raise AuthorizationError("invalid_occurrence_index")
        _timestamp = parse_rfc3339_timestamp(rule["effective_at"])
        del _timestamp
        if rule["effective_boundary"] not in {"inclusive", "exclusive"}:
            raise AuthorizationError("invalid_effective_boundary")
        pair = (rule["source_location"], rule["occurrence_index"])
        if pair in seen_pairs:
            raise AuthorizationError("duplicate_source_condition_identity")
        if rule["source_condition_id"] in seen_conditions:
            raise AuthorizationError("duplicate_source_condition_id")
        seen_pairs.add(pair); seen_conditions.add(rule["source_condition_id"])


def _temporal_reconciliation(value: Any) -> None:
    _keys(value, {"status", "review_submission_hash", "checked_at"})
    if value["status"] != "succeeded":
        raise AuthorizationError("temporal_reconciliation_not_succeeded")
    _hash(value["review_submission_hash"], "review_submission_hash")
    parse_rfc3339_timestamp(value["checked_at"])


def _instruction_ids(value: Any) -> None:
    values = _array(value, "instruction_ids")
    for item in values:
        _id(item, "instruction_id")


def _exclusions(value: Any) -> list[Any]:
    entries = _array(value, "exclusions")
    _unique_ids(entries, "exclusion_id", "exclusion")
    for entry in entries:
        _keys(entry, {"exclusion_id", "predicate_id", "instruction_ids", "reason"})
        _id(entry["predicate_id"], "predicate_id"); _instruction_ids(entry["instruction_ids"])
        if not isinstance(entry["reason"], str):
            raise AuthorizationError("invalid_exclusion_reason")
    return entries


def _exceptions(value: Any) -> list[Any]:
    entries = _array(value, "exceptions_applied")
    _unique_ids(entries, "exception_id", "exception")
    for entry in entries:
        _keys(entry, {"exception_id", "instruction_ids", "reason"}, {"predicate_id", "record_ids"})
        has_predicate = "predicate_id" in entry
        has_records = "record_ids" in entry
        if has_predicate == has_records:
            raise AuthorizationError("exception_selector_exclusive")
        if has_predicate: _id(entry["predicate_id"], "predicate_id")
        else:
            records = _array(entry["record_ids"], "record_ids")
            if not records:
                raise AuthorizationError("invalid_exception_record_ids")
            for record in records:
                _id(record, "record_id")
        _instruction_ids(entry["instruction_ids"])
        if not isinstance(entry["reason"], str):
            raise AuthorizationError("invalid_exception_reason")
    return entries


def validate_sidecar(sidecar: Any, *, case_id: str, profile: str, temporal: bool = False, case: dict[str, Any] | None = None, retained_artifacts: dict[str, bytes] | None = None) -> AuthorizationResult:
    try:
        _keys(sidecar, _COMMON, _RESOLVED | {"governing_event", "temporal_rules", "temporal_reconciliation"})
        if sidecar["case_id"] != case_id or sidecar["profile"] != profile:
            raise AuthorizationError("case_identity_mismatch")
        _verify_hash(sidecar["source_case_hash"], "source_case_hash", retained_artifacts)
        status = sidecar["resolution_status"]
        if status not in {"resolved", "ambiguous", "quarantined"}:
            raise AuthorizationError("unsupported_resolution_status")
        _issues(sidecar["resolution_issues"])
        if status != "resolved" and not sidecar["resolution_issues"]:
            raise AuthorizationError("unresolved_status_requires_issue")
        if not isinstance(sidecar["resolution_note"], str):
            raise AuthorizationError("invalid_resolution_note")
        if not isinstance(sidecar["resolved_by"], list) or not sidecar["resolved_by"]:
            raise AuthorizationError("resolved_by_required")
        for provenance in sidecar["resolved_by"]:
            _keys(provenance, {"reviewer_id", "role", "reviewed_at", "independence_declaration", "review_submission_hash"})
            _id(provenance["reviewer_id"], "reviewer_id")
            if provenance["role"] not in {"human_reviewer", "adjudicator"} or type(provenance["independence_declaration"]) is not bool:
                raise AuthorizationError("invalid_provenance")
            parse_rfc3339_timestamp(provenance["reviewed_at"]); _verify_hash(provenance["review_submission_hash"], "review_submission_hash", retained_artifacts)
        if status != "resolved":
            forbidden = _RESOLVED - {"evidence_registry"} | {"governing_event", "temporal_rules", "temporal_reconciliation"}
            if any(name in sidecar for name in forbidden):
                raise AuthorizationError("resolved_members_forbidden")
            evidence = sidecar.get("evidence_registry")
            issue_ids = {evidence_id for issue in sidecar["resolution_issues"] for evidence_id in issue["evidence_ids"]}
            if issue_ids:
                if evidence is None:
                    raise AuthorizationError("issue_evidence_registry_required")
                evidence = _array(evidence, "evidence_registry")
                _unique_ids(evidence, "evidence_id", "evidence_definition")
                if {entry["evidence_id"] for entry in evidence} != issue_ids:
                    raise AuthorizationError("issue_evidence_registry_mismatch")
                for entry in evidence:
                    _keys(entry, {"evidence_id", "content_hash", "description"})
                    _id(entry["evidence_id"], "evidence_id")
                    if not isinstance(entry["description"], str):
                        raise AuthorizationError("invalid_evidence_description")
                    _verify_hash(entry["content_hash"], "content_hash", retained_artifacts)
            elif evidence not in (None, []):
                raise AuthorizationError("unresolved_evidence_registry_forbidden")
            return AuthorizationResult(True, status, ())
        if case is None:
            raise AuthorizationError("case_bundle_required_for_resolved_sidecar")
        if not validate_case(case).valid or case.get("case_id") != case_id or case.get("profile") != profile:
            raise AuthorizationError("invalid_or_mismatched_case_bundle")
        # The trusted case bundle determines whether temporal reconciliation is
        # mandatory. The optional flag remains a compatibility hint for callers,
        # but cannot disable a temporal gate present in the case itself.
        temporal = temporal or bool(case["payload"].get("temporal_conditions"))
        required = _RESOLVED
        if not required <= set(sidecar):
            raise AuthorizationError("resolved_members_required")
        if not isinstance(sidecar["governing_instruction_ids"], list) or not sidecar["governing_instruction_ids"]:
            raise AuthorizationError("governing_instruction_ids_required")
        for value in sidecar["governing_instruction_ids"]: _id(value, "instruction_id")
        predicates = _array(sidecar["predicate_definitions"], "predicate_definitions")
        _unique_ids(predicates, "predicate_id", "predicate_definition")
        payload = case["payload"]
        declarations = {(item["table"], item["field"]): item for item in payload["field_declarations"]}
        metadata_declarations = {item["field"]: item for item in payload.get("metadata_declarations", [])}
        for entry in predicates:
            _keys(entry, {"predicate_id", "expression"}); _id(entry["predicate_id"], "predicate_id")
            validate_definition(entry, declarations, metadata_declarations)
            selected = evaluate_predicate(entry["expression"], PredicateContext(payload["ledger"], payload.get("record_metadata", {})))
            known_records = {row["record_id"] for rows in payload["ledger"].values() for row in rows}
            if not selected <= known_records:
                raise AuthorizationError("predicate_selected_unknown_record")
        predicate_ids = {entry["predicate_id"] for entry in predicates}
        instruction_ids = {"original", case["payload"]["notice"]["notice_id"], *(update["update_id"] for update in case["payload"]["updates"])}
        evidence = _array(sidecar["evidence_registry"], "evidence_registry")
        _unique_ids(evidence, "evidence_id", "evidence_definition")
        for entry in evidence:
            _keys(entry, {"evidence_id", "content_hash", "description"}); _id(entry["evidence_id"], "evidence_id")
            if not isinstance(entry["description"], str): raise AuthorizationError("invalid_evidence_description")
            _verify_hash(entry["content_hash"], "content_hash", retained_artifacts)
        exclusions = _exclusions(sidecar["exclusions"])
        exceptions = _exceptions(sidecar["exceptions_applied"])
        evidence_ids = {entry["evidence_id"] for entry in evidence}
        exclusion_ids = {entry["exclusion_id"] for entry in exclusions}
        exception_ids = {entry["exception_id"] for entry in exceptions}
        for instruction_id in sidecar["governing_instruction_ids"]:
            if instruction_id not in instruction_ids: raise AuthorizationError("unknown_governing_instruction_id")
        for entry in exclusions + exceptions:
            if not set(entry["instruction_ids"]) <= instruction_ids: raise AuthorizationError("unknown_instruction_reference")
            if entry.get("predicate_id") is not None and entry["predicate_id"] not in predicate_ids: raise AuthorizationError("unknown_predicate_reference")
        notice = payload["notice"]
        if "predicate_id" in notice.get("scope", {}) and notice["scope"]["predicate_id"] not in predicate_ids: raise AuthorizationError("unknown_predicate_reference")
        for update in payload["updates"]:
            if "applies_to" in update and update["applies_to"]["predicate_id"] not in predicate_ids: raise AuthorizationError("unknown_predicate_reference")
        for condition in payload.get("temporal_conditions", []):
            if condition["predicate_id"] not in predicate_ids: raise AuthorizationError("unknown_predicate_reference")
        if not set(notice.get("exclusion_ids", [])) <= exclusion_ids or not set(notice.get("exception_ids", [])) <= exception_ids or not set(notice.get("evidence_ids", [])) <= evidence_ids:
            raise AuthorizationError("unresolved_notice_reference")
        referenced_evidence = {evidence_id for entry in exclusions + exceptions for evidence_id in entry.get("evidence_ids", [])}
        if not referenced_evidence <= evidence_ids:
            raise AuthorizationError("unresolved_evidence_id")
        eligible = sidecar["eligible_keys"]
        final = sidecar["required_final_values"]
        rationale = sidecar["eligibility_rationale"]
        if not isinstance(eligible, list) or any(x is None for x in eligible) or not all(isinstance(x, list) and len(x) == 3 and all(isinstance(part, str) for part in x) for x in eligible):
            raise AuthorizationError("invalid_eligible_keys")
        final = _array(final, "required_final_values")
        rationale = _array(rationale, "eligibility_rationale")
        if notice.get("operation") == "no_op" and (eligible or final or rationale):
            raise AuthorizationError("no_op_authorization_must_be_empty")
        final_keys = [x.get("key") for x in final if isinstance(x, dict)]
        if len(final) != len(eligible) or set(map(tuple, final_keys)) != set(map(tuple, eligible)):
            raise AuthorizationError("required_final_values_coverage")
        rationale_keys = []
        for item in rationale:
            if not isinstance(item, dict) or set(item) != {"key", "included_by", "excluded_by", "instruction_ids"}:
                raise AuthorizationError("invalid_eligibility_rationale")
            key = item["key"]
            if not isinstance(key, list) or len(key) != 3 or not all(isinstance(part, str) for part in key):
                raise AuthorizationError("invalid_eligibility_rationale_key")
            for member in ("included_by", "excluded_by", "instruction_ids"):
                values = _array(item[member], "eligibility_rationale_" + member)
                for reference in values: _id(reference, member)
            rationale_keys.append(tuple(key))
        if len(rationale) != len(eligible) or set(rationale_keys) != set(map(tuple, eligible)) or len(set(rationale_keys)) != len(rationale_keys):
            raise AuthorizationError("eligibility_rationale_coverage")
        exclusion_ids = {entry["exclusion_id"] for entry in _exclusions(sidecar["exclusions"])}
        for item in rationale:
            if not set(item["included_by"]) <= predicate_ids or not set(item["excluded_by"]) <= exclusion_ids or not set(item["instruction_ids"]) <= instruction_ids:
                raise AuthorizationError("unresolved_eligibility_rationale_reference")
        preservation = _array(sidecar["preservation_keys"], "preservation_keys")
        if any(not isinstance(x, list) or len(x) != 3 or not all(isinstance(part, str) for part in x) for x in preservation):
            raise AuthorizationError("invalid_preservation_keys")
        if len({tuple(x) for x in preservation}) != len(preservation):
            raise AuthorizationError("duplicate_preservation_key")
        per_key_rationale = _array(sidecar["rationale_by_key"], "rationale_by_key")
        rationale_by_key = []
        for item in per_key_rationale:
            if not isinstance(item, dict) or set(item) != {"key", "instruction_ids", "reason"}:
                raise AuthorizationError("invalid_rationale_by_key")
            if not isinstance(item["key"], list) or len(item["key"]) != 3 or not all(isinstance(part, str) for part in item["key"]):
                raise AuthorizationError("invalid_rationale_key")
            _instruction_ids(item["instruction_ids"])
            if not item["instruction_ids"] or not set(item["instruction_ids"]) <= instruction_ids or not isinstance(item["reason"], str):
                raise AuthorizationError("invalid_rationale_by_key")
            rationale_by_key.append(tuple(item["key"]))
        if len(rationale_by_key) != len(eligible) or set(rationale_by_key) != set(map(tuple, eligible)) or len(set(rationale_by_key)) != len(rationale_by_key):
            raise AuthorizationError("rationale_by_key_coverage")
        validate_resolved_coverage(sidecar, payload["ledger"], declarations, profile)
        if temporal:
            if sidecar.get("spec_version") != "acac-auth-1.1": raise AuthorizationError("temporal_spec_version_required")
            if "temporal_rules" not in sidecar or "temporal_reconciliation" not in sidecar: raise AuthorizationError("temporal_members_required")
            _temporal_rules(sidecar["temporal_rules"])
            _temporal_reconciliation(sidecar["temporal_reconciliation"])
            _verify_hash(sidecar["temporal_reconciliation"]["review_submission_hash"], "reconciliation_review_submission_hash", retained_artifacts)
            if case is None:
                raise AuthorizationError("case_bundle_required_for_temporal_reconciliation")
            reconcile_temporal(case, sidecar)
        elif sidecar.get("spec_version") != "acac-auth-1.0":
            raise AuthorizationError("non_temporal_spec_version_required")
        elif any(name in sidecar for name in {"governing_event", "temporal_rules", "temporal_reconciliation"}):
            raise AuthorizationError("temporal_members_forbidden")
        return AuthorizationResult(True, status, ())
    except Exception as exc:
        return AuthorizationResult(False, sidecar.get("resolution_status") if isinstance(sidecar, dict) else None, (str(exc),))


def validate_resolved_coverage(sidecar: Any, ledger: dict[str, list[dict[str, Any]]], declarations: dict[tuple[str, str], dict[str, Any]], profile: str) -> None:
    """Validate resolved cell coverage against the initial ledger.

    This validates structural eligibility and preservation invariants only; it
    does not decide whether a human authorization rationale is substantively
    correct.
    """
    if not isinstance(sidecar, dict) or sidecar.get("resolution_status") != "resolved":
        raise AuthorizationError("resolved_sidecar_required")
    eligible = [tuple(key) for key in sidecar.get("eligible_keys", [])]
    final_entries = sidecar.get("required_final_values", [])
    preservation = {tuple(key) for key in sidecar.get("preservation_keys", [])}
    if len(set(eligible)) != len(eligible):
        raise AuthorizationError("duplicate_eligible_key")
    initial = {}
    for table, rows in ledger.items():
        for row in rows:
            for field, value in row.get("values", {}).items():
                initial[(table, row.get("record_id"), field)] = value
    for key in eligible:
        if len(key) != 3 or key not in initial:
            raise AuthorizationError("eligible_key_not_in_ledger")
        declaration = declarations.get((key[0], key[2]))
        if declaration is None or (profile == "historical-ledger-1.0" and key[0] != "W") or declaration.get("mutable") is not True:
            raise AuthorizationError("eligible_key_not_mutable")
    final_by_key = {}
    for entry in final_entries:
        if not isinstance(entry, dict) or set(entry) != {"key", "value"}:
            raise AuthorizationError("invalid_required_final_value")
        key = tuple(entry["key"])
        if key in final_by_key:
            raise AuthorizationError("duplicate_required_final_value")
        declaration = declarations.get((key[0], key[2])) if len(key) == 3 else None
        if declaration is None or not matches_type(entry["value"], declaration.get("type")):
            raise AuthorizationError("required_final_value_type_mismatch")
        final_by_key[key] = entry["value"]
    if set(final_by_key) != set(eligible):
        raise AuthorizationError("required_final_values_coverage")
    expected_preservation = {key for key, value in initial.items() if key not in final_by_key or final_by_key[key] == value}
    if preservation != expected_preservation:
        raise AuthorizationError("preservation_keys_mismatch")
