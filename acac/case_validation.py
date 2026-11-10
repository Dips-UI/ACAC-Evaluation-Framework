"""Structural validation for ACAC v1.3 case bundles.

This module deliberately does not interpret prose, evaluate predicates, or
resolve trusted authorization sidecars.
"""

from dataclasses import dataclass
from typing import Any

from .strict_json import JSONContractError, is_integer, matches_type, parse_rfc3339_timestamp

_PROFILES = {"single-ledger-1.0": ("L",), "historical-ledger-1.0": ("M", "H", "W")}
_KINDS = {"clarification", "amendment", "temporary", "rollback", "administrative"}
_OPERATIONS = {"prospective", "retrospective_backfill", "case_correction", "rollback", "no_op"}


class CaseValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ValidationResult:
    """Stable structural-validation result and later-phase handoff."""

    valid: bool
    normalized_case: dict[str, Any] | None
    profile: str | None
    notice: dict[str, Any] | None
    scope: dict[str, Any] | None
    temporal_validation_status: str
    no_op_handoff_status: str
    errors: tuple[str, ...]


def _keys(obj, required=(), optional=()):
    if not isinstance(obj, dict):
        raise CaseValidationError("object_required")
    if any(not isinstance(key, str) for key in obj):
        raise CaseValidationError("non_string_member_name")
    allowed = set(required) | set(optional)
    unknown = set(obj) - allowed
    missing = set(required) - set(obj)
    if unknown:
        raise CaseValidationError("unknown_members:" + ",".join(sorted(unknown)))
    if missing:
        raise CaseValidationError("missing_members:" + ",".join(sorted(missing)))


def _id(value, label="id"):
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise CaseValidationError(f"invalid_{label}")


def _type(value, declared, label):
    if not matches_type(value, declared):
        raise CaseValidationError(f"invalid_type:{label}")


def _timestamp(value, label):
    try:
        parse_rfc3339_timestamp(value)
    except JSONContractError as exc:
        raise CaseValidationError(f"invalid_timestamp:{label}") from exc


def _locator(locator, tables, fields, metadata):
    if not isinstance(locator, dict) or not isinstance(locator.get("source"), str):
        raise CaseValidationError("invalid_governing_event")
    source = locator["source"]
    if source == "table_field":
        _keys(locator, ("source", "table", "field"))
        if locator["table"] not in tables:
            raise CaseValidationError("unknown_governing_event_table")
        _id(locator["field"], "field")
        declaration = fields.get((locator["table"], locator["field"]))
        if declaration is None or declaration.get("type") != "string" or declaration.get("format") != "rfc3339-timestamp":
            raise CaseValidationError("governing_event_field_must_be_timestamp")
    elif source == "record_metadata":
        _keys(locator, ("source", "field"))
        declaration = metadata.get(locator["field"])
        if declaration is None or declaration.get("type") != "string" or declaration.get("format") != "rfc3339-timestamp":
            raise CaseValidationError("unknown_governing_event_metadata")
    else:
        raise CaseValidationError("invalid_governing_event_source")
    return tuple(sorted(locator.items()))


def _declarations(payload, profile):
    declarations = payload["field_declarations"]
    if not isinstance(declarations, list):
        raise CaseValidationError("field_declarations_must_be_array")
    fields = {}
    for declaration in declarations:
        _keys(declaration, ("table", "field", "type", "mutable"), ("description", "format"))
        table, field = declaration["table"], declaration["field"]
        if table not in _PROFILES[profile]:
            raise CaseValidationError("invalid_declaration_table")
        _id(field, "field")
        if declaration["type"] not in {"string", "integer", "boolean"} or type(declaration["mutable"]) is not bool:
            raise CaseValidationError("invalid_field_declaration")
        if "description" in declaration and type(declaration["description"]) is not str:
            raise CaseValidationError("invalid_description")
        if "format" in declaration and (declaration["type"] != "string" or declaration["format"] != "rfc3339-timestamp"):
            raise CaseValidationError("invalid_field_format")
        if profile == "historical-ledger-1.0" and table in {"M", "H"} and declaration["mutable"]:
            raise CaseValidationError("historical_field_must_be_immutable")
        key = (table, field)
        if key in fields:
            raise CaseValidationError("duplicate_field_declaration")
        fields[key] = declaration
    return fields


def _metadata(payload):
    declarations = payload.get("metadata_declarations", [])
    if not isinstance(declarations, list):
        raise CaseValidationError("metadata_declarations_must_be_array")
    result = {}
    for declaration in declarations:
        _keys(declaration, ("field", "type"), ("format",))
        _id(declaration["field"], "metadata_field")
        if declaration["type"] not in {"string", "integer", "boolean"}:
            raise CaseValidationError("invalid_metadata_type")
        if "format" in declaration and (declaration["type"] != "string" or declaration["format"] != "rfc3339-timestamp"):
            raise CaseValidationError("invalid_metadata_format")
        if declaration["field"] in result:
            raise CaseValidationError("duplicate_metadata_declaration")
        result[declaration["field"]] = declaration
    return result


def _ledger(payload, profile, fields, metadata):
    ledger = payload["ledger"]
    if not isinstance(ledger, dict) or set(ledger) != set(_PROFILES[profile]):
        raise CaseValidationError("invalid_ledger_tables")
    record_sets = {}
    for table in _PROFILES[profile]:
        rows = ledger[table]
        if not isinstance(rows, list):
            raise CaseValidationError("ledger_table_must_be_array")
        ids = []
        for row in rows:
            _keys(row, ("record_id", "values"))
            _id(row["record_id"], "record_id")
            if row["record_id"] in ids:
                raise CaseValidationError("duplicate_record_id")
            ids.append(row["record_id"])
            values = row["values"]
            if not isinstance(values, dict):
                raise CaseValidationError("values_must_be_object")
            declared = {field: declaration for (decl_table, field), declaration in fields.items() if decl_table == table}
            if set(values) != set(declared):
                raise CaseValidationError("ledger_fields_mismatch")
            for field, declaration in declared.items():
                _type(values[field], declaration["type"], f"{table}.{field}")
                if declaration.get("format") == "rfc3339-timestamp":
                    _timestamp(values[field], f"{table}.{field}")
        record_sets[table] = set(ids)
    if profile == "historical-ledger-1.0" and not (record_sets["M"] == record_sets["H"] == record_sets["W"]):
        raise CaseValidationError("historical_record_ids_mismatch")
    record_metadata = payload.get("record_metadata", {})
    if not isinstance(record_metadata, dict):
        raise CaseValidationError("record_metadata_must_be_object")
    if metadata:
        all_ids = set().union(*record_sets.values()) if record_sets else set()
        if set(record_metadata) != all_ids:
            raise CaseValidationError("record_metadata_coverage_mismatch")
        for record_id, values in record_metadata.items():
            if not isinstance(values, dict) or set(values) != set(metadata):
                raise CaseValidationError("record_metadata_fields_mismatch")
            for field, declaration in metadata.items():
                _type(values[field], declaration["type"], f"metadata.{field}")
                if declaration.get("format") == "rfc3339-timestamp":
                    _timestamp(values[field], f"metadata.{field}")
    elif record_metadata:
        raise CaseValidationError("record_metadata_without_declarations")


def _updates(payload):
    updates = payload["updates"]
    if not isinstance(updates, list):
        raise CaseValidationError("updates_must_be_array")
    ids, previous = set(), 0
    for update in updates:
        _keys(update, ("update_id", "sequence", "kind", "text"), ("announced_at", "effective_at", "effective_boundary", "applies_to", "supersedes"))
        _id(update["update_id"], "update_id")
        if update["update_id"] in ids:
            raise CaseValidationError("duplicate_update_id")
        ids.add(update["update_id"])
        if not is_integer(update["sequence"]) or int(update["sequence"]) <= previous:
            raise CaseValidationError("update_sequence_not_increasing")
        previous = int(update["sequence"])
        if update["kind"] not in _KINDS or type(update["text"]) is not str:
            raise CaseValidationError("invalid_update")
        if "announced_at" in update:
            _timestamp(update["announced_at"], "announced_at")
        if "effective_at" in update:
            _timestamp(update["effective_at"], "effective_at")
            if update.get("effective_boundary") not in {"inclusive", "exclusive"}:
                raise CaseValidationError("effective_boundary_required")
        elif "effective_boundary" in update:
            raise CaseValidationError("orphan_effective_boundary")
        if "applies_to" in update:
            if not isinstance(update["applies_to"], dict) or set(update["applies_to"]) != {"predicate_id"}:
                raise CaseValidationError("invalid_applies_to")
            _id(update["applies_to"]["predicate_id"], "predicate_id")
        if "supersedes" in update:
            if not isinstance(update["supersedes"], list):
                raise CaseValidationError("supersedes_must_be_array")
            for reference in update["supersedes"]:
                _id(reference, "superseded_update_id")
    references = [ref for update in updates for ref in update.get("supersedes", [])]
    if not set(references).issubset(ids):
        raise CaseValidationError("unknown_superseded_update_id")
    return updates, ids


def _notice(payload, profile, fields, metadata):
    notice = payload["notice"]
    _keys(notice, ("notice_id", "operation", "authority_text", "scope"), ("issued_at", "governing_event", "effective_at", "effective_boundary", "exclusion_ids", "exception_ids", "evidence_ids"))
    _id(notice["notice_id"], "notice_id")
    if notice["operation"] not in _OPERATIONS or type(notice["authority_text"]) is not str:
        raise CaseValidationError("invalid_notice")
    if "issued_at" in notice:
        _timestamp(notice["issued_at"], "issued_at")
    for name in ("exclusion_ids", "exception_ids", "evidence_ids"):
        if name in notice:
            if not isinstance(notice[name], list):
                raise CaseValidationError(f"{name}_must_be_array")
            for reference in notice[name]:
                _id(reference, name[:-4] + "_id")
    scope = notice["scope"]
    if not isinstance(scope, dict):
        raise CaseValidationError("invalid_scope")
    if notice["operation"] == "no_op":
        if set(scope) != {"fields"} or scope["fields"] != []:
            raise CaseValidationError("invalid_no_op_scope")
    else:
        if set(scope) - {"fields", "predicate_id"} or not isinstance(scope.get("fields"), list) or not scope["fields"]:
            raise CaseValidationError("invalid_scope")
        for field in scope["fields"]:
            _id(field, "field")
            table = "W" if profile == "historical-ledger-1.0" else "L"
            if (table, field) not in fields:
                raise CaseValidationError("unknown_notice_field")
        if "predicate_id" in scope:
            _id(scope["predicate_id"], "predicate_id")
    temporal = any(key in notice for key in ("governing_event", "effective_at", "effective_boundary"))
    if "effective_at" in notice:
        _timestamp(notice["effective_at"], "notice_effective_at")
        if notice.get("effective_boundary") not in {"inclusive", "exclusive"}:
            raise CaseValidationError("notice_effective_boundary_required")
        temporal = True
    elif "effective_boundary" in notice:
        raise CaseValidationError("orphan_notice_effective_boundary")
    if temporal:
        if "governing_event" not in notice:
            raise CaseValidationError("notice_governing_event_required")
        if "effective_at" not in notice or "effective_boundary" not in notice:
            raise CaseValidationError("notice_temporal_fields_required")
        locator = _locator(notice["governing_event"], _PROFILES[profile], fields, metadata)
    else:
        locator = None
    return notice, scope, locator


def _temporal_conditions(payload, profile, fields, metadata, notice, updates, update_ids):
    if "temporal_conditions" in payload and payload["temporal_conditions"] is None:
        raise CaseValidationError("temporal_conditions_null_forbidden")
    conditions = payload.get("temporal_conditions")
    temporal_declared = any(key in notice for key in ("governing_event", "effective_at", "effective_boundary"))
    temporal_declared |= any(any(key in update for key in ("effective_at", "effective_boundary")) for update in updates)
    temporal_declared |= conditions is not None
    if conditions is None:
        if temporal_declared:
            raise CaseValidationError("temporal_conditions_required")
        return "absent", None
    if not isinstance(conditions, list) or not conditions:
        raise CaseValidationError("temporal_conditions_must_be_nonempty_array")
    if not temporal_declared:
        raise CaseValidationError("temporal_conditions_forbidden")
    locators, ids = set(), set()
    for condition in conditions:
        _keys(condition, ("condition_id", "instruction_id", "predicate_id", "governing_event", "effective_at", "effective_boundary"))
        _id(condition["condition_id"], "condition_id")
        _id(condition["instruction_id"], "instruction_id")
        _id(condition["predicate_id"], "predicate_id")
        if condition["condition_id"] in ids:
            raise CaseValidationError("duplicate_condition_id")
        ids.add(condition["condition_id"])
        _timestamp(condition["effective_at"], "condition_effective_at")
        if condition["effective_boundary"] not in {"inclusive", "exclusive"}:
            raise CaseValidationError("invalid_condition_boundary")
        if condition["instruction_id"] not in {"original", notice["notice_id"], *update_ids}:
            raise CaseValidationError("unknown_temporal_instruction_id")
        locator = _locator(condition["governing_event"], _PROFILES[profile], fields, metadata)
        locators.add(locator)
    if len(locators) != 1:
        raise CaseValidationError("multiple_governing_events")
    by_instruction = {}
    for condition in conditions:
        by_instruction.setdefault(condition["instruction_id"], []).append(condition)
    notice_temporal = any(key in notice for key in ("governing_event", "effective_at", "effective_boundary"))
    notice_conditions = by_instruction.get(notice["notice_id"], [])
    if notice_temporal:
        if not notice_conditions:
            raise CaseValidationError("missing_notice_temporal_condition")
        if len(notice_conditions) != 1:
            raise CaseValidationError("duplicate_temporal_instruction_mapping")
        condition = notice_conditions[0]
        if condition["effective_at"] != notice["effective_at"] or condition["effective_boundary"] != notice["effective_boundary"]:
            raise CaseValidationError("notice_temporal_condition_mismatch")
        if tuple(sorted(condition["governing_event"].items())) != tuple(sorted(notice["governing_event"].items())):
            raise CaseValidationError("notice_governing_event_mismatch")
    elif notice_conditions:
        raise CaseValidationError("extra_notice_temporal_condition")
    for update in updates:
        mapped_conditions = by_instruction.get(update["update_id"], [])
        if "effective_at" in update:
            if not mapped_conditions:
                raise CaseValidationError("missing_update_temporal_condition")
            if len(mapped_conditions) != 1:
                raise CaseValidationError("duplicate_temporal_instruction_mapping")
            mapped = mapped_conditions[0]
            if mapped["effective_at"] != update["effective_at"] or mapped["effective_boundary"] != update["effective_boundary"]:
                raise CaseValidationError("update_temporal_condition_mismatch")
        elif mapped_conditions:
            raise CaseValidationError("extra_update_temporal_condition")
    allowed = {"original", notice["notice_id"], *update_ids}
    if any(key not in allowed for key in by_instruction):
        raise CaseValidationError("extra_temporal_condition")
    return "validated", conditions


def validate_case(case: dict[str, Any]) -> ValidationResult:
    errors = []
    try:
        _keys(case, ("schema_version", "profile", "case_id", "task", "payload"))
        if case["schema_version"] != "acac-1.3" or case["task"] != "correct_ledger":
            raise CaseValidationError("invalid_case_version_or_task")
        if case["profile"] not in _PROFILES:
            raise CaseValidationError("invalid_profile")
        _id(case["case_id"], "case_id")
        payload = case["payload"]
        _keys(payload, ("field_declarations", "ledger", "original_guideline", "updates", "notice"), ("metadata_declarations", "record_metadata", "temporal_conditions"))
        if type(payload["original_guideline"]) is not str:
            raise CaseValidationError("original_guideline_must_be_string")
        fields = _declarations(payload, case["profile"])
        metadata = _metadata(payload)
        _ledger(payload, case["profile"], fields, metadata)
        updates, update_ids = _updates(payload)
        notice, scope, notice_locator = _notice(payload, case["profile"], fields, metadata)
        temporal_status, conditions = _temporal_conditions(payload, case["profile"], fields, metadata, notice, updates, update_ids)
        if conditions and notice_locator is not None:
            expected = tuple(sorted(notice["governing_event"].items()))
            if tuple(sorted(conditions[0]["governing_event"].items())) != expected:
                raise CaseValidationError("governing_event_mismatch")
        normalized = {"schema_version": case["schema_version"], "profile": case["profile"], "case_id": case["case_id"], "task": case["task"], "payload": payload}
        return ValidationResult(True, normalized, case["profile"], notice, scope, temporal_status, "empty" if notice["operation"] == "no_op" else "not_applicable", ())
    except (CaseValidationError, KeyError, TypeError, AttributeError, ValueError) as exc:
        errors.append(str(exc))
        return ValidationResult(False, None, case.get("profile") if isinstance(case, dict) else None, None, None, "invalid", "invalid", tuple(errors))


def validate_case_bytes(raw: bytes) -> ValidationResult:
    from .strict_json import loads_bytes
    try:
        return validate_case(loads_bytes(raw))
    except JSONContractError as exc:
        return ValidationResult(False, None, None, None, None, "invalid", "invalid", (str(exc),))
