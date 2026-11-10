"""Structural validation for immutable ACAC v1.4 authorization inputs.

This artifact is finalized before human review. It is deliberately separate
from the v1.3.8 final-sidecar validator: it carries no review, reference,
sidecar, or approval hashes and cannot by itself authorize grading.
"""

from dataclasses import dataclass
import hashlib
from typing import Any

from .case_validation import validate_case
from .predicates import PredicateContext, PredicateError, evaluate, validate_definition
from .strict_json import equal, is_integer, loads_bytes, matches_type, parse_rfc3339_timestamp
from .temporal import TemporalError, applies as temporal_applies


class AuthorizationInputError(ValueError):
    pass


@dataclass(frozen=True)
class AuthorizationInputResult:
    valid: bool
    status: str | None
    input_hash: str | None
    errors: tuple[str, ...]
    exception_decision_candidates: tuple[tuple[str, str, tuple[str, str, str]], ...] = ()


_COMMON = {
    "schema_version", "case_id", "source_case_hash", "profile",
}
_RESOLUTION = {
    "governing_instruction_ids", "predicate_definitions", "evidence_registry",
    "eligible_keys", "eligibility_rationale", "exclusions",
    "exceptions_applied", "required_final_values", "preservation_keys",
    "rationale_by_key",
}
_TEMPORAL = {"governing_event", "temporal_rules"}


def _object(value: Any, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict):
        raise AuthorizationInputError("object_required")
    if any(not isinstance(key, str) for key in value):
        raise AuthorizationInputError("string_keys_required")
    keys = set(value)
    if keys - required - optional or required - keys:
        raise AuthorizationInputError("invalid_members")
    return value


def _array(value: Any, label: str) -> list:
    if not isinstance(value, list):
        raise AuthorizationInputError(f"{label}_array_required")
    if any(item is None for item in value):
        raise AuthorizationInputError(f"{label}_null_forbidden")
    return value


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise AuthorizationInputError(f"invalid_{label}")
    return value


def _nonempty_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorizationInputError(f"invalid_{label}")
    return value


def _hash(value: Any, label: str, retained: dict[str, bytes]) -> bytes:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise AuthorizationInputError(f"invalid_{label}")
    raw = retained.get(value)
    if not isinstance(raw, bytes) or "sha256:" + hashlib.sha256(raw).hexdigest() != value:
        raise AuthorizationInputError(f"{label}_hash_mismatch")
    return raw


def _contains_null(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, dict):
        return any(_contains_null(key) or _contains_null(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_null(item) for item in value)
    return False


def _same_json_value(left: Any, right: Any) -> bool:
    """Compare parsed and supplied JSON values without bool/int aliasing."""
    if isinstance(left, dict) or isinstance(right, dict):
        return (
            isinstance(left, dict) and isinstance(right, dict)
            and set(left) == set(right)
            and all(_same_json_value(left[key], right[key]) for key in left)
        )
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list) and isinstance(right, list)
            and len(left) == len(right)
            and all(_same_json_value(a, b) for a, b in zip(left, right))
        )
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left is right
    if isinstance(left, str) or isinstance(right, str):
        return type(left) is str and type(right) is str and left == right
    if is_integer(left) or is_integer(right):
        return is_integer(left) and is_integer(right) and int(left) == int(right)
    if hasattr(left, "is_finite") or hasattr(right, "is_finite"):
        return type(left) is type(right) and left == right
    return type(left) is type(right) and left == right


def _address(value: Any, label: str) -> tuple[str, str, str]:
    if not isinstance(value, list) or len(value) != 3:
        raise AuthorizationInputError(f"invalid_{label}")
    return tuple(_id(part, label) for part in value)


def _unique_entries(entries: list, member: str, label: str) -> set[str]:
    result: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or member not in entry:
            raise AuthorizationInputError(f"invalid_{label}")
        identifier = _id(entry[member], member)
        if identifier in result:
            raise AuthorizationInputError(f"duplicate_{label}")
        result.add(identifier)
    return result


def _verify_registry(entries: Any, *, retained: dict[str, bytes], label: str = "evidence_registry") -> set[str]:
    values = _array(entries, label)
    identifiers = _unique_entries(values, "evidence_id", "evidence_definition")
    for entry in values:
        _object(entry, {"evidence_id", "content_hash", "description"})
        if not isinstance(entry["description"], str):
            raise AuthorizationInputError("invalid_evidence_description")
        _hash(entry["content_hash"], "content_hash", retained)
    return identifiers


def _validate_issues(value: Any) -> set[str]:
    issues = _array(value, "resolution_issues")
    ids: set[str] = set()
    for issue in issues:
        _object(issue, {"issue_id", "category", "source_location", "description", "evidence_ids"})
        issue_id = _id(issue["issue_id"], "issue_id")
        if issue_id in ids:
            raise AuthorizationInputError("duplicate_issue_id")
        ids.add(issue_id)
        for member in ("category", "source_location", "description"):
            _nonempty_text(issue[member], member)
        evidence = _array(issue["evidence_ids"], "issue_evidence_ids")
        for evidence_id in evidence:
            _id(evidence_id, "evidence_id")
    return ids


def _temporal_mapping(case: dict, resolution: dict, predicate_ids: set[str], instructions: set[str], declarations: dict, metadata: dict) -> None:
    conditions = case["payload"].get("temporal_conditions", [])
    governing_event = resolution["governing_event"]
    rules = _array(resolution["temporal_rules"], "temporal_rules")
    if len(rules) != len(conditions):
        raise AuthorizationInputError("temporal_rule_count_mismatch")
    if not isinstance(governing_event, dict):
        raise AuthorizationInputError("invalid_governing_event")
    if governing_event.get("source") not in {"table_field", "record_metadata"}:
        raise AuthorizationInputError("invalid_governing_event")
    if governing_event["source"] == "table_field":
        _object(governing_event, {"source", "table", "field"})
        declaration = declarations.get((governing_event["table"], governing_event["field"]))
    else:
        _object(governing_event, {"source", "field"})
        declaration = metadata.get(governing_event["field"])
    if declaration is None or declaration.get("type") != "string" or declaration.get("format") != "rfc3339-timestamp":
        raise AuthorizationInputError("governing_event_must_resolve_to_timestamp")
    condition_by_id: dict[str, dict] = {}
    for condition in conditions:
        condition_by_id[condition["condition_id"]] = condition
        if condition.get("governing_event") != governing_event:
            raise AuthorizationInputError("governing_event_mismatch")
    seen_rules: set[str] = set()
    seen_conditions: set[str] = set()
    seen_locations: set[tuple[str, int]] = set()
    for rule in rules:
        _object(rule, {
            "rule_id", "source_condition_id", "source_location", "occurrence_index",
            "instruction_id", "predicate_id", "effective_at", "effective_boundary",
        })
        for name in ("rule_id", "source_condition_id", "instruction_id", "predicate_id"):
            _id(rule[name], name)
        if rule["rule_id"] in seen_rules or rule["source_condition_id"] in seen_conditions:
            raise AuthorizationInputError("duplicate_temporal_rule_identity")
        if not isinstance(rule["source_location"], str) or not rule["source_location"].startswith("/payload/temporal_conditions/"):
            raise AuthorizationInputError("invalid_source_location")
        suffix = rule["source_location"][len("/payload/temporal_conditions/"):]
        if not suffix.isascii() or not suffix.isdigit() or (len(suffix) > 1 and suffix.startswith("0")):
            raise AuthorizationInputError("invalid_source_location")
        condition_index = int(suffix)
        if condition_index >= len(conditions) or conditions[condition_index].get("condition_id") != rule["source_condition_id"]:
            raise AuthorizationInputError("temporal_source_condition_mismatch")
        if not is_integer(rule["occurrence_index"]) or int(rule["occurrence_index"]) != 0:
            raise AuthorizationInputError("invalid_occurrence_index")
        identity = (rule["source_location"], rule["occurrence_index"])
        if identity in seen_locations:
            raise AuthorizationInputError("duplicate_source_condition_identity")
        condition = condition_by_id.get(rule["source_condition_id"])
        if condition is None:
            raise AuthorizationInputError("unknown_source_condition")
        if rule["instruction_id"] not in instructions or rule["instruction_id"] != condition["instruction_id"]:
            raise AuthorizationInputError("temporal_instruction_mismatch")
        if rule["predicate_id"] not in predicate_ids or rule["predicate_id"] != condition["predicate_id"]:
            raise AuthorizationInputError("temporal_predicate_mismatch")
        if rule["effective_at"] != condition["effective_at"] or rule["effective_boundary"] != condition["effective_boundary"]:
            raise AuthorizationInputError("temporal_threshold_mismatch")
        parse_rfc3339_timestamp(rule["effective_at"])
        if rule["effective_boundary"] not in {"inclusive", "exclusive"}:
            raise AuthorizationInputError("invalid_effective_boundary")
        seen_rules.add(rule["rule_id"])
        seen_conditions.add(rule["source_condition_id"])
        seen_locations.add(identity)


def _reconcile_predicate_eligibility(
    case: dict,
    resolution: dict,
    instructions: set[str],
    predicate_definitions: dict[str, dict],
    eligible: list[tuple[str, str, str]],
    eligibility_rationale: list[dict],
    exclusions: list[dict],
    exceptions: list[dict],
) -> tuple[tuple[str, str, tuple[str, str, str]], ...]:
    """Reconcile declared eligible cells with explicit structured scope.

    This deliberately refuses to compose differing predicate results across
    instruction sources. The artifact has no composition operator for those
    relationships, so choosing union/intersection here would invent policy.
    """
    payload = case["payload"]
    notice = payload["notice"]
    fields = notice["scope"]["fields"]
    if notice["operation"] == "no_op":
        # No-op shape and the empty key/final-value/rationale sets are checked
        # by the ordinary validator. In particular, preservation may overlap
        # an empty eligible set without any special authorization shortcut.
        if eligible:
            raise AuthorizationInputError("no_op_authorization_must_be_empty")
        if exceptions:
            raise AuthorizationInputError("exception_applicability_unresolved")
        return ()

    profile = case["profile"]
    target_table = "L" if profile == "single-ledger-1.0" else "W"
    if not fields:
        raise AuthorizationInputError("eligibility_target_scope_unresolved")
    if notice["notice_id"] not in instructions:
        raise AuthorizationInputError("eligibility_notice_instruction_not_governing")

    context = PredicateContext(
        payload["ledger"], payload.get("record_metadata", {})
    )
    conditions = payload.get("temporal_conditions", [])
    groups: dict[str, list[tuple[str, set[str], set[str], bool]]] = {}

    def add_scope(instruction_id: str, predicate_id: str, *, condition: dict | None = None) -> None:
        try:
            selected = evaluate(predicate_definitions[predicate_id]["expression"], context)
        except (KeyError, TypeError, PredicateError) as exc:
            raise AuthorizationInputError("eligibility_predicate_evaluation_failed") from exc
        raw_selected = set(selected)
        if condition is not None:
            locator = condition["governing_event"]
            if locator["source"] == "table_field":
                event_values = {
                    row["record_id"]: row["values"][locator["field"]]
                    for row in payload["ledger"][locator["table"]]
                }
            else:
                event_values = {
                    record_id: values[locator["field"]]
                    for record_id, values in payload.get("record_metadata", {}).items()
                }
            if selected - set(event_values):
                raise AuthorizationInputError("eligibility_predicate_unknown_record")
            try:
                selected = {
                    record_id for record_id in selected
                    if record_id in event_values and temporal_applies(
                        event_values[record_id], condition["effective_at"],
                        condition["effective_boundary"],
                    )
                }
            except (KeyError, TypeError, TemporalError, ValueError) as exc:
                raise AuthorizationInputError("eligibility_temporal_scope_unresolved") from exc
        groups.setdefault(instruction_id, []).append((
            predicate_id, raw_selected, set(selected), condition is not None
        ))

    scope = notice["scope"]
    governing_instruction_ids = set(resolution["governing_instruction_ids"])
    if "predicate_id" in scope:
        add_scope(notice["notice_id"], scope["predicate_id"])
    for update in payload["updates"]:
        update_id = update["update_id"]
        if update_id not in governing_instruction_ids:
            continue
        if "applies_to" in update:
            add_scope(update_id, update["applies_to"]["predicate_id"])
        elif not any(item["instruction_id"] == update_id for item in conditions):
            raise AuthorizationInputError("eligibility_update_scope_unresolved")
    for condition in conditions:
        if condition["instruction_id"] in set(resolution["governing_instruction_ids"]):
            add_scope(condition["instruction_id"], condition["predicate_id"], condition=condition)

    # Original prose can govern the correction's meaning, but it is never
    # parsed here. A structured predicate/temporal association is required
    # before it can contribute record scope.
    if not groups:
        ledger_record_ids = {row["record_id"] for row in payload["ledger"][target_table]}
        if ledger_record_ids:
            raise AuthorizationInputError("eligibility_record_scope_unresolved")
        record_scope: set[str] = set()
    else:
        group_results: dict[str, set[str]] = {}
        group_predicates: dict[str, set[str]] = {}
        for instruction_id, entries in groups.items():
            # Predicates associated with one instruction must select the same
            # records unless their relationship is explicitly encoded inside
            # a single predicate tree. A temporal condition then applies its
            # own threshold to that explicitly associated record selection.
            raw_record_sets = [entry[1] for entry in entries]
            if any(result != raw_record_sets[0] for result in raw_record_sets[1:]):
                raise AuthorizationInputError("eligibility_predicate_composition_unresolved")
            temporal_sets = [entry[2] for entry in entries if entry[3]]
            if temporal_sets and any(result != temporal_sets[0] for result in temporal_sets[1:]):
                raise AuthorizationInputError("eligibility_temporal_composition_unresolved")
            group_results[instruction_id] = temporal_sets[0] if temporal_sets else raw_record_sets[0]
            group_predicates[instruction_id] = {entry[0] for entry in entries}
        result_sets = list(group_results.values())
        if any(result != result_sets[0] for result in result_sets[1:]):
            raise AuthorizationInputError("eligibility_instruction_scope_composition_unresolved")
        record_scope = result_sets[0]

    declared_fields = set(fields)
    cells_by_record = {
        row["record_id"]: row["values"]
        for row in payload["ledger"][target_table]
    }
    if record_scope - set(cells_by_record):
        raise AuthorizationInputError("eligibility_predicate_unknown_record")
    declarations = {
        item["field"]: item for item in payload["field_declarations"]
        if item["table"] == target_table
    }
    candidate_keys = {
        (target_table, record_id, field)
        for record_id in record_scope
        if record_id in cells_by_record
        for field in declared_fields
        if field in declarations and declarations[field]["mutable"] is True
        and field in cells_by_record[record_id]
    }
    rationale_by_key = {
        _address(item["key"], "eligibility_rationale_key"): item
        for item in eligibility_rationale
    }

    instructions_by_record: dict[str, set[str]] = {
        record_id: {notice["notice_id"]} for record_id in record_scope
    }
    predicates_by_record: dict[str, set[str]] = {record_id: set() for record_id in record_scope}
    for instruction_id, selected in group_results.items():
        for record_id in selected:
            if record_id in record_scope:
                instructions_by_record[record_id].add(instruction_id)
                predicates_by_record[record_id].update(group_predicates[instruction_id])

    exclusion_matches: dict[str, set[str]] = {}
    for exclusion in exclusions:
        try:
            exclusion_matches[exclusion["exclusion_id"]] = evaluate(
                predicate_definitions[exclusion["predicate_id"]]["expression"], context
            )
        except (KeyError, TypeError, PredicateError) as exc:
            raise AuthorizationInputError("exclusion_predicate_evaluation_failed") from exc

    applicable_exclusions: dict[tuple[str, str, str], set[str]] = {key: set() for key in candidate_keys}
    for key in candidate_keys:
        record_id = key[1]
        scoped_instructions = instructions_by_record.get(record_id, set())
        for exclusion in exclusions:
            if record_id not in exclusion_matches[exclusion["exclusion_id"]]:
                continue
            if scoped_instructions.intersection(exclusion["instruction_ids"]):
                applicable_exclusions[key].add(exclusion["exclusion_id"])
            else:
                raise AuthorizationInputError("exclusion_scope_unresolved")

    exception_matches: dict[str, set[str]] = {}
    for exception in exceptions:
        if "predicate_id" in exception:
            try:
                exception_matches[exception["exception_id"]] = evaluate(
                    predicate_definitions[exception["predicate_id"]]["expression"], context
                )
            except (KeyError, TypeError, PredicateError) as exc:
                raise AuthorizationInputError("exception_predicate_evaluation_failed") from exc
        else:
            exception_matches[exception["exception_id"]] = set(exception["record_ids"])

    exception_uses: dict[str, set[tuple[str, str, str]]] = {item["exception_id"]: set() for item in exceptions}
    exception_override_tuples: set[tuple[str, str, tuple[str, str, str]]] = set()
    expected_eligible: set[tuple[str, str, str]] = set()
    for key in candidate_keys:
        record_id = key[1]
        excluded_ids = applicable_exclusions[key]
        if not excluded_ids:
            expected_eligible.add(key)
            continue
        for exclusion_id in excluded_ids:
            exclusion = next(item for item in exclusions if item["exclusion_id"] == exclusion_id)
            for exception in exceptions:
                exception_id = exception["exception_id"]
                if record_id not in exception_matches[exception_id]:
                    continue
                exception_instruction_ids = set(exception["instruction_ids"])
                key_instruction_ids = (
                    instructions_by_record.get(record_id, set())
                    | set(rationale_by_key.get(key, {}).get("instruction_ids", []))
                )
                if not exception_instruction_ids.intersection(key_instruction_ids):
                    continue
                if exception_id not in notice.get("exception_ids", []):
                    raise AuthorizationInputError("exception_not_referenced_by_notice")
                matching_exclusion_ids = {
                    candidate_exclusion["exclusion_id"]
                    for candidate_exclusion in exclusions
                    if candidate_exclusion["exclusion_id"] in excluded_ids
                    and exception_instruction_ids.intersection(candidate_exclusion["instruction_ids"])
                    and exception_instruction_ids.intersection(key_instruction_ids)
                }
                if matching_exclusion_ids != {exclusion_id}:
                    raise AuthorizationInputError("exception_exclusion_association_unresolved")
                authority_ids = (
                    exception_instruction_ids
                    & instructions
                    & set(exclusion["instruction_ids"])
                    & key_instruction_ids
                )
                if not authority_ids:
                    raise AuthorizationInputError("exception_authority_or_scope_unresolved")
                exception_uses[exception_id].add(key)
                exception_override_tuples.add((exception_id, exclusion_id, key))
        # A matching exclusion remains traceable when an explicit applicable
        # exception permits the key. Unoverridden exclusions remain decisive.
        if all(
            any(candidate_exclusion == exclusion_id and candidate_key == key
                for _, candidate_exclusion, candidate_key in exception_override_tuples)
            for exclusion_id in excluded_ids
        ):
            expected_eligible.add(key)

    unused_exceptions = [identifier for identifier, used in exception_uses.items() if not used]
    if unused_exceptions:
        raise AuthorizationInputError("exception_applicability_unresolved")
    if expected_eligible != set(eligible):
        if set(eligible) - expected_eligible:
            raise AuthorizationInputError("eligible_key_unsupported_by_scope")
        raise AuthorizationInputError("eligible_key_missing_from_scope")

    for key in expected_eligible:
        item = rationale_by_key[key]
        record_id = key[1]
        required_instruction_ids = instructions_by_record.get(record_id, {notice["notice_id"]})
        rationale_instructions = set(item["instruction_ids"])
        if not required_instruction_ids <= rationale_instructions or not rationale_instructions <= set(resolution["governing_instruction_ids"]):
            raise AuthorizationInputError("eligibility_instruction_association_mismatch")
        expected_predicates = predicates_by_record.get(record_id, set())
        if set(item["included_by"]) != expected_predicates:
            raise AuthorizationInputError("eligibility_predicate_association_mismatch")
        if set(item["excluded_by"]) != applicable_exclusions[key]:
            raise AuthorizationInputError("eligibility_exclusion_association_mismatch")
    return tuple(sorted(exception_override_tuples))


def _validate_resolution(value: Any, case: dict, retained: dict[str, bytes]) -> None:
    payload = case["payload"]
    declarations = {(item["table"], item["field"]): item for item in payload["field_declarations"]}
    metadata = {item["field"]: item for item in payload.get("metadata_declarations", [])}
    updates = payload["updates"]
    notice = payload["notice"]
    instructions = {"original", notice["notice_id"], *(update["update_id"] for update in updates)}
    conditions = payload.get("temporal_conditions", [])
    is_temporal = bool(conditions)
    required = _COMMON | _RESOLUTION | (_TEMPORAL if is_temporal else set())
    _object(value, required)

    governing = _array(value["governing_instruction_ids"], "governing_instruction_ids")
    if not governing:
        raise AuthorizationInputError("governing_instruction_ids_required")
    if len(governing) != len(set(governing)):
        raise AuthorizationInputError("duplicate_governing_instruction_id")
    for instruction in governing:
        if _id(instruction, "instruction_id") not in instructions:
            raise AuthorizationInputError("unknown_governing_instruction_id")

    predicates = _array(value["predicate_definitions"], "predicate_definitions")
    predicate_ids = _unique_entries(predicates, "predicate_id", "predicate_definition")
    for definition in predicates:
        try:
            validate_definition(definition, declarations, metadata)
        except PredicateError as exc:
            raise AuthorizationInputError(f"invalid_predicate_definition:{exc}") from exc

    evidence_ids = _verify_registry(value["evidence_registry"], retained=retained)
    exclusions = _array(value["exclusions"], "exclusions")
    exclusion_ids = _unique_entries(exclusions, "exclusion_id", "exclusion")
    for exclusion in exclusions:
        _object(exclusion, {"exclusion_id", "predicate_id", "instruction_ids", "reason"})
        if exclusion["predicate_id"] not in predicate_ids:
            raise AuthorizationInputError("unknown_exclusion_predicate")
        if not isinstance(exclusion["reason"], str):
            raise AuthorizationInputError("invalid_exclusion_reason")
        ids = _array(exclusion["instruction_ids"], "exclusion_instruction_ids")
        if any(_id(item, "instruction_id") not in instructions for item in ids):
            raise AuthorizationInputError("unknown_exclusion_instruction")

    exceptions = _array(value["exceptions_applied"], "exceptions_applied")
    exception_ids = _unique_entries(exceptions, "exception_id", "exception")
    for exception in exceptions:
        _object(exception, {"exception_id", "instruction_ids", "reason"}, {"predicate_id", "record_ids"})
        if ("predicate_id" in exception) == ("record_ids" in exception):
            raise AuthorizationInputError("exception_selector_exclusive")
        if "predicate_id" in exception and exception["predicate_id"] not in predicate_ids:
            raise AuthorizationInputError("unknown_exception_predicate")
        if "record_ids" in exception:
            record_ids = _array(exception["record_ids"], "exception_record_ids")
            if not record_ids:
                raise AuthorizationInputError("exception_record_ids_required")
            for record_id in record_ids:
                _id(record_id, "record_id")
        ids = _array(exception["instruction_ids"], "exception_instruction_ids")
        if any(_id(item, "instruction_id") not in instructions for item in ids):
            raise AuthorizationInputError("unknown_exception_instruction")
        if not isinstance(exception["reason"], str):
            raise AuthorizationInputError("invalid_exception_reason")

    for reference_name, known in (("exclusion_ids", exclusion_ids), ("exception_ids", exception_ids), ("evidence_ids", evidence_ids)):
        for reference in notice.get(reference_name, []):
            if reference not in known:
                raise AuthorizationInputError("unresolved_notice_reference")
    case_predicates = []
    scope = notice.get("scope", {})
    if "predicate_id" in scope:
        case_predicates.append(scope["predicate_id"])
    for update in updates:
        if "applies_to" in update:
            case_predicates.append(update["applies_to"]["predicate_id"])
    case_predicates.extend(condition["predicate_id"] for condition in conditions)
    if any(predicate not in predicate_ids for predicate in case_predicates):
        raise AuthorizationInputError("unknown_case_predicate_reference")

    eligible_raw = _array(value["eligible_keys"], "eligible_keys")
    if notice["operation"] == "no_op":
        no_op_final = _array(value["required_final_values"], "required_final_values")
        no_op_rationale = _array(value["eligibility_rationale"], "eligibility_rationale")
        if eligible_raw or no_op_final or no_op_rationale:
            raise AuthorizationInputError("no_op_authorization_must_be_empty")
    eligible = [_address(item, "eligible_key") for item in eligible_raw]
    if len(eligible) != len(set(eligible)):
        raise AuthorizationInputError("duplicate_eligible_key")
    ledger_cells = {
        (table, row["record_id"], field): cell
        for table, rows in payload["ledger"].items()
        for row in rows
        for field, cell in row["values"].items()
    }
    for key in eligible:
        declaration = declarations.get((key[0], key[2]))
        if key not in ledger_cells or declaration is None or declaration["mutable"] is not True:
            raise AuthorizationInputError("eligible_key_not_mutable_or_missing")
        if case["profile"] == "historical-ledger-1.0" and key[0] != "W":
            raise AuthorizationInputError("historical_eligible_key_must_be_working_table")

    rationale = _array(value["eligibility_rationale"], "eligibility_rationale")
    rationale_keys = []
    for item in rationale:
        _object(item, {"key", "included_by", "excluded_by", "instruction_ids"})
        key = _address(item["key"], "eligibility_rationale_key")
        rationale_keys.append(key)
        for field_name, known in (("included_by", predicate_ids), ("excluded_by", exclusion_ids), ("instruction_ids", instructions)):
            refs = _array(item[field_name], field_name)
            if any(_id(ref, field_name) not in known for ref in refs):
                raise AuthorizationInputError(f"unresolved_{field_name}_reference")
    if len(rationale_keys) != len(eligible) or set(rationale_keys) != set(eligible) or len(set(rationale_keys)) != len(rationale_keys):
        raise AuthorizationInputError("eligibility_rationale_coverage")

    final_entries = _array(value["required_final_values"], "required_final_values")
    final_by_key: dict[tuple[str, str, str], Any] = {}
    for entry in final_entries:
        _object(entry, {"key", "value"})
        key = _address(entry["key"], "required_final_value_key")
        if key in final_by_key:
            raise AuthorizationInputError("duplicate_required_final_value")
        declaration = declarations.get((key[0], key[2]))
        if declaration is None or key not in ledger_cells or not matches_type(entry["value"], declaration["type"]):
            raise AuthorizationInputError("required_final_value_type_mismatch")
        final_by_key[key] = entry["value"]
    if set(final_by_key) != set(eligible):
        raise AuthorizationInputError("required_final_values_coverage")

    preservation_raw = _array(value["preservation_keys"], "preservation_keys")
    preservation = [_address(item, "preservation_key") for item in preservation_raw]
    if len(preservation) != len(set(preservation)):
        raise AuthorizationInputError("duplicate_preservation_key")
    expected_preservation = {
        key for key, old_value in ledger_cells.items()
        if key not in final_by_key or equal(old_value, final_by_key[key])
    }
    if set(preservation) != expected_preservation:
        raise AuthorizationInputError("preservation_keys_mismatch")

    by_key = _array(value["rationale_by_key"], "rationale_by_key")
    by_key_addresses = []
    for item in by_key:
        _object(item, {"key", "instruction_ids", "reason"})
        key = _address(item["key"], "rationale_key")
        by_key_addresses.append(key)
        ids = _array(item["instruction_ids"], "rationale_instruction_ids")
        if not ids or any(_id(instruction, "instruction_id") not in instructions for instruction in ids):
            raise AuthorizationInputError("invalid_rationale_instruction_ids")
        if not isinstance(item["reason"], str):
            raise AuthorizationInputError("invalid_rationale_reason")
    if len(by_key_addresses) != len(eligible) or set(by_key_addresses) != set(eligible) or len(set(by_key_addresses)) != len(by_key_addresses):
        raise AuthorizationInputError("rationale_by_key_coverage")

    if is_temporal:
        _temporal_mapping(case, value, predicate_ids, instructions, declarations, metadata)
    elif _TEMPORAL & set(value):
        raise AuthorizationInputError("temporal_members_forbidden")

    return _reconcile_predicate_eligibility(
        case,
        value,
        instructions,
        {entry["predicate_id"]: entry for entry in predicates},
        eligible,
        rationale,
        exclusions,
        exceptions,
    )


def validate_authorization_input(
    value: Any,
    case: Any,
    *,
    authorization_input_bytes: bytes,
    case_bytes: bytes,
    retained_artifacts: dict[str, bytes] | None = None,
) -> AuthorizationInputResult:
    """Validate a v1.4 pre-review authorization input against retained bytes.

    This verifies schema, hashes, references, and structural coverage. It does
    not establish human approval or make the input eligible for grading.
    """
    try:
        if not isinstance(authorization_input_bytes, bytes) or not isinstance(case_bytes, bytes):
            raise AuthorizationInputError("retained_exact_bytes_required")
        if _contains_null(value):
            raise AuthorizationInputError("json_null_forbidden")
        retained = dict(retained_artifacts or {})
        case_hash = "sha256:" + hashlib.sha256(case_bytes).hexdigest()
        input_hash = "sha256:" + hashlib.sha256(authorization_input_bytes).hexdigest()
        retained[case_hash] = case_bytes
        retained[input_hash] = authorization_input_bytes
        try:
            parsed_case = loads_bytes(case_bytes)
            parsed_input = loads_bytes(authorization_input_bytes)
        except Exception as exc:
            raise AuthorizationInputError("retained_json_invalid") from exc
        if not _same_json_value(parsed_case, case) or not _same_json_value(parsed_input, value):
            raise AuthorizationInputError("retained_artifact_content_mismatch")
        case_result = validate_case(case)
        if not case_result.valid:
            raise AuthorizationInputError("invalid_case_bundle")
        temporal = bool(case["payload"].get("temporal_conditions"))
        required = _COMMON | _RESOLUTION | (_TEMPORAL if temporal else set())
        _object(value, required)
        if value["schema_version"] != "acac-auth-input-1.0":
            raise AuthorizationInputError("unsupported_authorization_input_version")
        if value["case_id"] != case["case_id"] or value["profile"] != case["profile"]:
            raise AuthorizationInputError("case_identity_mismatch")
        source_bytes = _hash(value["source_case_hash"], "source_case", retained)
        if source_bytes != case_bytes:
            raise AuthorizationInputError("source_case_hash_mismatch")
        exception_candidates = _validate_resolution(value, case, retained)
        return AuthorizationInputResult(True, None, input_hash, (), exception_candidates)
    except Exception as exc:
        return AuthorizationInputResult(False, None, None, (str(exc),))
