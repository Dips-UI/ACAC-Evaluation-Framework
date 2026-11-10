"""Structural reconciliation of case temporal conditions and sidecar rules."""
from .strict_json import parse_rfc3339_timestamp


class TemporalError(ValueError):
    pass


def applies(event_value: str, effective_at: str, boundary: str) -> bool:
    event = parse_rfc3339_timestamp(event_value).instant
    threshold = parse_rfc3339_timestamp(effective_at).instant
    if boundary == "inclusive":
        return event >= threshold
    if boundary == "exclusive":
        return event > threshold
    raise TemporalError("invalid_effective_boundary")


def reconcile(case: dict, sidecar: dict) -> None:
    if not isinstance(case, dict) or not isinstance(sidecar, dict) or not isinstance(case.get("payload"), dict):
        raise TemporalError("case_bundle_required")
    conditions = case.get("payload", {}).get("temporal_conditions", [])
    rules = sidecar.get("temporal_rules", [])
    if not isinstance(conditions, list) or not isinstance(rules, list):
        raise TemporalError("temporal_arrays_required")
    if bool(conditions) != bool(rules):
        raise TemporalError("temporal_rule_presence_mismatch")
    if not conditions:
        if "temporal_reconciliation" in sidecar:
            raise TemporalError("temporal_reconciliation_without_conditions")
        return
    if sidecar.get("spec_version") != "acac-auth-1.1":
        raise TemporalError("temporal_spec_version_required")
    governing_event = sidecar.get("governing_event")
    if governing_event is None:
        raise TemporalError("governing_event_required")
    reconciliation = sidecar.get("temporal_reconciliation")
    if not isinstance(reconciliation, dict) or set(reconciliation) != {"status", "review_submission_hash", "checked_at"} or reconciliation["status"] != "succeeded":
        raise TemporalError("temporal_reconciliation_required")
    parse_rfc3339_timestamp(reconciliation["checked_at"])
    if len(rules) != len(conditions):
        raise TemporalError("temporal_rule_count_mismatch")
    if not isinstance(governing_event, dict) or governing_event.get("source") not in {"table_field", "record_metadata"}:
        raise TemporalError("invalid_governing_event")
    payload = case["payload"]
    known_instructions = {"original"}
    known_instructions.update(update.get("update_id") for update in payload.get("updates", []) if isinstance(update, dict))
    notice = payload.get("notice")
    if isinstance(notice, dict): known_instructions.add(notice.get("notice_id"))
    predicates = sidecar.get("predicate_definitions", [])
    if not isinstance(predicates, list): raise TemporalError("predicate_definitions_required")
    predicate_ids = [entry.get("predicate_id") for entry in predicates if isinstance(entry, dict)]
    if len(predicate_ids) != len(predicates) or len(predicate_ids) != len(set(predicate_ids)):
        raise TemporalError("invalid_predicate_definitions")
    seen_locations = set(); seen_ids = set(); seen_rules = set(); mapped_conditions = set()
    for rule in rules:
        if set(rule) != {"rule_id", "source_condition_id", "source_location", "occurrence_index", "instruction_id", "predicate_id", "effective_at", "effective_boundary"}:
            raise TemporalError("temporal_rule_members")
        if not isinstance(rule["rule_id"], str) or not rule["rule_id"].strip() or rule["rule_id"] in seen_rules:
            raise TemporalError("duplicate_temporal_rule_id")
        if not isinstance(rule["source_condition_id"], str) or not rule["source_condition_id"].strip() or rule["source_condition_id"] in seen_ids or rule["source_location"] in seen_locations:
            raise TemporalError("duplicate_temporal_rule_identity")
        seen_ids.add(rule["source_condition_id"]); seen_locations.add(rule["source_location"]); seen_rules.add(rule["rule_id"])
        if not isinstance(rule["source_location"], str) or not rule["source_location"].startswith("/payload/temporal_conditions/") or type(rule["occurrence_index"]) is not int or rule["occurrence_index"] != 0:
            raise TemporalError("temporal_source_location_mismatch")
        suffix = rule["source_location"][len("/payload/temporal_conditions/"):]
        if not suffix.isascii() or not suffix.isdigit() or (len(suffix) > 1 and suffix.startswith("0")):
            raise TemporalError("temporal_source_location_mismatch")
        condition_index = int(suffix)
        if condition_index >= len(conditions) or condition_index in mapped_conditions:
            raise TemporalError("temporal_source_location_mismatch")
        condition = conditions[condition_index]
        mapped_conditions.add(condition_index)
        if not isinstance(condition, dict) or rule["source_condition_id"] != condition.get("condition_id"):
            raise TemporalError("temporal_source_condition_id_mismatch")
        if rule["instruction_id"] not in known_instructions:
            raise TemporalError("unknown_temporal_instruction_id")
        if rule["predicate_id"] not in predicate_ids:
            raise TemporalError("unknown_temporal_predicate_id")
        for key in ("instruction_id", "predicate_id", "effective_at", "effective_boundary"):
            if rule[key] != condition[key]:
                raise TemporalError("temporal_rule_source_mismatch")
        if condition.get("governing_event") != governing_event:
            raise TemporalError("governing_event_mismatch")
        parse_rfc3339_timestamp(rule["effective_at"])
        if rule["effective_boundary"] not in {"inclusive", "exclusive"}:
            raise TemporalError("invalid_effective_boundary")
    if len(mapped_conditions) != len(conditions):
        raise TemporalError("temporal_rule_count_mismatch")
