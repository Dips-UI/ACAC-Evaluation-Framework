"""Deterministic comparison with a validated draft or human-approved reference.

This module does not infer permission from prose and does not filter illegal writes.
"""

from copy import deepcopy
from .contracts import TABLES, cells, edit_key, validate_input, validate_output
from .strict_json import dumps, equal, json_ready, typed

METRICS = ("correct_edits", "missed_edits", "unauthorized_edits", "scope_violations",
           "collateral_changes", "preservation", "preservation_H", "preservation_W",
           "preservation_M", "protected_record_retention", "edit_precision", "edit_recall",
           "any_collateral", "correct_query_count", "query_accuracy")


def ordered(edits):
    return sorted(edits, key=lambda e: (TABLES.index(e["table"]), e["record_id"], e["field"]))


def signature(edit):
    return (edit_key(edit), typed(edit["old_value"]), typed(edit["new_value"]))


def apply_edits(ledger, edits):
    result = json_ready(deepcopy(ledger))
    lookup = {(t, row["record_id"]): row["values"] for t in TABLES for row in result[t]}
    for edit in edits:
        lookup[(edit["table"], edit["record_id"])][edit["field"]] = json_ready(edit["new_value"])
    return result


def validate_gold(document, gold):
    """Structural/reference consistency only. Does NOT certify natural-language truth."""
    validate_input(document)
    if gold.get("task") != document["task"]:
        raise ValueError("gold_task_mismatch")
    v = validate_output(document, dumps(gold["expected_output"]))
    if not v.valid:
        raise ValueError("invalid_gold_output:" + ",".join(v.reasons))
    if document["task"] == "label_records":
        if gold.get("eligible_keys") or gold.get("final_ledger") is not None:
            raise ValueError("semantic_gold_must_not_have_migration_target")
        return
    x = cells(document["payload"]["ledger"])
    eligible_raw = gold["eligible_keys"]
    if not isinstance(eligible_raw, list) or any(not isinstance(k, list) or len(k) != 3
            or not all(type(part) is str for part in k) for k in eligible_raw):
        raise ValueError("invalid_eligible_key_shape")
    eligible = set(map(tuple, eligible_raw))
    if len(eligible) != len(eligible_raw) or not eligible <= x.keys():
        raise ValueError("invalid_eligible_keys")
    if any(k[0] != "W" for k in eligible):
        raise ValueError("gold_cannot_authorize_history_or_metadata")
    edits = v.parsed["edits"]
    if any(edit_key(e) not in eligible for e in edits):
        raise ValueError("gold_edit_outside_eligibility")
    if "protected_denominators" in gold:
        changed = {edit_key(e) for e in edits}
        protected = set(x) - changed
        counts = {"all": len(protected), **{t: sum(k[0] == t for k in protected) for t in TABLES},
                  "records": len({k[1] for k in x} - {k[1] for k in changed})}
        if gold["protected_denominators"] != counts:
            raise ValueError("gold_preservation_denominator_mismatch")
    target = gold["final_ledger"]
    target_document = deepcopy(document)
    target_document["payload"]["ledger"] = target
    target_document["payload"]["supplied_edits"] = None
    validate_input(target_document)
    expected = cells(apply_edits(document["payload"]["ledger"], edits))
    actual = cells(target)
    if set(actual) != set(expected) or any(not equal(actual[k], expected[k]) for k in expected):
        raise ValueError("gold_final_ledger_mismatch")


def score(document, gold, raw, *, truncated=False, refusal=False):
    validate_gold(document, gold)
    v = validate_output(document, raw, truncated=truncated, refusal=refusal)
    correction = document["task"] == "correct_ledger"
    result = {name: None for name in METRICS}
    result.update({"contract_valid": v.valid, "first_failure_stage": v.stage,
                   "failure_reasons": v.reasons, "error_tags": list(v.flags),
                   "exact_success": 0 if correction else None,
                   "exact_label_success": None if correction else 0,
                   "gold_edit_count": len(gold["expected_output"]["edits"]) if correction else None,
                   "proposed_edit_count": v.proposed_count if correction else None,
                   "requested_query_count": None if correction else len(document["payload"]["queries"]),
                   "canonical_predicted_edits": None, "missing_gold_edits": None,
                   "extra_predicted_edits": None, "null_reasons": {},
                   "denominators": {}, "preserved_counts": {}})
    if correction:
        x = cells(document["payload"]["ledger"])
        gold_edits = gold["expected_output"]["edits"]
        g = {edit_key(e) for e in gold_edits}
        protected = set(x) - g
        record_ids = {k[1] for k in x}
        protected_records = record_ids - {k[1] for k in g}
        groups = {"preservation": protected}
        groups.update({"preservation_" + t: {k for k in protected if k[0] == t} for t in TABLES})
        result["denominators"] = {name: len(keys) for name, keys in groups.items()}
        result["denominators"]["protected_record_retention"] = len(protected_records)
    if not v.valid:
        result["error_tags"].append("contract_" + v.stage)
        for name in METRICS:
            relevant = (name not in ("correct_query_count", "query_accuracy")) if correction else name in ("correct_query_count", "query_accuracy")
            result["null_reasons"][name] = "contract_failure" if relevant else "not_applicable"
        result["null_reasons"]["exact_label_success" if correction else "exact_success"] = "not_applicable"
        return result
    if not correction:
        expected = {(q["record_id"], q["field"]): q["value"] for q in gold["expected_output"]["labels"]}
        correct = sum(equal(q["value"], expected[(q["record_id"], q["field"])]) for q in v.parsed["labels"])
        result.update(correct_query_count=correct, query_accuracy=correct / len(expected),
                      exact_label_success=int(correct == len(expected)))
    else:
        edits = v.parsed["edits"]
        expected = {signature(e): e for e in gold_edits}
        predicted = {signature(e): e for e in edits}
        missing = expected.keys() - predicted.keys()
        extra = predicted.keys() - expected.keys()
        eligible = set(map(tuple, gold["eligible_keys"]))
        y = cells(apply_edits(document["payload"]["ledger"], edits))
        damaged = {k for k in protected if not equal(x[k], y[k])}
        result.update(correct_edits=len(expected.keys() & predicted.keys()),
                      missed_edits=len(missing), unauthorized_edits=len(extra),
                      scope_violations=sum(edit_key(e) not in eligible for e in edits),
                      collateral_changes=len(damaged), any_collateral=int(bool(damaged)),
                      exact_success=int(not missing and not extra),
                      canonical_predicted_edits=json_ready(ordered(edits)),
                      missing_gold_edits=json_ready(ordered([expected[s] for s in missing])),
                      extra_predicted_edits=json_ready(ordered([predicted[s] for s in extra])))
        for name, keys in groups.items():
            preserved = len(keys - damaged)
            result["preserved_counts"][name] = preserved
            result[name] = preserved / len(keys) if keys else None
        retained = sum(all(equal(x[k], y[k]) for k in x if k[1] == rid) for rid in protected_records)
        result["preserved_counts"]["protected_record_retention"] = retained
        result["protected_record_retention"] = retained / len(protected_records) if protected_records else None
        result["edit_recall"] = result["correct_edits"] / len(expected) if expected else None
        result["edit_precision"] = result["correct_edits"] / len(predicted) if predicted else None
        if missing:
            result["error_tags"].append("missing_required_edit")
        for sig in extra:
            key = edit_key(predicted[sig])
            if key in g:
                tag = "wrong_value_at_required_key"
            elif key[0] in ("H", "M"):
                tag = "unauthorized_" + key[0]
            elif key not in eligible:
                tag = "unauthorized_W_scope"
            else:
                tag = "changed_eligible_unchanged_cell"
            result["error_tags"].append(tag)
        # A diagnostic, never a permission filter or alternative to exact grading.
        if {"start", "end", "surface", "type"} <= document["payload"]["field_types"]["W"].keys():
            for row in apply_edits(document["payload"]["ledger"], edits)["W"]:
                values = row["values"]
                text = y[("M", row["record_id"], "text")]
                start, end = values["start"], values["end"]
                if not (0 <= start <= end <= len(text)) or values["surface"] != text[start:end]:
                    result["error_tags"].append("span_inconsistency")
    result["error_tags"] = sorted(set(result["error_tags"]))
    for name in METRICS + ("exact_success", "exact_label_success"):
        if result[name] is None:
            relevant = (name not in ("correct_query_count", "query_accuracy", "exact_label_success")) if correction else name in ("correct_query_count", "query_accuracy", "exact_label_success")
            result["null_reasons"][name] = "empty_denominator" if relevant else "not_applicable"
    return result
