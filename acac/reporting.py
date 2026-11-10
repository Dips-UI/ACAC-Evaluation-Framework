"""Offline score records and denominator-explicit aggregates; no inference calls."""

from collections import defaultdict
from statistics import mean

from .dataset import load_configuration
from .runner import schedule
from .scoring import score


def score_record(root, slot, raw, *, source_kind, metadata=None):
    if source_kind not in ("synthetic_test", "model_response"):
        raise ValueError("explicit_response_provenance_required")
    metadata = metadata or {}
    d, g, config = load_configuration(root, slot["configuration_id"])
    received = raw is not None
    r = score(d, g, raw if received else "", truncated=metadata.get("truncated", False),
              refusal=metadata.get("refusal", False))
    r.update({"source_kind": source_kind, "case_id": config["case_id"], "family": config["family"],
              "condition": config["condition"], "configuration_id": config["configuration_id"],
              "model_slot": slot["model_slot"], "repetition": int(slot["repetition"]),
              "input_hash": config["input_hash"], "gold_hash": config["gold_hash"],
              "response_received": received, "transport_status": "received" if received else "unavailable",
              "retry_count": metadata.get("retry_count", 0)})
    for field in ("pilot_version", "exact_model_id", "request_id", "finish_reason", "input_tokens",
                  "output_tokens", "reasoning_tokens", "latency", "billed_cost", "raw_output_path", "parsed_output_path"):
        r[field] = metadata.get(field)
    if not received:
        r.update(contract_valid=None, first_failure_stage="transport", failure_reasons=["infrastructure_unavailable"],
                 error_tags=["infrastructure_unavailable"])
        r["null_reasons"] = {k: ("infrastructure_unavailable" if reason == "contract_failure" else reason)
                             for k, reason in r["null_reasons"].items()}
    return r


def _mean(values):
    values = list(values)
    return mean(values) if values else None


def _summary(rows):
    valid = [r for r in rows if r["contract_valid"] is True]
    received = [r for r in rows if r["response_received"]]
    result = {"scheduled_slots": len(rows), "received": len(received), "unavailable": len(rows) - len(received),
              "contract_valid_responses": len(valid), "contract_failures": len(received) - len(valid),
              "scheduled_exact_accuracy": _mean(r["exact_success"] for r in rows),
              "response_conditional_exact_accuracy": _mean(r["exact_success"] for r in received),
              "validity_per_received": len(valid) / len(received) if received else None,
              "validity_per_scheduled": len(valid) / len(rows) if rows else None,
              "semantic_metrics_are_conditional_on_contract_validity": True,
              "conditional_n": len(valid)}
    counts = ("correct_edits", "missed_edits", "unauthorized_edits", "scope_violations", "collateral_changes")
    result["conditional_counts"] = {k: sum(r[k] for r in valid) if valid else None for k in counts}
    result["conditional_means"] = {}
    for key in ("preservation", "preservation_H", "preservation_W", "preservation_M", "protected_record_retention", "any_collateral", "edit_precision", "edit_recall"):
        values = [r[key] for r in valid if r[key] is not None]
        result["conditional_means"][key] = {"value": _mean(values), "n": len(values)}
    return result


def aggregate(plan, observations):
    """Require an explicit record for every slot, including unavailable slots."""
    expected = {(s["model_slot"], s["configuration_id"], s["repetition"]) for s in schedule(plan)}
    indexed = {}
    for r in observations:
        key = (r["model_slot"], r["configuration_id"], r["repetition"])
        if key not in expected or key in indexed:
            raise ValueError("unknown_or_duplicate_observation")
        case, condition = r["configuration_id"].split("__")
        if (r["case_id"], r["family"], r["condition"]) != (case, case[:2], condition):
            raise ValueError("observation_identity_mismatch")
        indexed[key] = r
    if indexed.keys() != expected:
        raise ValueError("missing_scheduled_observation_use_explicit_unavailable_record")
    origins = {r["source_kind"] for r in observations}
    if len(origins) != 1:
        raise ValueError("cannot_mix_synthetic_tests_and_model_responses")
    output = {"source_kind": next(iter(origins)), "models": {}}
    for model in plan["model_slots"]:
        rows = [r for r in observations if r["model_slot"] == model]
        main = [r for r in rows if r["condition"] == "main"]
        family_rows = defaultdict(list)
        for r in main:
            family_rows[r["family"]].append(r)
        family_scores = {}
        for fam, items in family_rows.items():
            case_scores = defaultdict(list)
            for r in items: case_scores[r["case_id"]].append(r["exact_success"])
            family_scores[fam] = _mean(_mean(scores) for scores in case_scores.values())
        primary = [r for r in main if r["family"] in ("S1", "S3", "S4")]
        model_result = {"family_exact_accuracy": family_scores,
                        "primary_family_macro": _mean(family_scores[f] for f in ("S1", "S3", "S4") if f in family_scores),
                        "primary_micro": _mean(r["exact_success"] for r in primary),
                        "all_five_family_macro": _mean(family_scores.values()),
                        "main": _summary(main), "primary": _summary(primary),
                        "families": {f: _summary(rs) for f, rs in family_rows.items()},
                        "no_op": _summary([r for r in main if r["gold_edit_count"] == 0]),
                        "non_no_op": _summary([r for r in main if r["gold_edit_count"] != 0]),
                        "control_pairs": [], "authorization_pairs": []}
        for r in rows:
            if r["condition"] == "main": continue
            base = indexed[(model, r["case_id"] + "__main", r["repetition"])]
            comparable = r["condition"] in ("resolved", "order", "wording")
            valid_pair = base["contract_valid"] is True and r["contract_valid"] is True
            model_result["control_pairs"].append({
                "configuration_id": r["configuration_id"], "repetition": r["repetition"],
                "main_exact": base["exact_success"], "control_exact": r["exact_label_success"] if r["condition"] == "semantic" else r["exact_success"],
                "both_received": base["response_received"] and r["response_received"],
                "paired_difference": r["exact_success"] - base["exact_success"] if comparable else None,
                "patch_equal": r["canonical_predicted_edits"] == base["canonical_predicted_edits"] if valid_pair and r["condition"] in ("order", "wording") else None,
                "edit_differences": {k: r[k] - base[k] for k in ("missed_edits", "unauthorized_edits", "collateral_changes")} if comparable and valid_pair else None})
        for left, right in (("S1-A", "S1-B"), ("S3-A", "S3-B"), ("S5-A", "S5-B")):
            for repetition in plan["repetitions"]:
                keys = [(model, c + "__main", int(repetition)) for c in (left, right)]
                if not all(k in indexed for k in keys): continue
                a, b = [indexed[k] for k in keys]
                model_result["authorization_pairs"].append({"pair": [left, right], "repetition": int(repetition),
                    "both_received": a["response_received"] and b["response_received"],
                    "paired_exact_success": int(a["exact_success"] == b["exact_success"] == 1)})
        output["models"][model] = model_result
    return output
