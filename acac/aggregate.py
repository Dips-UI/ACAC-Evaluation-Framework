"""Deterministic aggregate eligibility and denominator reporting."""


def aggregate_cases(cases: list[dict]) -> dict:
    included = []
    excluded = []
    for case in cases:
        reason = case.get("exclusion_reason")
        eligible = case.get("resolution_status") == "resolved" and case.get("hash_valid") is True and case.get("governance_status") in {"approved_unfrozen", "frozen"}
        if case.get("temporal_required") and not case.get("temporal_gate"):
            eligible = False
            reason = reason or "temporal_gate_failed"
        if eligible:
            included.append(case["case_id"])
        else:
            excluded.append({"case_id": case.get("case_id"), "reason": reason or "not_eligible"})
    return {"scheduled_count": len(cases), "included_count": len(included), "excluded_count": len(excluded), "included_case_ids": included, "excluded_cases": excluded}
