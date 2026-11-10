"""Per-case and aggregate V1 report composition."""

from .grader import _exact_ratio


def case_report(case_id: str, grade_result, governance) -> dict:
    return {"case_id": case_id, "contract_valid": grade_result.contract_valid, "exact_edit_set_valid": grade_result.exact_edit_set_valid, "metrics": grade_result.metrics, "diagnostics": list(grade_result.diagnostics), "governance_status": governance.status, "included": governance.eligible}


def aggregate_report(reports: list[dict]) -> dict:
    included = [report for report in reports if report["included"]]
    exact = sum(report["exact_edit_set_valid"] is True for report in included)
    return {"scheduled_count": len(reports), "included_count": len(included), "excluded_count": len(reports) - len(included), "aggregate_exact_validity": _exact_ratio(exact, len(included)) if included else {"status": "not_applicable", "reason": "no_included_cases"}}
