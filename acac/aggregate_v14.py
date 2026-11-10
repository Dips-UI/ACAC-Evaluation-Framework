"""Exact v1.4 aggregation from revalidated retained artifact bundles."""
from typing import Any

from .coordinator_v14 import V14Artifacts, grade_with_artifact_eligibility
from .metrics_v14 import add, divide, rational


class AggregateV14Error(ValueError):
    pass


_COUNT_METRICS = (
    "missed_corrections", "unauthorized_edits", "scope_violations", "collateral_changes",
)


def aggregate_artifact_run_v14(
    artifacts_by_case: dict[str, V14Artifacts],
    scheduled_case_ids: set[str],
) -> dict[str, Any]:
    """Revalidate each scheduled case through the coordinator before aggregation.

    No caller-provided eligible/governance Boolean is consumed. Results are
    aggregated only when the integrated coordinator returns a bound result.
    """
    if not isinstance(artifacts_by_case, dict) or not isinstance(scheduled_case_ids, set):
        raise AggregateV14Error("aggregate_inputs_required")
    if any(not isinstance(case_id, str) or not case_id for case_id in scheduled_case_ids):
        raise AggregateV14Error("invalid_scheduled_case_id")
    if any(not isinstance(case_id, str) for case_id in artifacts_by_case):
        raise AggregateV14Error("invalid_artifact_case_id")
    if not set(artifacts_by_case) <= scheduled_case_ids:
        raise AggregateV14Error("unscheduled_case_artifact")

    included: list[str] = []
    excluded: list[dict[str, str]] = []
    exact_values: list[dict[str, str]] = []
    preservation_numerator = 0
    preservation_denominator = 0
    structural_failures = 0
    valid_response_count = 0
    counts = {name: 0 for name in _COUNT_METRICS}
    result_by_case: dict[str, dict[str, Any]] = {}

    for case_id in sorted(scheduled_case_ids):
        artifacts = artifacts_by_case.get(case_id)
        if artifacts is None:
            excluded.append({"case_id": case_id, "reason": "missing_artifact"})
            continue
        if not isinstance(artifacts, V14Artifacts):
            raise AggregateV14Error("invalid_case_artifact_bundle")
        manifest = artifacts.manifest
        manifest_scheduled = manifest.get("scheduled_case_ids") if isinstance(manifest, dict) else None
        manifest_executed = manifest.get("executed_case_ids") if isinstance(manifest, dict) else None
        if (
            not isinstance(manifest_scheduled, list)
            or any(not isinstance(value, str) for value in manifest_scheduled)
            or set(manifest_scheduled) != scheduled_case_ids
            or not isinstance(manifest_executed, list)
            or any(not isinstance(value, str) for value in manifest_executed)
            or case_id not in manifest_executed
        ):
            excluded.append({"case_id": case_id, "reason": "manifest_invalid"})
            continue
        checked = grade_with_artifact_eligibility(artifacts)
        if not checked.eligible:
            excluded.append({"case_id": case_id, "reason": checked.refusal_code or "malformed_artifact"})
            continue
        if checked.result["case_id"] != case_id:
            excluded.append({"case_id": case_id, "reason": "binding_mismatch"})
            continue

        result = checked.result
        contribution = checked.aggregate_contribution
        if not isinstance(contribution, dict):
            raise AggregateV14Error("coordinator_aggregate_contribution_missing")
        included.append(case_id)
        result_by_case[case_id] = result
        exact_values.append(rational(int(contribution["exact_edit_set_valid"]), 1))
        if contribution["structural_failure"]:
            structural_failures += 1
        else:
            valid_response_count += 1
            for name in _COUNT_METRICS:
                value = result["metrics"][name]
                if type(value) is int:
                    counts[name] += value
        numerator = contribution["preservation_numerator"]
        denominator = contribution["preservation_denominator"]
        if denominator is not None:
            if type(numerator) is not int or type(denominator) is not int or numerator < 0 or denominator <= 0 or numerator > denominator:
                raise AggregateV14Error("invalid_preservation_contribution")
            preservation_numerator += numerator
            preservation_denominator += denominator
        elif numerator is not None:
            raise AggregateV14Error("invalid_preservation_contribution")

    exact_mean = divide(add(*exact_values), len(exact_values)) if exact_values else {"status": "not_applicable", "reason": "empty_aggregate_denominator"}
    preservation = (
        rational(preservation_numerator, preservation_denominator)
        if preservation_denominator
        else {
            "status": "not_applicable",
            "reason": "structural_invalidity"
            if structural_failures and not valid_response_count
            else "empty_preservation_denominator",
        }
    )
    structural_rate = (
        rational(structural_failures, len(included))
        if included else {"status": "not_applicable", "reason": "empty_aggregate_denominator"}
    )
    return {
        "schema_version": "acac-1.4",
        "scheduled_count": len(scheduled_case_ids),
        "included_count": len(included),
        "excluded_count": len(excluded),
        "included_case_ids": included,
        "excluded_cases": excluded,
        "exact_edit_set_validity": exact_mean,
        "exact_edit_set_validity_denominator": len(exact_values),
        "preservation_accuracy": preservation,
        "preservation_protected_cell_denominator": preservation_denominator,
        "structural_failure_rate": structural_rate,
        "structural_failure_count": structural_failures,
        "structural_failure_denominator": len(included),
        "ledger_metric_denominator": valid_response_count,
        "count_metrics": counts,
        "case_results": result_by_case,
    }
