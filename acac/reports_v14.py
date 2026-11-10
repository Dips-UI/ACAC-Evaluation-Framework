"""Public v1.4 report rendering from coordinator-validated artifact bundles.

The report helpers deliberately re-run the integrated coordinator. Component
validation results and caller-supplied eligibility flags are not report inputs.
"""

from __future__ import annotations

import json
from typing import Any

from .coordinator_v14 import CoordinatorResult, V14Artifacts, grade_with_artifact_eligibility
from .canonical import exact_hash
from .patches import validate_patch_bytes


class ReportV14Error(ValueError):
    pass


def edit_decisions_v14(
    artifacts: V14Artifacts, checked: CoordinatorResult | None = None,
) -> dict[str, Any]:
    """Explain each proposed edit from the already-validated authorization chain.

    This is a presentation layer over existing decisions and metrics. It does
    not evaluate prose or create authorization. The schema has per-key
    rationale and instruction/predicate references, but no direct evidence-ID
    pointer for each key; the report makes that limitation explicit.
    """
    checked = checked or grade_with_artifact_eligibility(artifacts)
    if checked.result is None:
        return {
            "status": "not_evaluated_authorization_chain_refused",
            "refusal_code": checked.refusal_code,
            "edits": [],
        }

    declarations = {
        (item["table"], item["field"]): item
        for item in artifacts.case["payload"]["field_declarations"]
    }
    patch = validate_patch_bytes(
        artifacts.raw_output_bytes, artifacts.case["payload"]["ledger"],
        declarations, artifacts.case["profile"],
    )
    provenance = checked.result["provenance"]
    artifact_hashes = {
        "source_case": provenance["case_exact_hash"],
        "authorization_input": provenance["authorization_input_hash"],
        "review_submissions": list(provenance["review_submission_hashes"]),
        "final_authorization_sidecar": provenance["final_authorization_sidecar_hash"],
        "reference": provenance["reference_hash"],
        "adjudication": provenance["adjudication_hash"],
        "approval_event": provenance["approval_event_hash"],
        "raw_model_output": provenance["raw_output_hash"],
        "prompt": provenance["prompt_hash"],
        "configuration": provenance["configuration_hash"],
    }
    if not patch.valid:
        operation_by_index = {
            index: {"valid_in_isolation": valid, "errors": list(errors)}
            for index, valid, errors in patch.operation_diagnostics
        }
        edits = []
        for index, edit in enumerate(patch.edits):
            target = [edit.get(name, "<missing>") for name in ("table", "record_id", "field")]
            item = {
                "index": index,
                "target": target,
                "authorization_decision": "not_evaluated_structural_failure",
                "reason": "The patch failed structural validation; no authorization conclusion is made.",
                "structural_diagnostics": operation_by_index.get(index, {"valid_in_isolation": False, "errors": []}),
            }
            if "old_value" in edit:
                item["from"] = edit["old_value"]
            if "new_value" in edit:
                item["to"] = edit["new_value"]
            edits.append(item)
        return {
            "status": "structural_failure",
            "diagnostics": list(patch.errors),
            "artifact_hashes": artifact_hashes,
            "edits": edits,
        }

    authorization = artifacts.authorization_input
    eligible = {tuple(key) for key in authorization["eligible_keys"]}
    required = {tuple(item["key"]): item["value"] for item in authorization["required_final_values"]}
    rationale = {tuple(item["key"]): item for item in authorization["rationale_by_key"]}
    eligibility = {tuple(item["key"]): item for item in authorization["eligibility_rationale"]}
    initial = {
        (table, row["record_id"], field): value
        for table, rows in artifacts.case["payload"]["ledger"].items()
        for row in rows for field, value in row["values"].items()
    }
    temporal_rules = authorization.get("temporal_rules", [])
    exceptions = authorization["exceptions_applied"]
    edits = []
    for index, edit in enumerate(patch.edits):
        key = (edit["table"], edit["record_id"], edit["field"])
        key_eligibility = eligibility.get(key, {})
        key_rationale = rationale.get(key, {})
        instruction_ids = sorted(set(
            key_eligibility.get("instruction_ids", [])
            + key_rationale.get("instruction_ids", [])
        ))
        predicate_ids = sorted(set(key_eligibility.get("included_by", [])))
        exclusion_ids = sorted(set(key_eligibility.get("excluded_by", [])))
        temporal_rule_ids = sorted({
            item["rule_id"] for item in temporal_rules
            if item.get("predicate_id") in predicate_ids
            and item.get("instruction_id") in instruction_ids
        })
        exception_ids = sorted({
            item["exception_id"] for item in exceptions
            if set(item["instruction_ids"]).intersection(instruction_ids)
            and (
                key[1] in item.get("record_ids", [])
                or item.get("predicate_id") in predicate_ids
            )
        })
        if key in eligible and key in required and edit["old_value"] == initial.get(key) and edit["new_value"] == required[key]:
            decision = "matches_resolved_required_edit"
            reason = key_rationale.get("reason", "The edit exactly matches the resolved required final value.")
        elif key in eligible:
            decision = "does_not_match_resolved_required_edit"
            reason = "The target is eligible, but the proposed transition does not match its resolved required final value."
        elif key in set(map(tuple, authorization["preservation_keys"])):
            decision = "violates_preservation_requirement"
            reason = "The target is declared for preservation and is not an authorized change target."
        else:
            decision = "outside_eligible_scope"
            reason = "The target is absent from the validated eligible-key set."
        edits.append({
            "index": index,
            "target": list(key),
            "from": edit["old_value"],
            "to": edit["new_value"],
            "authorization_decision": decision,
            "reason": reason,
            "applicable_rules": {
                "instruction_ids": instruction_ids,
                "predicate_ids": predicate_ids,
                "temporal_rule_ids": temporal_rule_ids,
                "exclusion_ids": exclusion_ids,
                "exception_ids": exception_ids,
            },
            "supporting_evidence": {
                "direct_evidence_ids": [],
                "direct_key_to_evidence_mapping_available": False,
                "artifact_hashes": artifact_hashes,
            },
        })
    return {"status": "evaluated", "edits": edits}


def case_report_v14(artifacts: V14Artifacts) -> dict[str, Any]:
    """Return a public-facing report only after the artifact chain revalidates."""
    checked: CoordinatorResult = grade_with_artifact_eligibility(artifacts)
    if not checked.eligible or checked.result is None:
        raise ReportV14Error("grading_chain_ineligible:" + (checked.refusal_code or "unknown"))

    result = checked.result
    provenance = result["provenance"]
    review_records = [pair[0] for pair in artifacts.reviews_by_hash.values()]
    review_records.sort(key=lambda review: review["review_id"])
    adjudication = artifacts.adjudication
    independence = [
        {
            "declared_independent": review["independence_declaration"],
            "basis_recorded": bool(review["independence_basis"].strip()),
        }
        for review in review_records
    ]
    report = {
        "schema_version": "acac-report-1.4",
        "case_id": result["case_id"],
        "run_id": result["run_id"],
        "contract_valid": result["contract_valid"],
        "exact_edit_set_valid": result["exact_edit_set_valid"],
        "metrics": result["metrics"],
        "diagnostics": result["diagnostics"],
        "edit_decisions": edit_decisions_v14(artifacts, checked),
        "reference_governance_status": provenance["reference_governance_status"],
        "reference_content_hash": provenance["reference_hash"],
        "approval_event_hash": provenance["approval_event_hash"],
        "freeze_event_hash": provenance.get("freeze_event_hash"),
        "freeze_binding": (
            "run_specific"
            if provenance["reference_governance_status"] == "frozen"
            else "not_frozen"
        ),
        "human_review_governance": {
            "human_review_count": len(review_records),
            "review_independence": independence,
            "adjudication_present": True,
            "adjudicator_independence_declared": adjudication["independence_declaration"],
            "same_person_reviewed_and_adjudicated": any(
                review["reviewer_id"] == adjudication["adjudicator_id"]
                for review in review_records
            ),
            "interpretation": (
                "Role separation and declared independence are reported as provenance; "
                "they do not establish independent validation or guarantee correctness."
            ),
        },
    }
    return report


def aggregate_report_v14(aggregate: dict[str, Any]) -> dict[str, Any]:
    """Validate the aggregate's public shape and return a detached JSON value."""
    if not isinstance(aggregate, dict) or aggregate.get("schema_version") != "acac-1.4":
        raise ReportV14Error("v1_4_aggregate_required")
    try:
        # Ensure report serialization itself cannot introduce non-JSON values.
        return json.loads(json.dumps(aggregate, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise ReportV14Error("aggregate_not_json_serializable") from exc


def render_case_markdown_v14(report: dict[str, Any]) -> str:
    """Render a compact Markdown report without changing metric values."""
    if not isinstance(report, dict) or report.get("schema_version") != "acac-report-1.4":
        raise ReportV14Error("v1_4_case_report_required")
    provenance_rows = (
        ("Reference governance", report["reference_governance_status"]),
        ("Reference content hash", report["reference_content_hash"]),
        ("Approval event hash", report["approval_event_hash"]),
        ("Freeze binding", report["freeze_binding"]),
    )
    lines = [
        f"# ACAC case report: {report['case_id']}",
        "",
        f"Run: `{report['run_id']}`",
        f"Contract valid: `{str(report['contract_valid']).lower()}`",
        f"Exact edit-set valid: `{str(report['exact_edit_set_valid']).lower()}`",
        "",
        "## Governance and artifact provenance",
        "",
        *[f"- {label}: `{value}`" for label, value in provenance_rows],
        f"- Human reviews: `{report['human_review_governance']['human_review_count']}`",
        f"- Review independence declarations: `{json.dumps([item['declared_independent'] for item in report['human_review_governance']['review_independence']])}`",
        f"- Adjudication present: `{str(report['human_review_governance']['adjudication_present']).lower()}`",
        f"- Adjudicator independence declared: `{str(report['human_review_governance']['adjudicator_independence_declared']).lower()}`",
        f"- Reviewer also adjudicated: `{str(report['human_review_governance']['same_person_reviewed_and_adjudicated']).lower()}`",
        "",
        "## Metrics",
        "",
        "| Metric | Exact value |",
        "|---|---|",
    ]
    for name, value in sorted(report["metrics"].items()):
        lines.append(f"| `{name}` | `{json.dumps(value, ensure_ascii=False, sort_keys=True)}` |")
    if report["diagnostics"]:
        lines.extend(("", "## Diagnostics", "", *[f"- `{item}`" for item in report["diagnostics"]]))
    lines.append("")
    return "\n".join(lines)
