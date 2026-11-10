"""Fail-closed integrated v1.4 validation and grading coordinator."""

from dataclasses import dataclass, field
from typing import Any

from .adjudication_v14 import validate_adjudication_v14
from .authorization_input import validate_authorization_input
from .authorization_sidecar_v14 import validate_final_sidecar_v14
from .canonical import exact_hash
from .lifecycle_v14 import replay_lifecycle_v14
from .manifest_v14 import validate_manifest_v14
from .metrics_v14 import grade_patch_v14
from .patches import validate_patch_bytes
from .references_v14 import validate_reference_v14
from .results_v14 import validate_result_v14
from .review_records_v14 import validate_human_review_v14
from .strict_json import is_integer, loads_bytes


@dataclass(frozen=True)
class V14Artifacts:
    case: Any
    case_bytes: bytes
    authorization_input: Any
    authorization_input_bytes: bytes
    reviews_by_hash: dict[str, tuple[dict, bytes]]
    sidecar: Any
    sidecar_bytes: bytes
    reference: Any
    reference_bytes: bytes
    adjudication: Any
    adjudication_bytes: bytes
    lifecycle_events: list[dict]
    lifecycle_event_bytes: list[bytes]
    lifecycle_event_hashes: list[str]
    raw_output_bytes: bytes
    manifest: dict
    manifest_bytes: bytes
    scheduled_case_ids: set[str]
    manifest_artifacts_by_case: dict[str, dict[str, Any]]
    reference_author_id: str
    configured_approver_id: str
    additional_retained_artifacts: dict[str, bytes] = field(default_factory=dict)


@dataclass(frozen=True)
class CoordinatorResult:
    result: dict[str, Any] | None
    refusal_code: str | None
    diagnostics: tuple[str, ...]
    aggregate_contribution: dict[str, Any] | None = None

    @property
    def eligible(self) -> bool:
        return self.result is not None


def _refuse(code: str, details: tuple[str, ...] = ()) -> CoordinatorResult:
    return CoordinatorResult(None, code, (code, *details))


def _contains_retained_hash_mismatch(errors: tuple[str, ...] | list[str]) -> bool:
    exact_mismatch_tokens = (
        "review_hash_mismatch", "lifecycle_event_hash_mismatch", "case_hash_mismatch",
        "raw_output_hash_mismatch", "_hashes_hash_mismatch", "_hashes_mismatch",
    )
    return any(any(token in error for token in exact_mismatch_tokens) for error in errors)


def _same_json_value(left: Any, right: Any) -> bool:
    if isinstance(left, dict) or isinstance(right, dict):
        return isinstance(left, dict) and isinstance(right, dict) and set(left) == set(right) and all(_same_json_value(left[key], right[key]) for key in left)
    if isinstance(left, list) or isinstance(right, list):
        return isinstance(left, list) and isinstance(right, list) and len(left) == len(right) and all(_same_json_value(a, b) for a, b in zip(left, right))
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left is right
    if is_integer(left) or is_integer(right):
        return is_integer(left) and is_integer(right) and int(left) == int(right)
    return type(left) is type(right) and left == right


def grade_with_artifact_eligibility(artifacts: V14Artifacts) -> CoordinatorResult:
    """Validate the retained artifact chain before computing any metrics.

    Component validators intentionally do not expose grading eligibility.
    """
    required_bytes = (
        artifacts.case_bytes, artifacts.authorization_input_bytes,
        artifacts.sidecar_bytes, artifacts.reference_bytes,
        artifacts.adjudication_bytes, artifacts.raw_output_bytes,
        artifacts.manifest_bytes,
    )
    if any(not isinstance(item, bytes) for item in required_bytes):
        return _refuse("missing_artifact")
    if not isinstance(artifacts.reviews_by_hash, dict) or not artifacts.reviews_by_hash:
        return _refuse("review_missing")
    if not isinstance(artifacts.lifecycle_events, list) or not artifacts.lifecycle_events:
        return _refuse("approval_missing")

    try:
        parsed = (
            loads_bytes(artifacts.case_bytes),
            loads_bytes(artifacts.authorization_input_bytes),
            loads_bytes(artifacts.sidecar_bytes),
            loads_bytes(artifacts.reference_bytes),
            loads_bytes(artifacts.adjudication_bytes),
            loads_bytes(artifacts.manifest_bytes),
        )
        if not all(_same_json_value(value, expected) for value, expected in zip(
            parsed,
            (artifacts.case, artifacts.authorization_input, artifacts.sidecar,
             artifacts.reference, artifacts.adjudication, artifacts.manifest),
        )):
            return _refuse("malformed_artifact", ("retained_value_mismatch",))
    except Exception as exc:
        return _refuse("malformed_artifact", (str(exc),))

    case, authorization_input, sidecar, reference, adjudication, manifest = parsed
    if not isinstance(manifest, dict):
        return _refuse("manifest_invalid")
    input_result = validate_authorization_input(
        authorization_input, case,
        authorization_input_bytes=artifacts.authorization_input_bytes,
        case_bytes=artifacts.case_bytes,
    )
    if not input_result.valid:
        if any("unsupported" in error for error in input_result.errors):
            code = "unsupported_version"
        elif any("source_case_hash_mismatch" in error for error in input_result.errors):
            code = "binding_mismatch"
        else:
            code = "malformed_artifact"
        return _refuse(code, input_result.errors)
    case_hash = exact_hash(artifacts.case_bytes)
    input_hash = exact_hash(artifacts.authorization_input_bytes)
    if not isinstance(reference, dict) or reference.get("case_id") != case.get("case_id") or reference.get("authorization_input_hash") != input_hash:
        return _refuse("binding_mismatch", ("reference_input_or_case_mismatch",))
    if reference.get("source_case_hash") != case_hash:
        return _refuse("binding_mismatch", ("reference_case_hash_mismatch",))
    reference_hash = exact_hash(artifacts.reference_bytes)

    review_errors: list[str] = []
    for digest, pair in artifacts.reviews_by_hash.items():
        if not isinstance(pair, tuple) or len(pair) != 2 or not isinstance(pair[1], bytes):
            review_errors.append("review_artifact_missing")
            continue
        review, raw = pair
        checked = validate_human_review_v14(
            review, review_bytes=raw, case=case,
            authorization_input=authorization_input,
            authorization_input_bytes=artifacts.authorization_input_bytes,
            reference=reference, reference_bytes=artifacts.reference_bytes,
        )
        if not checked.valid or checked.review_hash != digest:
            review_errors.extend(checked.errors or ("review_hash_mismatch",))
    if review_errors:
        code = "hash_mismatch" if _contains_retained_hash_mismatch(review_errors) else "review_invalid"
        return _refuse(code, tuple(review_errors))

    checked_sidecar = validate_final_sidecar_v14(
        sidecar, sidecar_bytes=artifacts.sidecar_bytes,
        case=case, case_bytes=artifacts.case_bytes,
        authorization_input=authorization_input,
        authorization_input_bytes=artifacts.authorization_input_bytes,
        reference=reference, reference_bytes=artifacts.reference_bytes,
        reviews_by_hash=artifacts.reviews_by_hash,
    )
    if not checked_sidecar.valid:
        temporal_failure_prefixes = (
            "temporal_reconciliation_shape",
            "temporal_reconciliation_not_succeeded",
            "temporal_reconciliation_review_hashes_required",
            "temporal_reconciliation_checked_at_invalid",
        )
        if _contains_retained_hash_mismatch(checked_sidecar.errors):
            return _refuse("hash_mismatch", checked_sidecar.errors)
        if case["payload"].get("temporal_conditions") and any(
            error.startswith(temporal_failure_prefixes)
            for error in checked_sidecar.errors
        ):
            return _refuse("temporal_reconciliation_failed", checked_sidecar.errors)
        return _refuse("sidecar_invalid", checked_sidecar.errors)
    if set(artifacts.reviews_by_hash) != set(sidecar.get("review_submission_hashes", [])):
        return _refuse("review_invalid", ("review_artifact_set_mismatch",))
    if checked_sidecar.status == "ambiguous":
        return _refuse("unresolved_authorization")
    if checked_sidecar.status == "quarantined":
        return _refuse("quarantined_authorization")
    if checked_sidecar.status != "resolved":
        return _refuse("unresolved_authorization")
    if case["payload"].get("temporal_conditions"):
        reconciliation = sidecar.get("temporal_reconciliation")
        if not isinstance(reconciliation, dict) or reconciliation.get("status") != "succeeded":
            return _refuse("temporal_reconciliation_failed")

    checked_reference = validate_reference_v14(
        reference, reference_bytes=artifacts.reference_bytes,
        case=case, case_bytes=artifacts.case_bytes,
        authorization_input=authorization_input,
        authorization_input_bytes=artifacts.authorization_input_bytes,
        sidecar=sidecar, sidecar_bytes=artifacts.sidecar_bytes,
        reviews_by_hash=artifacts.reviews_by_hash,
    )
    if not checked_reference.valid:
        if _contains_retained_hash_mismatch(checked_reference.errors):
            return _refuse("hash_mismatch", checked_reference.errors)
        return _refuse("reference_invalid", checked_reference.errors)

    review_hashes = set(artifacts.reviews_by_hash)
    checked_adjudication = validate_adjudication_v14(
        adjudication, adjudication_bytes=artifacts.adjudication_bytes,
        case_id=case["case_id"], source_case_hash=case_hash,
        authorization_input_hash=input_hash, reference=reference,
        reference_bytes=artifacts.reference_bytes, review_hashes=review_hashes,
        case=case, authorization_input=authorization_input,
        exception_decision_candidates=input_result.exception_decision_candidates,
    )
    if not checked_adjudication.valid:
        if _contains_retained_hash_mismatch(checked_adjudication.errors):
            return _refuse("hash_mismatch", checked_adjudication.errors)
        return _refuse("adjudication_invalid", checked_adjudication.errors)
    if checked_adjudication.unauthorized_exceptions:
        if any(decision == "unresolved" for *_, decision in checked_adjudication.unauthorized_exceptions):
            return _refuse("exception_authority_unresolved", ("exception_authority_unresolved",))
        return _refuse("exception_not_authorized", ("exception_authority_not_established",))

    retained_by_hash = {
        case_hash: artifacts.case_bytes,
        input_hash: artifacts.authorization_input_bytes,
        exact_hash(artifacts.sidecar_bytes): artifacts.sidecar_bytes,
        reference_hash: artifacts.reference_bytes,
        checked_adjudication.adjudication_hash: artifacts.adjudication_bytes,
        exact_hash(artifacts.manifest_bytes): artifacts.manifest_bytes,
    }
    if isinstance(artifacts.additional_retained_artifacts, dict):
        retained_by_hash.update(artifacts.additional_retained_artifacts)
    for digest, (_, raw) in artifacts.reviews_by_hash.items():
        retained_by_hash[digest] = raw
    for raw, digest in zip(artifacts.lifecycle_event_bytes, artifacts.lifecycle_event_hashes):
        retained_by_hash[digest] = raw
    if (
        not isinstance(artifacts.manifest_artifacts_by_case, dict)
        or not isinstance(artifacts.manifest_artifacts_by_case.get(case["case_id"]), dict)
    ):
        return _refuse("manifest_invalid", ("current_case_artifact_bytes_missing",))
    current_retained = artifacts.manifest_artifacts_by_case[case["case_id"]]
    expected_retained = {
        "case": artifacts.case_bytes,
        "raw_output": artifacts.raw_output_bytes,
        "authorization_input": artifacts.authorization_input_bytes,
        "review_submission_bytes": [raw for _, raw in artifacts.reviews_by_hash.values()],
        "final_authorization_sidecar": artifacts.sidecar_bytes,
        "reference": artifacts.reference_bytes,
        "adjudication": artifacts.adjudication_bytes,
    }
    approval_pair = next(
        ((event, raw) for event, raw in zip(artifacts.lifecycle_events, artifacts.lifecycle_event_bytes)
         if event.get("event_type") == "approved"),
        None,
    )
    if approval_pair is None:
        return _refuse("approval_missing")
    expected_retained["approval_event"] = approval_pair[1]
    for name, expected in expected_retained.items():
        if current_retained.get(name) != expected:
            return _refuse("manifest_invalid", (f"current_case_{name}_binding_mismatch",))
    replay = replay_lifecycle_v14(
        artifacts.lifecycle_events, artifacts.lifecycle_event_bytes,
        artifacts.lifecycle_event_hashes, reference=reference,
        reference_bytes=artifacts.reference_bytes,
        reference_author_id=artifacts.reference_author_id,
        configured_approver_id=artifacts.configured_approver_id,
        retained_artifacts=retained_by_hash,
    )
    if not replay.valid:
        if _contains_retained_hash_mismatch(replay.errors):
            return _refuse("hash_mismatch", replay.errors)
        code = "approver_not_distinct" if any("approver_is_reference_author" in error for error in replay.errors) else "lifecycle_invalid"
        return _refuse(code, replay.errors)
    if replay.governance_status not in {"approved_unfrozen", "frozen"} or replay.approval_event_hash is None:
        return _refuse("approval_missing")
    approval = next((event for event, digest in zip(artifacts.lifecycle_events, artifacts.lifecycle_event_hashes) if digest == replay.approval_event_hash), None)
    if approval is None:
        return _refuse("approval_missing")
    if (
        approval.get("authorization_input_hash") != input_hash
        or approval.get("final_authorization_sidecar_hash") != exact_hash(artifacts.sidecar_bytes)
        or set(approval.get("review_submission_hashes", [])) != set(sidecar.get("review_submission_hashes", []))
        or approval.get("adjudication_hash") != checked_adjudication.adjudication_hash
        or approval.get("approved_reference_hash") != reference_hash
    ):
        return _refuse("binding_mismatch", ("approval_artifact_binding_mismatch",))

    if case["case_id"] not in manifest.get("executed_case_ids", []):
        return _refuse("manifest_invalid", ("case_not_executed",))
    if any(isinstance(item, dict) and item.get("case_id") == case["case_id"] for item in manifest.get("excluded_cases", [])):
        return _refuse("manifest_invalid", ("excluded_case_cannot_be_graded",))
    try:
        validate_manifest_v14(manifest, artifacts.scheduled_case_ids, artifacts.manifest_artifacts_by_case)
    except Exception as exc:
        details = (str(exc),)
        code = "hash_mismatch" if _contains_retained_hash_mismatch(details) else "manifest_invalid"
        return _refuse(code, details)
    if replay.governance_status == "frozen":
        expected_manifest_hash = exact_hash(artifacts.manifest_bytes)
        if not any(
            event.get("event_type") == "frozen"
            and event.get("run_id") == manifest.get("run_id")
            and event.get("manifest_hash") == expected_manifest_hash
            for event in artifacts.lifecycle_events
        ):
            return _refuse("lifecycle_invalid", ("run_specific_freeze_binding_missing",))

    declarations = {(item["table"], item["field"]): item for item in case["payload"]["field_declarations"]}
    patch = validate_patch_bytes(artifacts.raw_output_bytes, case["payload"]["ledger"], declarations, case["profile"])
    resolution = authorization_input
    graded = grade_patch_v14(
        patch, case["payload"]["ledger"],
        resolution["eligible_keys"], resolution["required_final_values"],
    )
    provenance = {
        "case_exact_hash": case_hash,
        "authorization_input_hash": input_hash,
        "review_submission_hashes": sorted(review_hashes),
        "final_authorization_sidecar_hash": exact_hash(artifacts.sidecar_bytes),
        "reference_hash": reference_hash,
        "adjudication_hash": checked_adjudication.adjudication_hash,
        "approval_event_hash": replay.approval_event_hash,
        "reference_governance_status": replay.governance_status,
        "raw_output_hash": exact_hash(artifacts.raw_output_bytes),
        "prompt_hash": manifest["prompt_hash"],
        "configuration_hash": manifest["configuration_hash"],
        "grader_version": "acac-grader-1.4",
    }
    if replay.governance_status == "frozen":
        provenance["freeze_event_hash"] = replay.freeze_event_hash
    result = {
        "schema_version": "acac-1.4",
        "case_id": case["case_id"],
        "run_id": manifest["run_id"],
        "contract_valid": graded["contract_valid"],
        "exact_edit_set_valid": graded["exact_edit_set_valid"],
        "metrics": graded["metrics"],
        "diagnostics": graded["diagnostics"],
        "provenance": provenance,
    }
    try:
        validate_result_v14(result)
    except Exception as exc:
        return _refuse("malformed_artifact", ("result_schema_invalid", str(exc)))
    return CoordinatorResult(result, None, (), graded["aggregate_contribution"])
