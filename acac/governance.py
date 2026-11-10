"""Reference approval and freeze gates for V1 aggregation."""
from dataclasses import dataclass
from .lifecycle import replay, replay_v1


class GovernanceError(ValueError):
    pass


@dataclass(frozen=True)
class GovernanceDecision:
    status: str
    eligible: bool
    reason: str | None = None


def evaluate_reference(*, events: list[dict], sidecar_status: str, source_hash_valid: bool, reference_hash_valid: bool, temporal_gate: bool, run_id: str | None = None, manifest_hash: str | None = None, freeze_binding: dict | None = None) -> GovernanceDecision:
    status = replay(events)
    if status not in {"approved", "frozen"}:
        return GovernanceDecision(status, False, "lifecycle_not_approved")
    if sidecar_status != "resolved":
        return GovernanceDecision(status, False, "authorization_unresolved")
    if not source_hash_valid or not reference_hash_valid:
        return GovernanceDecision(status, False, "hash_invalid")
    if not temporal_gate:
        return GovernanceDecision(status, False, "temporal_gate_failed")
    if status == "frozen":
        if not run_id or not manifest_hash or not freeze_binding or freeze_binding.get("run_id") != run_id or freeze_binding.get("manifest_hash") != manifest_hash:
            return GovernanceDecision(status, False, "freeze_binding_invalid")
    return GovernanceDecision("approved_unfrozen" if status == "approved" else "frozen", True)


def evaluate_v1_reference(*, events: list[dict], event_bytes: list[bytes], event_hashes: list[str], reference_id: str, reference_author_id: str, configured_approver_id: str | None, sidecar_status: str, source_hash_valid: bool, authorization_hash_valid: bool, reference_hash_valid: bool, temporal_gate: bool, retained_artifacts: dict[str, bytes] | None = None, run_id: str | None = None, manifest_hash: str | None = None) -> GovernanceDecision:
    """Evaluate v1 eligibility from validated lifecycle/artifact evidence."""
    try:
        status = replay_v1(events, event_bytes, event_hashes, reference_id=reference_id, retained_artifacts=retained_artifacts)
    except ValueError as exc:
        return GovernanceDecision("invalid", False, str(exc))
    if status not in {"approved", "frozen"}:
        return GovernanceDecision(status, False, "lifecycle_not_approved")
    if sidecar_status != "resolved":
        return GovernanceDecision(status, False, "authorization_unresolved")
    if not source_hash_valid or not authorization_hash_valid or not reference_hash_valid:
        return GovernanceDecision(status, False, "hash_invalid")
    if not temporal_gate:
        return GovernanceDecision(status, False, "temporal_gate_failed")
    if not configured_approver_id:
        return GovernanceDecision(status, False, "owner_approver_not_configured")
    approvals = [event for event in events if event["event_type"] == "approved"]
    if not approvals or approvals[-1]["actor"]["actor_id"] != configured_approver_id:
        return GovernanceDecision(status, False, "configured_approver_mismatch")
    if configured_approver_id == reference_author_id:
        return GovernanceDecision(status, False, "approver_is_reference_author")
    if status == "frozen":
        freezes = [event for event in events if event["event_type"] == "frozen"]
        if not run_id or not manifest_hash or not any(event.get("run_id") == run_id and event.get("manifest_hash") == manifest_hash for event in freezes):
            return GovernanceDecision(status, False, "freeze_binding_invalid")
    return GovernanceDecision("approved_unfrozen" if status == "approved" else "frozen", True)
