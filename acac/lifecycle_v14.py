"""ACAC v1.4 lifecycle 1.1 event validation and exact-byte replay."""

from dataclasses import dataclass
from typing import Any

from .canonical import exact_hash
from .strict_json import is_integer, loads_bytes, parse_rfc3339_timestamp


class LifecycleV14Error(ValueError):
    pass


@dataclass(frozen=True)
class LifecycleReplayResult:
    valid: bool
    status: str | None
    governance_status: str | None
    approval_event_hash: str | None
    freeze_event_hash: str | None
    errors: tuple[str, ...]


_TYPES = {"created", "reviewed", "adjudicated", "approved", "frozen", "superseded", "ambiguous", "quarantined"}
_ROLES = {"reference_author", "human_reviewer", "adjudicator", "approver"}
_TRANSITIONS = {
    "created": {"reviewed", "ambiguous", "quarantined"},
    "reviewed": {"adjudicated", "ambiguous", "quarantined"},
    "adjudicated": {"approved", "ambiguous", "quarantined"},
    "approved": {"frozen", "superseded", "quarantined"},
    "frozen": {"frozen", "superseded", "quarantined"},
    "ambiguous": set(), "quarantined": set(), "superseded": set(),
}
_COMMON = {
    "event_schema_version", "event_id", "reference_id", "reference_revision",
    "reference_content_hash", "sequence", "event_type", "actor", "occurred_at",
    "evidence_hashes", "reason", "previous_event_hash",
}
_APPROVAL = {
    "authorization_input_hash", "final_authorization_sidecar_hash",
    "review_submission_hashes", "adjudication_hash", "approved_reference_hash",
}


def _hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise LifecycleV14Error(f"invalid_{label}")


def _id(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise LifecycleV14Error(f"invalid_{label}")


def _same_json_value(left: Any, right: Any) -> bool:
    if isinstance(left, dict) or isinstance(right, dict):
        return isinstance(left, dict) and isinstance(right, dict) and set(left) == set(right) and all(_same_json_value(left[k], right[k]) for k in left)
    if isinstance(left, list) or isinstance(right, list):
        return isinstance(left, list) and isinstance(right, list) and len(left) == len(right) and all(_same_json_value(a, b) for a, b in zip(left, right))
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left is right
    if is_integer(left) or is_integer(right):
        return is_integer(left) and is_integer(right) and int(left) == int(right)
    return type(left) is type(right) and left == right


def _event_shape(event: Any, *, reference_id: str, reference_revision: int, expected_sequence: int, previous_hash: str) -> None:
    if not isinstance(event, dict) or any(not isinstance(key, str) for key in event):
        raise LifecycleV14Error("event_object_required")
    event_type = event.get("event_type")
    allowed = set(_COMMON)
    if event_type == "approved":
        allowed |= _APPROVAL
    elif event_type == "frozen":
        allowed |= {"run_id", "manifest_hash"}
    elif event_type == "superseded":
        allowed |= {"replacement_reference_id", "replacement_reference_hash"}
    if set(event) != allowed:
        raise LifecycleV14Error("lifecycle_event_members")
    if event["event_schema_version"] != "acac-lifecycle-1.1" or event_type not in _TYPES:
        raise LifecycleV14Error("lifecycle_event_version_or_type")
    if event["reference_id"] != reference_id or event["reference_revision"] != reference_revision:
        raise LifecycleV14Error("lifecycle_reference_identity_mismatch")
    if not is_integer(event["reference_revision"]) or int(event["reference_revision"]) <= 0:
        raise LifecycleV14Error("invalid_reference_revision")
    if not is_integer(event["sequence"]) or int(event["sequence"]) != expected_sequence:
        raise LifecycleV14Error("lifecycle_sequence_mismatch")
    if event["previous_event_hash"] != previous_hash:
        raise LifecycleV14Error("lifecycle_previous_hash_mismatch")
    for name in ("event_id", "reference_id"):
        _id(event[name], name)
    _hash(event["reference_content_hash"], "reference_content_hash")
    if not isinstance(event["actor"], dict) or set(event["actor"]) != {"actor_id", "role"}:
        raise LifecycleV14Error("lifecycle_actor_shape")
    _id(event["actor"]["actor_id"], "actor_id")
    if event["actor"]["role"] not in _ROLES:
        raise LifecycleV14Error("lifecycle_actor_role")
    role_by_type = {
        "created": {"reference_author"}, "reviewed": {"human_reviewer"},
        "adjudicated": {"adjudicator"}, "approved": {"approver"},
        "frozen": {"approver"}, "superseded": {"approver"},
        "ambiguous": {"human_reviewer", "adjudicator"},
        "quarantined": {"human_reviewer", "adjudicator"},
    }
    if event["actor"]["role"] not in role_by_type[event_type]:
        raise LifecycleV14Error("lifecycle_actor_role_mismatch")
    parse_rfc3339_timestamp(event["occurred_at"])
    if not isinstance(event["reason"], str) or not event["reason"].strip():
        raise LifecycleV14Error("lifecycle_reason_required")
    evidence = event["evidence_hashes"]
    if not isinstance(evidence, list):
        raise LifecycleV14Error("lifecycle_evidence_hashes_required")
    for digest in evidence:
        _hash(digest, "evidence_hash")
    if len(evidence) != len(set(evidence)):
        raise LifecycleV14Error("duplicate_lifecycle_evidence_hash")
    if event_type in {"reviewed", "adjudicated", "approved", "frozen", "superseded"} and not evidence:
        raise LifecycleV14Error("event_specific_evidence_required")
    if expected_sequence == 1 and previous_hash != "":
        raise LifecycleV14Error("first_event_previous_hash_must_be_empty")
    if expected_sequence > 1:
        _hash(previous_hash, "previous_event_hash")
    if event_type == "approved":
        for name in ("authorization_input_hash", "final_authorization_sidecar_hash", "adjudication_hash", "approved_reference_hash"):
            _hash(event[name], name)
        reviews = event["review_submission_hashes"]
        if not isinstance(reviews, list) or not reviews:
            raise LifecycleV14Error("approval_review_hashes_required")
        for digest in reviews:
            _hash(digest, "review_submission_hash")
        if len(reviews) != len(set(reviews)):
            raise LifecycleV14Error("duplicate_approval_review_hash")
        if event["approved_reference_hash"] != event["reference_content_hash"]:
            raise LifecycleV14Error("approved_reference_hash_mismatch")
        typed_hashes = [event["authorization_input_hash"], event["final_authorization_sidecar_hash"], *reviews, event["adjudication_hash"], event["approved_reference_hash"]]
        if len(typed_hashes) != len(set(typed_hashes)) or set(typed_hashes) != set(evidence):
            raise LifecycleV14Error("approval_evidence_binding_mismatch")
    elif event_type == "frozen":
        _id(event["run_id"], "run_id")
        _hash(event["manifest_hash"], "manifest_hash")
        if event["manifest_hash"] not in evidence:
            raise LifecycleV14Error("freeze_manifest_evidence_required")
    elif event_type == "superseded":
        _id(event["replacement_reference_id"], "replacement_reference_id")
        _hash(event["replacement_reference_hash"], "replacement_reference_hash")
        if event["replacement_reference_id"] == reference_id:
            raise LifecycleV14Error("self_supersession")


def replay_lifecycle_v14(
    events: list[dict],
    event_bytes: list[bytes],
    event_hashes: list[str],
    *,
    reference: dict,
    reference_bytes: bytes,
    reference_author_id: str,
    configured_approver_id: str,
    retained_artifacts: dict[str, bytes],
) -> LifecycleReplayResult:
    """Replay a reference-specific v1.4 event chain and verify exact bindings."""
    status = None
    try:
        if not isinstance(reference, dict) or not isinstance(reference_bytes, bytes) or not isinstance(retained_artifacts, dict):
            raise LifecycleV14Error("lifecycle_artifact_inputs_required")
        if not _same_json_value(loads_bytes(reference_bytes), reference):
            raise LifecycleV14Error("reference_content_bytes_mismatch")
        reference_id = reference.get("reference_id")
        revision = reference.get("revision")
        if not isinstance(reference_id, str) or not is_integer(revision) or int(revision) <= 0:
            raise LifecycleV14Error("reference_identity_required")
        reference_hash = exact_hash(reference_bytes)
        if not isinstance(events, list) or not events or not isinstance(event_bytes, list) or not isinstance(event_hashes, list) or not (len(events) == len(event_bytes) == len(event_hashes)):
            raise LifecycleV14Error("lifecycle_event_artifacts_required")
        _id(reference_author_id, "reference_author_id")
        _id(configured_approver_id, "configured_approver_id")
        previous_hash = ""
        seen_ids: set[str] = set()
        approvals: list[str] = []
        freezes: list[str] = []
        reviewed_hashes: set[str] = set()
        adjudication_hashes: set[str] = set()
        author = reference.get("author")
        if not isinstance(author, dict) or author.get("author_id") != reference_author_id:
            raise LifecycleV14Error("reference_author_identity_mismatch")
        for index, (event, raw, recorded_hash) in enumerate(zip(events, event_bytes, event_hashes), 1):
            _event_shape(event, reference_id=reference_id, reference_revision=int(revision), expected_sequence=index, previous_hash=previous_hash)
            if event["reference_content_hash"] != reference_hash:
                raise LifecycleV14Error("lifecycle_reference_hash_mismatch")
            if not isinstance(raw, bytes) or exact_hash(raw) != recorded_hash:
                raise LifecycleV14Error("lifecycle_event_hash_mismatch")
            _hash(recorded_hash, "lifecycle_event_hash")
            if not _same_json_value(loads_bytes(raw), event):
                raise LifecycleV14Error("lifecycle_event_bytes_mismatch")
            if event["event_id"] in seen_ids:
                raise LifecycleV14Error("duplicate_lifecycle_event_id")
            seen_ids.add(event["event_id"])
            event_type = event["event_type"]
            if event_type == "created" and event["actor"]["actor_id"] != reference_author_id:
                raise LifecycleV14Error("created_actor_reference_author_mismatch")
            if status is None:
                if event_type != "created":
                    raise LifecycleV14Error("lifecycle_must_start_created")
            elif event_type not in _TRANSITIONS.get(status, set()):
                raise LifecycleV14Error("illegal_lifecycle_transition")
            for digest in event["evidence_hashes"]:
                evidence = retained_artifacts.get(digest)
                if not isinstance(evidence, bytes) or exact_hash(evidence) != digest:
                    raise LifecycleV14Error("lifecycle_evidence_hash_mismatch")
            parsed_evidence: dict[str, Any] = {}
            for digest in event["evidence_hashes"]:
                try:
                    parsed_evidence[digest] = loads_bytes(retained_artifacts[digest])
                except Exception:
                    continue
            if event_type == "reviewed":
                matching = {digest for digest, artifact in parsed_evidence.items() if isinstance(artifact, dict) and artifact.get("reviewer_role") == "human_reviewer"}
                if not matching:
                    raise LifecycleV14Error("human_review_evidence_required")
                if not any(parsed_evidence[digest].get("reviewer_id") == event["actor"]["actor_id"] for digest in matching):
                    raise LifecycleV14Error("reviewed_actor_evidence_mismatch")
                reviewed_hashes.update(matching)
            if event_type == "adjudicated":
                matches = {digest: artifact for digest, artifact in parsed_evidence.items() if isinstance(artifact, dict) and artifact.get("reviewer_role") == "adjudicator"}
                if len(matches) != 1:
                    raise LifecycleV14Error("adjudication_evidence_required")
                adjudication_hash, adjudication = next(iter(matches.items()))
                if adjudication.get("adjudicator_id") != event["actor"]["actor_id"]:
                    raise LifecycleV14Error("adjudicated_actor_evidence_mismatch")
                considered = adjudication.get("considered_review_hashes")
                if not isinstance(considered, list) or any(item not in event["evidence_hashes"] for item in considered):
                    raise LifecycleV14Error("adjudication_review_evidence_missing")
                adjudication_hashes.add(adjudication_hash)
            if event_type == "approved":
                if event["actor"]["actor_id"] != configured_approver_id:
                    raise LifecycleV14Error("configured_approver_mismatch")
                if configured_approver_id == reference_author_id:
                    raise LifecycleV14Error("approver_is_reference_author")
                if event["authorization_input_hash"] != reference.get("authorization_input_hash"):
                    raise LifecycleV14Error("approval_input_reference_mismatch")
                try:
                    sidecar = loads_bytes(retained_artifacts[event["final_authorization_sidecar_hash"]])
                except Exception as exc:
                    raise LifecycleV14Error("approval_sidecar_artifact_invalid") from exc
                if not isinstance(sidecar, dict) or sidecar.get("authorization_input_hash") != event["authorization_input_hash"]:
                    raise LifecycleV14Error("approval_sidecar_input_mismatch")
                adjudication = parsed_evidence.get(event["adjudication_hash"])
                if not isinstance(adjudication, dict) or adjudication.get("reference_content_hash") != reference_hash or adjudication.get("authorization_input_hash") != event["authorization_input_hash"]:
                    raise LifecycleV14Error("approval_adjudication_binding_mismatch")
                if not set(event["review_submission_hashes"]) <= reviewed_hashes:
                    raise LifecycleV14Error("approved_review_event_evidence_missing")
                if event["adjudication_hash"] not in adjudication_hashes:
                    raise LifecycleV14Error("approved_adjudication_event_evidence_missing")
                approvals.append(recorded_hash)
            if event_type == "frozen":
                manifest = retained_artifacts.get(event["manifest_hash"])
                if not isinstance(manifest, bytes) or exact_hash(manifest) != event["manifest_hash"]:
                    raise LifecycleV14Error("freeze_manifest_hash_mismatch")
                try:
                    manifest_value = loads_bytes(manifest)
                    manifest_created = parse_rfc3339_timestamp(manifest_value["created_at"])
                    freeze_recorded = parse_rfc3339_timestamp(event["occurred_at"])
                except Exception as exc:
                    raise LifecycleV14Error("freeze_completed_manifest_required") from exc
                if not isinstance(manifest_value, dict) or manifest_value.get("run_id") != event["run_id"]:
                    raise LifecycleV14Error("freeze_manifest_run_mismatch")
                if freeze_recorded.instant <= manifest_created.instant:
                    raise LifecycleV14Error("freeze_must_follow_completed_manifest")
                freezes.append(recorded_hash)
            if event_type == "superseded":
                replacement = retained_artifacts.get(event["replacement_reference_hash"])
                if not isinstance(replacement, bytes) or exact_hash(replacement) != event["replacement_reference_hash"]:
                    raise LifecycleV14Error("replacement_reference_hash_mismatch")
                replacement_value = loads_bytes(replacement)
                if not isinstance(replacement_value, dict) or replacement_value.get("reference_id") != event["replacement_reference_id"]:
                    raise LifecycleV14Error("replacement_reference_identity_mismatch")
                if replacement_value.get("case_id") != reference.get("case_id"):
                    raise LifecycleV14Error("replacement_reference_case_mismatch")
                replacement_revision = replacement_value.get("revision")
                if not is_integer(replacement_revision) or int(replacement_revision) != int(revision) + 1:
                    raise LifecycleV14Error("replacement_reference_revision_mismatch")
            status = event_type
            previous_hash = recorded_hash
        # Supersession prevents new run bindings, while the specification keeps
        # already-frozen runs valid. The coordinator still checks the exact
        # run ID and manifest hash against a prior frozen event.
        governance = (
            "approved_unfrozen" if status == "approved"
            else ("frozen" if status == "frozen" or (status == "superseded" and freezes) else None)
        )
        return LifecycleReplayResult(True, status, governance, approvals[-1] if approvals else None, freezes[-1] if freezes else None, ())
    except Exception as exc:
        return LifecycleReplayResult(False, status, None, None, None, (str(exc),))
