"""Append-only reference lifecycle transition validation."""

TRANSITIONS = {
    "created": {"reviewed", "ambiguous", "quarantined"},
    "reviewed": {"adjudicated", "ambiguous", "quarantined"},
    "adjudicated": {"approved", "ambiguous", "quarantined"},
    "approved": {"frozen", "superseded", "quarantined"},
    "frozen": {"frozen", "superseded", "quarantined"},
}

from .canonical import exact_hash
from .strict_json import loads_bytes, parse_rfc3339_timestamp
from .review_records import validate_human_review
from .adjudication import validate_adjudication, validate_ai_audit


def event_hash(event_bytes: bytes) -> str:
    return exact_hash(event_bytes)


def validate_event(event: dict, *, reference_id: str, expected_previous_hash: str, expected_sequence: int) -> None:
    required = {"event_id", "reference_id", "sequence", "previous_event_hash", "event", "actor_id", "actor_role", "evidence"}
    if not isinstance(event, dict) or set(event) != required:
        raise ValueError("lifecycle_event_members")
    if event["reference_id"] != reference_id or event["sequence"] != expected_sequence or event["previous_event_hash"] != expected_previous_hash:
        raise ValueError("lifecycle_event_chain")
    if event["event"] not in {target for targets in TRANSITIONS.values() for target in targets}:
        raise ValueError("lifecycle_event_type")
    if not isinstance(event["evidence"], list):
        raise ValueError("lifecycle_evidence_required")
    if event["event"] in {"reviewed", "adjudicated", "approved", "frozen", "quarantined", "superseded"} and not event["evidence"]:
        raise ValueError("event_specific_evidence_required")
    if event["actor_role"] not in {"reviewer", "adjudicator", "approver", "system", "owner"}:
        raise ValueError("invalid_actor_role")


def validate_transition(previous: str, next_status: str) -> None:
    if next_status not in TRANSITIONS.get(previous, set()):
        raise ValueError("illegal_lifecycle_transition")


def replay(events: list[dict]) -> str:
    status = "created"
    expected_sequence = 1
    previous_hash = ""
    for event in events:
        if event.get("sequence") != expected_sequence or event.get("previous_event_hash", "") != previous_hash:
            raise ValueError("invalid_lifecycle_chain")
        validate_transition(status, event.get("event"))
        status = event["event"]
        previous_hash = event.get("event_hash", "")
        expected_sequence += 1
    return status


V1_EVENT_TYPES = {"created", "reviewed", "adjudicated", "approved", "frozen", "superseded", "ambiguous", "quarantined"}
V1_ACTOR_ROLES = {"reference_author", "human_reviewer", "adjudicator", "approver"}


def validate_v1_event(event: dict, *, reference_id: str, expected_previous_hash: str, expected_sequence: int) -> None:
    """Validate an ``acac-lifecycle-1.0`` event without mutating artifacts."""
    required = {"event_schema_version", "event_id", "reference_id", "reference_content_hash", "sequence", "event_type", "actor", "occurred_at", "evidence_hashes", "reason", "previous_event_hash"}
    if not isinstance(event, dict) or set(event) - required - {"replacement_reference_id", "replacement_reference_hash", "run_id", "manifest_hash"} or not required <= set(event):
        raise ValueError("lifecycle_event_members")
    if event["event_schema_version"] != "acac-lifecycle-1.0" or event["reference_id"] != reference_id:
        raise ValueError("lifecycle_event_identity")
    if type(event["sequence"]) is not int or event["sequence"] != expected_sequence or event["previous_event_hash"] != expected_previous_hash:
        raise ValueError("lifecycle_event_chain")
    if event["event_type"] not in V1_EVENT_TYPES:
        raise ValueError("lifecycle_event_type")
    actor = event["actor"]
    if not isinstance(actor, dict) or set(actor) != {"actor_id", "role"} or not isinstance(actor["actor_id"], str) or not actor["actor_id"].strip() or actor["actor_id"].strip() != actor["actor_id"] or not actor["actor_id"].isprintable() or actor["role"] not in V1_ACTOR_ROLES:
        raise ValueError("invalid_actor")
    for name in ("event_id", "reference_id"):
        value = event[name]
        if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
            raise ValueError("invalid_lifecycle_identity")
    parse_rfc3339_timestamp(event["occurred_at"])
    if not isinstance(event["evidence_hashes"], list):
        raise ValueError("invalid_evidence_hashes")
    for value in event["evidence_hashes"]: _hash(value, "evidence_hashes")
    if not isinstance(event["reason"], str) or not event["reason"].strip():
        raise ValueError("lifecycle_reason_required")
    expected_roles = {
        "created": {"reference_author"},
        "reviewed": {"human_reviewer"},
        "adjudicated": {"adjudicator"},
        "approved": {"approver"},
        "frozen": {"approver"},
        "superseded": {"approver"},
        "ambiguous": {"human_reviewer", "adjudicator"},
        "quarantined": {"human_reviewer", "adjudicator"},
    }
    if actor["role"] not in expected_roles[event["event_type"]]:
        raise ValueError("event_actor_role_mismatch")
    _hash(event["reference_content_hash"], "reference_content_hash")
    if event["sequence"] == 1 and event["previous_event_hash"] != "":
        raise ValueError("first_event_previous_hash_must_be_empty")
    if event["sequence"] > 1:
        _hash(event["previous_event_hash"], "previous_event_hash")
    if event["event_type"] == "superseded":
        replacement_id = event.get("replacement_reference_id")
        replacement_hash = event.get("replacement_reference_hash")
        if not isinstance(replacement_id, str) or not replacement_id or replacement_id.strip() != replacement_id or not replacement_id.isprintable() or not isinstance(replacement_hash, str):
            raise ValueError("supersession_fields_required")
        _hash(replacement_hash, "replacement_reference_hash")
        if replacement_id == reference_id:
            raise ValueError("self_supersession")
    if event["event_type"] == "superseded":
        if set(event) & {"run_id", "manifest_hash"} or not isinstance(event.get("replacement_reference_id"), str) or not isinstance(event.get("replacement_reference_hash"), str):
            raise ValueError("supersession_fields_required")
    elif event["event_type"] == "frozen":
        if set(event) & {"replacement_reference_id", "replacement_reference_hash"} or not isinstance(event.get("run_id"), str) or not event["run_id"] or event["run_id"].strip() != event["run_id"] or not event["run_id"].isprintable() or not isinstance(event.get("manifest_hash"), str):
            raise ValueError("freeze_fields_required")
    elif set(event) & {"replacement_reference_id", "replacement_reference_hash", "run_id", "manifest_hash"}:
        raise ValueError("conditional_lifecycle_fields_forbidden")
    if event["event_type"] in {"reviewed", "adjudicated", "approved", "frozen", "superseded"} and not event["evidence_hashes"]:
        raise ValueError("event_specific_evidence_required")


def _hash(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise ValueError(label)


def replay_v1(events: list[dict], event_bytes: list[bytes], event_hashes: list[str], *, reference_id: str, retained_artifacts: dict[str, bytes] | None = None) -> str:
    """Replay v1 events and verify linked evidence against retained exact bytes."""
    if not isinstance(events, list) or not isinstance(event_bytes, list) or not isinstance(event_hashes, list) or not (len(events) == len(event_bytes) == len(event_hashes)) or not events:
        raise ValueError("lifecycle_event_artifacts_required")
    if not isinstance(retained_artifacts, dict):
        raise ValueError("retained_lifecycle_artifacts_required")
    status = None
    previous_hash = ""
    event_ids = set()
    for index, (event, raw, recorded_hash) in enumerate(zip(events, event_bytes, event_hashes), 1):
        validate_v1_event(event, reference_id=reference_id, expected_previous_hash=previous_hash, expected_sequence=index)
        reference_bytes = retained_artifacts.get(event["reference_content_hash"])
        if not isinstance(reference_bytes, bytes) or exact_hash(reference_bytes) != event["reference_content_hash"]:
            raise ValueError("reference_content_artifact_mismatch")
        try:
            reference_content = loads_bytes(reference_bytes)
        except Exception as exc:
            raise ValueError("reference_content_artifact_invalid") from exc
        if not isinstance(reference_content, dict) or reference_content.get("reference_id") != reference_id:
            raise ValueError("reference_content_identity_mismatch")
        if not isinstance(raw, bytes) or exact_hash(raw) != recorded_hash:
            raise ValueError("lifecycle_event_hash_mismatch")
        _hash(recorded_hash, "lifecycle_event_hash")
        try:
            if loads_bytes(raw) != event:
                raise ValueError("lifecycle_event_bytes_mismatch")
        except Exception as exc:
            if isinstance(exc, ValueError) and str(exc) == "lifecycle_event_bytes_mismatch":
                raise
            raise ValueError("lifecycle_event_bytes_invalid") from exc
        if event["event_id"] in event_ids:
            raise ValueError("duplicate_lifecycle_event_id")
        event_ids.add(event["event_id"])
        roles = []
        parsed_evidence = {}
        for digest in event["evidence_hashes"]:
            evidence_bytes = retained_artifacts.get(digest)
            if not isinstance(evidence_bytes, bytes) or exact_hash(evidence_bytes) != digest:
                raise ValueError("lifecycle_evidence_hash_mismatch")
            try:
                evidence = loads_bytes(evidence_bytes)
            except Exception:
                continue  # Non-JSON supporting evidence is hash-verified and retained.
            role = evidence.get("reviewer_role") if isinstance(evidence, dict) else None
            if role == "human_reviewer":
                validate_human_review(evidence)
            elif role == "adjudicator":
                validate_adjudication(evidence)
                for considered_hash in evidence["considered_review_hashes"]:
                    if considered_hash not in event["evidence_hashes"]:
                        raise ValueError("adjudication_review_evidence_missing")
            elif role == "ai_auditor":
                validate_ai_audit(evidence)
            if role is not None:
                roles.append(role)
                parsed_evidence[digest] = evidence
        kind = event["event_type"]
        if kind == "reviewed" and "human_reviewer" not in roles:
            raise ValueError("human_review_evidence_required")
        if kind == "adjudicated" and "adjudicator" not in roles:
            raise ValueError("adjudication_evidence_required")
        if kind == "approved" and not ({"human_reviewer", "adjudicator"} <= set(roles)):
            raise ValueError("approval_review_and_adjudication_evidence_required")
        if kind == "frozen":
            manifest_bytes = retained_artifacts.get(event["manifest_hash"])
            if not isinstance(manifest_bytes, bytes) or exact_hash(manifest_bytes) != event["manifest_hash"]:
                raise ValueError("freeze_manifest_hash_mismatch")
        if kind == "superseded":
            replacement_bytes = retained_artifacts.get(event["replacement_reference_hash"])
            if not isinstance(replacement_bytes, bytes) or exact_hash(replacement_bytes) != event["replacement_reference_hash"]:
                raise ValueError("replacement_reference_hash_mismatch")
            try:
                replacement = loads_bytes(replacement_bytes)
            except Exception as exc:
                raise ValueError("replacement_reference_artifact_invalid") from exc
            if not isinstance(replacement, dict) or replacement.get("reference_id") != event["replacement_reference_id"]:
                raise ValueError("replacement_reference_identity_mismatch")
        next_status = event["event_type"]
        if status is None:
            if next_status != "created":
                raise ValueError("lifecycle_must_start_created")
        else:
            validate_transition(status, next_status)
        status = next_status
        previous_hash = recorded_hash
    return status
