import unittest
import json
from acac.lifecycle import replay, replay_v1, validate_transition, validate_event, validate_v1_event
from acac.canonical import exact_hash


class LifecycleTests(unittest.TestCase):
    def test_allowed_graph_and_terminal_states(self):
        validate_transition("created", "reviewed")
        validate_transition("approved", "quarantined")
        validate_transition("frozen", "frozen")
        with self.assertRaises(ValueError): validate_transition("created", "approved")

    def test_replay_checks_sequence_and_chain(self):
        events = [{"sequence": 1, "previous_event_hash": "", "event": "reviewed", "event_hash": "h1"}, {"sequence": 2, "previous_event_hash": "h1", "event": "adjudicated", "event_hash": "h2"}]
        self.assertEqual(replay(events), "adjudicated")
        with self.assertRaises(ValueError): replay([{**events[0], "sequence": 2}])

    def test_event_schema_chain_fields(self):
        validate_event({"event_id": "e1", "reference_id": "ref", "sequence": 1, "previous_event_hash": "", "event": "reviewed", "actor_id": "human", "actor_role": "reviewer", "evidence": ["sha256:" + "0" * 64]}, reference_id="ref", expected_previous_hash="", expected_sequence=1)

    def test_v1_event_schema_and_conditional_fields(self):
        event = {"event_schema_version": "acac-lifecycle-1.0", "event_id": "e1", "reference_id": "ref", "reference_content_hash": "sha256:" + "0" * 64, "sequence": 1, "event_type": "created", "actor": {"actor_id": "author", "role": "reference_author"}, "occurred_at": "2026-01-01T00:00:00Z", "evidence_hashes": [], "reason": "created", "previous_event_hash": ""}
        validate_v1_event(event, reference_id="ref", expected_previous_hash="", expected_sequence=1)
        event["run_id"] = "run-1"
        with self.assertRaisesRegex(ValueError, "conditional"):
            validate_v1_event(event, reference_id="ref", expected_previous_hash="", expected_sequence=1)

    def test_v1_frozen_event_requires_manifest_binding(self):
        event = {"event_schema_version": "acac-lifecycle-1.0", "event_id": "e1", "reference_id": "ref", "reference_content_hash": "sha256:" + "0" * 64, "sequence": 1, "event_type": "frozen", "actor": {"actor_id": "owner", "role": "approver"}, "occurred_at": "2026-01-01T00:00:00Z", "evidence_hashes": ["sha256:" + "1" * 64], "reason": "frozen", "previous_event_hash": "", "run_id": "run-1", "manifest_hash": "sha256:" + "2" * 64}
        validate_v1_event(event, reference_id="ref", expected_previous_hash="", expected_sequence=1)

    def test_v1_replay_requires_exact_retained_reference_bytes(self):
        reference = json.dumps({"reference_id": "ref"}, separators=(",", ":")).encode()
        reference_hash = exact_hash(reference)
        event = {"event_schema_version": "acac-lifecycle-1.0", "event_id": "e1", "reference_id": "ref", "reference_content_hash": reference_hash, "sequence": 1, "event_type": "created", "actor": {"actor_id": "author", "role": "reference_author"}, "occurred_at": "2026-01-01T00:00:00Z", "evidence_hashes": [], "reason": "created", "previous_event_hash": ""}
        raw = json.dumps(event, separators=(",", ":")).encode()
        digest = exact_hash(raw)
        with self.assertRaisesRegex(ValueError, "retained_lifecycle_artifacts_required"):
            replay_v1([event], [raw], [digest], reference_id="ref")
        self.assertEqual(replay_v1([event], [raw], [digest], reference_id="ref", retained_artifacts={reference_hash: reference}), "created")
        with self.assertRaisesRegex(ValueError, "reference_content_artifact_mismatch"):
            replay_v1([event], [raw], [digest], reference_id="ref", retained_artifacts={reference_hash: b"replacement"})

    def test_v1_replay_rejects_reference_bytes_for_another_identity(self):
        reference = json.dumps({"reference_id": "other-ref"}, separators=(",", ":")).encode()
        reference_hash = exact_hash(reference)
        event = {"event_schema_version": "acac-lifecycle-1.0", "event_id": "e1", "reference_id": "ref", "reference_content_hash": reference_hash, "sequence": 1, "event_type": "created", "actor": {"actor_id": "author", "role": "reference_author"}, "occurred_at": "2026-01-01T00:00:00Z", "evidence_hashes": [], "reason": "created", "previous_event_hash": ""}
        raw = json.dumps(event, separators=(",", ":")).encode()
        digest = exact_hash(raw)
        with self.assertRaisesRegex(ValueError, "reference_content_identity_mismatch"):
            replay_v1([event], [raw], [digest], reference_id="ref", retained_artifacts={reference_hash: reference})


if __name__ == "__main__": unittest.main()
