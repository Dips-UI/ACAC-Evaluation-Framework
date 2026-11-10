"""Synthetic v1.4 lifecycle-chain tests."""

import hashlib
import unittest

from acac.lifecycle_v14 import replay_lifecycle_v14
from tests.test_references_v14 import build_chain, stored


def hash_bytes(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_events(chain, *, author_id="author-1", approver_id="owner-approver", freeze=False):
    case_value, case_bytes, auth, auth_bytes, reference, reference_bytes, sidecar, sidecar_bytes, reviews = chain
    review_hash, (review, review_bytes) = next(iter(reviews.items()))
    input_hash = hash_bytes(auth_bytes)
    sidecar_hash = hash_bytes(sidecar_bytes)
    adjudication = {
        "review_id": "adjudication-1", "case_id": case_value["case_id"],
        "reviewer_role": "adjudicator", "source_case_hash": hash_bytes(case_bytes),
        "authorization_input_hash": input_hash, "reference_id": reference["reference_id"],
        "reference_revision": reference["revision"],
        "reference_content_hash": hash_bytes(reference_bytes),
        "considered_review_hashes": [review_hash], "disagreement_disposition": [{"review_id": review["review_id"], "decision": "accepted"}],
        "decision_rationale": "Synthetic adjudication", "exception_decisions": [], "adjudicator_id": "adjudicator-1",
        "independence_declaration": True, "independence_basis": "Synthetic basis",
        "completed_at": "2026-10-31T12:00:00Z",
    }
    adjudication_bytes = stored(adjudication)
    adjudication_hash = hash_bytes(adjudication_bytes)
    reference_hash = hash_bytes(reference_bytes)
    events = []
    retained = {
        hash_bytes(case_bytes): case_bytes, input_hash: auth_bytes,
        sidecar_hash: sidecar_bytes, reference_hash: reference_bytes,
        review_hash: review_bytes, adjudication_hash: adjudication_bytes,
    }
    previous = ""

    def append(event_type, actor_id, role, evidence, extras=None):
        nonlocal previous
        event = {
            "event_schema_version": "acac-lifecycle-1.1",
            "event_id": f"event-{len(events) + 1}", "reference_id": reference["reference_id"],
            "reference_revision": reference["revision"], "reference_content_hash": reference_hash,
            "sequence": len(events) + 1, "event_type": event_type,
            "actor": {"actor_id": actor_id, "role": role},
            "occurred_at": "2026-10-31T13:00:00Z", "evidence_hashes": list(evidence),
            "reason": "Synthetic lifecycle evidence", "previous_event_hash": previous,
        }
        if extras:
            event.update(extras)
        raw = stored(event)
        previous = hash_bytes(raw)
        events.append((event, raw, previous))

    append("created", author_id, "reference_author", [])
    append("reviewed", "reviewer-1", "human_reviewer", [review_hash])
    append("adjudicated", "adjudicator-1", "adjudicator", [adjudication_hash, review_hash])
    approval_hashes = [input_hash, sidecar_hash, review_hash, adjudication_hash, reference_hash]
    append("approved", approver_id, "approver", approval_hashes, {
        "authorization_input_hash": input_hash,
        "final_authorization_sidecar_hash": sidecar_hash,
        "review_submission_hashes": [review_hash],
        "adjudication_hash": adjudication_hash,
        "approved_reference_hash": reference_hash,
    })
    if freeze:
        manifest = stored({
            "manifest_version": "1.4", "run_id": "run-1",
            "created_at": "2026-10-31T12:59:59Z",
        })
        manifest_hash = hash_bytes(manifest)
        retained[manifest_hash] = manifest
        append("frozen", approver_id, "approver", [manifest_hash], {"run_id": "run-1", "manifest_hash": manifest_hash})
    return [x[0] for x in events], [x[1] for x in events], [x[2] for x in events], retained


def replay(chain, **kwargs):
    case_value, case_bytes, auth, auth_bytes, reference, reference_bytes, *_ = chain
    events, raw, hashes, retained = build_events(chain, **kwargs)
    approver_id = kwargs.get("approver_id", "owner-approver")
    return replay_lifecycle_v14(
        events, raw, hashes, reference=reference, reference_bytes=reference_bytes,
        reference_author_id="author-1", configured_approver_id=approver_id,
        retained_artifacts=retained,
    ), events, raw, hashes, retained


def append_superseded(events, raw, hashes, retained, old_reference, replacement, *,
                      replacement_revision=None, replacement_case_id=None):
    replacement_value = dict(replacement[4])
    replacement_value["reference_id"] = "ref-2"
    replacement_value["revision"] = 2 if replacement_revision is None else replacement_revision
    replacement_value["case_id"] = old_reference["case_id"] if replacement_case_id is None else replacement_case_id
    replacement_bytes = stored(replacement_value)
    replacement_hash = hash_bytes(replacement_bytes)
    retained[replacement_hash] = replacement_bytes
    previous = hashes[-1]
    event = {
        "event_schema_version": "acac-lifecycle-1.1",
        "event_id": f"event-{len(events) + 1}", "reference_id": old_reference["reference_id"],
        "reference_revision": old_reference["revision"],
        "reference_content_hash": hash_bytes(stored(old_reference)),
        "sequence": len(events) + 1, "event_type": "superseded",
        "actor": {"actor_id": "owner-approver", "role": "approver"},
        "occurred_at": "2026-10-31T14:00:00Z", "evidence_hashes": [replacement_hash],
        "reason": "Synthetic replacement revision", "previous_event_hash": previous,
        "replacement_reference_id": replacement_value["reference_id"],
        "replacement_reference_hash": replacement_hash,
    }
    event_bytes = stored(event)
    events.append(event)
    raw.append(event_bytes)
    hashes.append(hash_bytes(event_bytes))
    return replacement_value, replacement_bytes


class LifecycleV14Tests(unittest.TestCase):
    def test_approved_chain_binds_typed_artifact_hashes(self):
        result, *_ = replay(build_chain())
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.status, "approved")
        self.assertEqual(result.governance_status, "approved_unfrozen")

    def test_frozen_chain_has_distinct_governance_status(self):
        result, *_ = replay(build_chain(), freeze=True)
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.governance_status, "frozen")
        self.assertTrue(result.freeze_event_hash.startswith("sha256:"))

    def test_freeze_timestamp_must_follow_completed_manifest(self):
        chain = build_chain()
        result, events, raw, hashes, retained = replay(chain, freeze=True)
        self.assertTrue(result.valid, result.errors)
        events[-1]["occurred_at"] = "2026-10-31T12:59:59Z"
        raw[-1] = stored(events[-1])
        hashes[-1] = hash_bytes(raw[-1])
        result = replay_lifecycle_v14(
            events, raw, hashes, reference=chain[4], reference_bytes=chain[5],
            reference_author_id="author-1", configured_approver_id="owner-approver",
            retained_artifacts=retained,
        )
        self.assertFalse(result.valid)
        self.assertIn("freeze_must_follow_completed_manifest", result.errors)

    def test_approval_evidence_must_equal_typed_bindings(self):
        result, events, raw, hashes, retained = replay(build_chain())
        events[-1]["authorization_input_hash"] = "sha256:" + "0" * 64
        raw[-1] = stored(events[-1])
        hashes[-1] = hash_bytes(raw[-1])
        events[-1]["previous_event_hash"] = hashes[-2]
        raw[-1] = stored(events[-1])
        hashes[-1] = hash_bytes(raw[-1])
        result = replay_lifecycle_v14(
            events, raw, hashes, reference=build_chain()[4], reference_bytes=stored(build_chain()[4]),
            reference_author_id="author-1", configured_approver_id="owner-approver", retained_artifacts=retained,
        )
        self.assertFalse(result.valid)
        self.assertIn("approval_evidence_binding_mismatch", result.errors)

    def test_configured_approver_cannot_be_reference_author(self):
        result, *_ = replay(build_chain(), approver_id="author-1")
        self.assertFalse(result.valid)
        self.assertIn("approver_is_reference_author", result.errors)

    def test_supersession_preserves_previously_frozen_run_eligibility(self):
        chain = build_chain()
        result, events, raw, hashes, retained = replay(chain, freeze=True)
        self.assertTrue(result.valid, result.errors)
        replacement = build_chain(case_id=chain[0]["case_id"], reference_id="ref-2", revision=2,
                                  input_revision_note="Fresh revision resolution")
        append_superseded(events, raw, hashes, retained, chain[4], replacement)
        replayed = replay_lifecycle_v14(
            events, raw, hashes, reference=chain[4], reference_bytes=chain[5],
            reference_author_id="author-1", configured_approver_id="owner-approver",
            retained_artifacts=retained,
        )
        self.assertTrue(replayed.valid, replayed.errors)
        self.assertEqual(replayed.status, "superseded")
        self.assertEqual(replayed.governance_status, "frozen")

    def test_supersession_requires_same_case_and_next_revision(self):
        for kwargs, expected_error in (
            ({"replacement_revision": 3}, "replacement_reference_revision_mismatch"),
            ({"replacement_case_id": "different-case"}, "replacement_reference_case_mismatch"),
        ):
            with self.subTest(kwargs=kwargs):
                chain = build_chain()
                _, events, raw, hashes, retained = replay(chain, freeze=True)
                replacement = build_chain(case_id=chain[0]["case_id"], reference_id="ref-2", revision=2)
                append_superseded(events, raw, hashes, retained, chain[4], replacement, **kwargs)
                replayed = replay_lifecycle_v14(
                    events, raw, hashes, reference=chain[4], reference_bytes=chain[5],
                    reference_author_id="author-1", configured_approver_id="owner-approver",
                    retained_artifacts=retained,
                )
                self.assertFalse(replayed.valid)
                self.assertIn(expected_error, replayed.errors)


if __name__ == "__main__":
    unittest.main()
