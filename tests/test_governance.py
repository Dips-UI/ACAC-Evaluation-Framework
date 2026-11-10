import unittest
import json
import hashlib
from acac.canonical import exact_hash
from acac.governance import evaluate_reference, evaluate_v1_reference


class GovernanceTests(unittest.TestCase):
    def test_approved_and_frozen_gates(self):
        approved = [{"sequence": 1, "previous_event_hash": "", "event": "reviewed", "event_hash": "h1"}, {"sequence": 2, "previous_event_hash": "h1", "event": "adjudicated", "event_hash": "h2"}, {"sequence": 3, "previous_event_hash": "h2", "event": "approved", "event_hash": "h3"}]
        decision = evaluate_reference(events=approved, sidecar_status="resolved", source_hash_valid=True, reference_hash_valid=True, temporal_gate=True)
        self.assertTrue(decision.eligible); self.assertEqual(decision.status, "approved_unfrozen")
        frozen = approved + [{"sequence": 4, "previous_event_hash": "h3", "event": "frozen", "event_hash": "h4"}]
        decision = evaluate_reference(events=frozen, sidecar_status="resolved", source_hash_valid=True, reference_hash_valid=True, temporal_gate=True, run_id="run", manifest_hash="sha256:x", freeze_binding={"run_id": "run", "manifest_hash": "sha256:x"})
        self.assertTrue(decision.eligible)
        self.assertFalse(evaluate_reference(events=frozen, sidecar_status="resolved", source_hash_valid=True, reference_hash_valid=True, temporal_gate=True).eligible)

    def test_v1_governance_uses_verified_chain_and_configured_approver(self):
        reference_bytes = json.dumps({"reference_id": "ref"}, separators=(",", ":")).encode()
        reference_hash = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
        review = {"review_id": "review-1", "case_id": "case-1", "reviewer_id": "reviewer", "reviewer_role": "human_reviewer", "independence_declaration": True, "independence_basis": "separate synthetic review", "source_case_hash": "sha256:" + "a" * 64, "authorization_spec_hash": "sha256:" + "b" * 64, "reference_content_hash": reference_hash, "review_scope": ["case-1"], "eligible_keys": [], "proposed_edits": [], "ambiguity_notes": [], "decision_reason": "reviewed synthetic fixture", "completed_at": "2026-01-01T00:00:00Z"}
        review_bytes = json.dumps(review, separators=(",", ":")).encode()
        review_hash = "sha256:" + hashlib.sha256(review_bytes).hexdigest()
        adjudication = {"review_id": "adjudication-1", "case_id": "case-1", "reviewer_role": "adjudicator", "source_case_hash": review["source_case_hash"], "authorization_spec_hash": review["authorization_spec_hash"], "reference_content_hash": reference_hash, "considered_review_hashes": [review_hash], "disagreement_disposition": [{"case_id": "case-1", "disposition": "confirmed", "reason": "synthetic"}], "decision_rationale": "synthetic adjudication", "adjudicator_id": "adjudicator", "independence_declaration": True, "independence_basis": "separate synthetic adjudication", "completed_at": "2026-01-02T00:00:00Z"}
        adjudication_bytes = json.dumps(adjudication, separators=(",", ":")).encode()
        adjudication_hash = "sha256:" + hashlib.sha256(adjudication_bytes).hexdigest()
        retained = {reference_hash: reference_bytes, review_hash: review_bytes, adjudication_hash: adjudication_bytes}
        events = []
        raw_events = []
        hashes = []
        previous = ""
        definitions = [("created", "author", "reference_author", []), ("reviewed", "reviewer", "human_reviewer", [review_hash]), ("adjudicated", "adj", "adjudicator", [adjudication_hash, review_hash]), ("approved", "owner", "approver", [review_hash, adjudication_hash])]
        for index, (kind, actor_id, role, evidence) in enumerate(definitions, 1):
            event = {"event_schema_version": "acac-lifecycle-1.0", "event_id": f"e{index}", "reference_id": "ref", "reference_content_hash": reference_hash, "sequence": index, "event_type": kind, "actor": {"actor_id": actor_id, "role": role}, "occurred_at": "2026-01-01T00:00:00Z", "evidence_hashes": evidence, "reason": kind, "previous_event_hash": previous}
            raw = json.dumps(event, separators=(",", ":")).encode()
            digest = exact_hash(raw)
            events.append(event); raw_events.append(raw); hashes.append(digest); previous = digest
        decision = evaluate_v1_reference(events=events, event_bytes=raw_events, event_hashes=hashes, reference_id="ref", reference_author_id="author", configured_approver_id="owner", sidecar_status="resolved", source_hash_valid=True, authorization_hash_valid=True, reference_hash_valid=True, temporal_gate=True, retained_artifacts=retained)
        self.assertTrue(decision.eligible)
        unresolved = evaluate_v1_reference(events=events, event_bytes=raw_events, event_hashes=hashes, reference_id="ref", reference_author_id="author", configured_approver_id="owner", sidecar_status="ambiguous", source_hash_valid=True, authorization_hash_valid=True, reference_hash_valid=True, temporal_gate=True, retained_artifacts=retained)
        self.assertFalse(unresolved.eligible)
        self.assertEqual(unresolved.reason, "authorization_unresolved")
        rejected = evaluate_v1_reference(events=events, event_bytes=raw_events, event_hashes=hashes, reference_id="ref", reference_author_id="author", configured_approver_id="other", sidecar_status="resolved", source_hash_valid=True, authorization_hash_valid=True, reference_hash_valid=True, temporal_gate=True, retained_artifacts=retained)
        self.assertFalse(rejected.eligible)
        tampered = list(hashes); tampered[1] = "sha256:" + "f" * 64
        self.assertFalse(evaluate_v1_reference(events=events, event_bytes=raw_events, event_hashes=tampered, reference_id="ref", reference_author_id="author", configured_approver_id="owner", sidecar_status="resolved", source_hash_valid=True, authorization_hash_valid=True, reference_hash_valid=True, temporal_gate=True, retained_artifacts=retained).eligible)


if __name__ == "__main__": unittest.main()
