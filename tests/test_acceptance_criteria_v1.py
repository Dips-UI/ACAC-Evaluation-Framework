import unittest
import json
from acac.canonical import exact_hash
from tests.test_case_validation import case
from acac.case_validation import validate_case
from acac.patches import validate_patch
from acac.grader import grade_patch
from acac.governance import evaluate_reference, evaluate_v1_reference
from acac.manifest import validate_manifest
from acac.projections import instruction_resolution
from acac.temporal import reconcile
from acac.authorization import validate_resolved_coverage, validate_sidecar
from acac.lifecycle import replay_v1
from tests.test_authorization import sidecar as resolved_sidecar, validate as validate_auth


class AcceptanceCriteriaV1Tests(unittest.TestCase):
    def test_A_B_C_unresolved_and_missing_status_fail_the_approval_gate(self):
        for status in ("ambiguous", "quarantined"):
            value = resolved_sidecar()
            value["resolution_status"] = status
            for member in ("governing_instruction_ids", "predicate_definitions", "eligible_keys", "eligibility_rationale", "exclusions", "exceptions_applied", "required_final_values", "preservation_keys", "rationale_by_key"):
                value.pop(member)
            value["resolution_issues"] = [{"issue_id": "i1", "category": "unclear", "source_location": "/payload", "description": "synthetic issue", "evidence_ids": []}]
            self.assertTrue(validate_auth(value, case_id="case-1", profile="single-ledger-1.0").valid)
            events = [{"sequence": 1, "previous_event_hash": "", "event": "reviewed", "event_hash": "h1"}, {"sequence": 2, "previous_event_hash": "h1", "event": "adjudicated", "event_hash": "h2"}, {"sequence": 3, "previous_event_hash": "h2", "event": "approved", "event_hash": "h3"}]
            self.assertFalse(evaluate_reference(events=events, sidecar_status=status, source_hash_valid=True, reference_hash_valid=True, temporal_gate=True).eligible)
        missing = resolved_sidecar(); missing.pop("resolution_status")
        self.assertFalse(validate_auth(missing, case_id="case-1", profile="single-ledger-1.0").valid)

    def test_D_source_hash_mismatch_rejects_resolved_sidecar(self):
        value = resolved_sidecar(); value["source_case_hash"] = "sha256:" + "f" * 64
        result = validate_auth(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("retained_source_case_hash_required", result.errors)

    def test_E_duplicate_eligible_keys_are_rejected(self):
        value = resolved_sidecar(); value["eligible_keys"] = [["L", "r1", "label"], ["L", "r1", "label"]]
        ledger = {"L": [{"record_id": "r1", "values": {"label": "OLD"}}]}
        declarations = {("L", "label"): {"type": "string", "mutable": True}}
        with self.assertRaisesRegex(ValueError, "duplicate_eligible_key"):
            validate_resolved_coverage(value, ledger, declarations, "single-ledger-1.0")

    def test_H_post_approval_quarantine_appends_without_rewriting_history(self):
        reference_bytes = b'{"reference_id":"ref"}'
        reference_hash = exact_hash(reference_bytes)
        case_hash, auth_hash = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        review = {"review_id": "review-1", "case_id": "case-1", "reviewer_id": "reviewer", "reviewer_role": "human_reviewer", "independence_declaration": True, "independence_basis": "synthetic", "source_case_hash": case_hash, "authorization_spec_hash": auth_hash, "reference_content_hash": reference_hash, "review_scope": ["case-1"], "eligible_keys": [], "proposed_edits": [], "ambiguity_notes": [], "decision_reason": "synthetic review", "completed_at": "2026-01-01T00:00:00Z"}
        review_bytes = json.dumps(review, separators=(",", ":")).encode()
        review_hash = exact_hash(review_bytes)
        adjudication = {"review_id": "adjudication-1", "case_id": "case-1", "reviewer_role": "adjudicator", "source_case_hash": case_hash, "authorization_spec_hash": auth_hash, "reference_content_hash": reference_hash, "considered_review_hashes": [review_hash], "disagreement_disposition": [{"case_id": "case-1", "disposition": "confirmed", "reason": "synthetic"}], "decision_rationale": "synthetic adjudication", "adjudicator_id": "adjudicator", "independence_declaration": True, "independence_basis": "synthetic", "completed_at": "2026-01-02T00:00:00Z"}
        adjudication_bytes = json.dumps(adjudication, separators=(",", ":")).encode()
        adjudication_hash = exact_hash(adjudication_bytes)
        retained = {reference_hash: reference_bytes, review_hash: review_bytes, adjudication_hash: adjudication_bytes}
        event_specs = [
            ("created", "author", "reference_author", []),
            ("reviewed", "reviewer", "human_reviewer", [review_hash]),
            ("adjudicated", "adjudicator", "adjudicator", [adjudication_hash, review_hash]),
            ("approved", "owner", "approver", [review_hash, adjudication_hash]),
            ("quarantined", "reviewer", "human_reviewer", [review_hash]),
        ]
        events, event_bytes, event_hashes = [], [], []
        previous = ""
        for sequence, (kind, actor_id, role, evidence) in enumerate(event_specs, 1):
            event = {"event_schema_version": "acac-lifecycle-1.0", "event_id": f"e{sequence}", "reference_id": "ref", "reference_content_hash": reference_hash, "sequence": sequence, "event_type": kind, "actor": {"actor_id": actor_id, "role": role}, "occurred_at": "2026-01-03T00:00:00Z", "evidence_hashes": evidence, "reason": kind, "previous_event_hash": previous}
            raw = json.dumps(event, separators=(",", ":")).encode()
            digest = exact_hash(raw)
            events.append(event); event_bytes.append(raw); event_hashes.append(digest); previous = digest
        prior_bytes = list(event_bytes[:4])
        self.assertEqual(replay_v1(events, event_bytes, event_hashes, reference_id="ref", retained_artifacts=retained), "quarantined")
        self.assertEqual(event_bytes[:4], prior_bytes)
        decision = evaluate_v1_reference(events=events, event_bytes=event_bytes, event_hashes=event_hashes, reference_id="ref", reference_author_id="author", configured_approver_id="owner", sidecar_status="resolved", source_hash_valid=True, authorization_hash_valid=True, reference_hash_valid=True, temporal_gate=True, retained_artifacts=retained)
        self.assertFalse(decision.eligible)

    def test_structural_validation_and_model_redaction(self):
        value = case(); result = validate_case(value)
        self.assertTrue(result.valid)
        projected = instruction_resolution(value)
        self.assertNotIn("scope", projected["payload"]["notice"])
        self.assertNotIn("updates", projected["payload"]["notice"])

    def test_authorized_and_unauthorized_outcomes(self):
        value = case(); ledger = value["payload"]["ledger"]; declarations = {("L", "label"): {"type": "string"}}
        patch = validate_patch({"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"}]}, ledger, declarations, value["profile"])
        grade = grade_patch(patch, ledger, [["L", "r1", "label"]], [{"key": ["L", "r1", "label"], "value": "NEW"}])
        self.assertTrue(grade.exact_edit_set_valid)
        unauthorized = validate_patch({"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "OTHER"}]}, ledger, declarations, value["profile"])
        self.assertFalse(grade_patch(unauthorized, ledger, [["L", "r1", "label"]], [{"key": ["L", "r1", "label"], "value": "NEW"}]).exact_edit_set_valid)

    def test_governance_and_manifest_gates(self):
        events = [{"sequence": 1, "previous_event_hash": "", "event": "reviewed", "event_hash": "h1"}, {"sequence": 2, "previous_event_hash": "h1", "event": "adjudicated", "event_hash": "h2"}, {"sequence": 3, "previous_event_hash": "h2", "event": "approved", "event_hash": "h3"}]
        decision = evaluate_reference(events=events, sidecar_status="resolved", source_hash_valid=True, reference_hash_valid=True, temporal_gate=True)
        self.assertTrue(decision.eligible)
        manifest = {"manifest_version": "1.3", "run_id": "r", "mode": "instruction_resolution", "scheduled_case_ids": ["c"], "executed_case_ids": [], "excluded_cases": [{"case_id": "c", "reason": "missing_reference"}], "case_hashes": {}, "authorization_spec_hashes": {}, "reference_hashes": {}, "approval_event_hashes": {}, "raw_output_hashes": {}, "prompt_hash": "sha256:" + "0" * 64, "configuration_hash": "sha256:" + "1" * 64, "grader_version": "acac-grader-1.3", "created_at": "2026-01-01T00:00:00Z"}
        validate_manifest(manifest, {"c"})


if __name__ == "__main__": unittest.main()
