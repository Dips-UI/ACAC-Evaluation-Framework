"""Synthetic v1.4 adjudication artifact tests."""

import hashlib
import json
import unittest
from copy import deepcopy

from acac.adjudication_v14 import validate_adjudication_v14


def stored(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def fixture(with_exception=False):
    reference = {"reference_id": "ref-1", "revision": 1, "case_id": "case-1"}
    reference_bytes = stored(reference)
    reference_hash = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
    input_hash = "sha256:" + "1" * 64
    source_hash = "sha256:" + "2" * 64
    review_hash = "sha256:" + "3" * 64
    value = {
        "review_id": "adjudication-1", "case_id": "case-1", "reviewer_role": "adjudicator",
        "source_case_hash": source_hash, "authorization_input_hash": input_hash,
        "reference_id": "ref-1", "reference_revision": 1,
        "reference_content_hash": reference_hash, "considered_review_hashes": [review_hash],
        "disagreement_disposition": [{"review_id": "review-1", "decision": "accepted"}],
        "decision_rationale": "Synthetic decision", "exception_decisions": [], "adjudicator_id": "adjudicator-1",
        "independence_declaration": True, "independence_basis": "Synthetic basis",
        "completed_at": "2026-10-31T12:00:00Z",
    }
    case = {"payload": {"original_guideline": "A synthetic governing instruction.", "updates": [], "notice": {"notice_id": "notice-1", "authority_text": "Notice authority."}}}
    authorization_input = {"exceptions_applied": [], "evidence_registry": []}
    candidates = ()
    if with_exception:
        authorization_input["exceptions_applied"] = [{"exception_id": "e1", "instruction_ids": ["original"]}]
        candidates = (("e1", "x1", ("L", "r1", "label")),)
        value["exception_decisions"] = [{
            "exception_id": "e1", "exclusion_id": "x1", "key": ["L", "r1", "label"],
            "decision": "authorized", "instruction_ids": ["original"],
            "source_locations": ["/payload/original_guideline"], "evidence_ids": [],
            "rationale": "Synthetic adjudicator decision",
        }]
    return reference, reference_bytes, value, source_hash, input_hash, review_hash, case, authorization_input, candidates


def validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, authorization_input, candidates):
    return validate_adjudication_v14(
        value, adjudication_bytes=stored(value), case_id="case-1",
        source_case_hash=source_hash, authorization_input_hash=input_hash,
        reference=ref, reference_bytes=ref_bytes, review_hashes={review_hash},
        case=case, authorization_input=authorization_input,
        exception_decision_candidates=candidates,
    )


class AdjudicationV14Tests(unittest.TestCase):
    def test_valid_adjudication_binds_input_reference_and_review(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture()
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertTrue(result.valid, result.errors)
        self.assertTrue(result.adjudication_hash.startswith("sha256:"))

    def test_unretained_considered_review_is_rejected(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture()
        value["considered_review_hashes"] = ["sha256:" + "4" * 64]
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertFalse(result.valid)
        self.assertIn("considered_review_not_retained", result.errors)

    def test_boolean_reference_revision_is_rejected(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture()
        value["reference_revision"] = True
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertFalse(result.valid)
        self.assertIn("invalid_reference_revision", result.errors)

    def test_exception_decision_is_hash_bound_and_scoped_to_exception_exclusion_key(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture(with_exception=True)
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.adjudication_hash, "sha256:" + hashlib.sha256(stored(value)).hexdigest())

    def test_exception_decision_must_cover_every_applicable_tuple(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture(with_exception=True)
        value["exception_decisions"] = []
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertFalse(result.valid)
        self.assertIn("exception_decision_coverage_mismatch", result.errors)

    def test_valid_negative_exception_decisions_preserve_adjudication_hash(self):
        for decision in ("not_authorized", "unresolved"):
            with self.subTest(decision=decision):
                ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture(with_exception=True)
                value["exception_decisions"][0]["decision"] = decision
                result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
                self.assertTrue(result.valid, result.errors)
                self.assertEqual(len(result.unauthorized_exceptions), 1)
                self.assertEqual(result.unauthorized_exceptions[0][3], decision)
                self.assertEqual(result.adjudication_hash, "sha256:" + hashlib.sha256(stored(value)).hexdigest())
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture(with_exception=True)
        value["exception_decisions"][0]["decision"] = "invalid_decision_choice"
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertFalse(result.valid)
        self.assertIn("exception_decision_value_invalid", result.errors)

    def test_exception_decision_must_bind_source_to_instruction(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture(with_exception=True)
        value["exception_decisions"][0]["source_locations"] = ["/payload/updates/0/text"]
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertFalse(result.valid)
        self.assertIn("exception_decision_source_location_mismatch", result.errors)

    def test_duplicate_exception_decision_tuple_is_rejected(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture(with_exception=True)
        value["exception_decisions"].append(deepcopy(value["exception_decisions"][0]))
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertFalse(result.valid)
        self.assertIn("exception_decision_duplicate_tuple", result.errors)

    def test_exception_decision_must_reference_retained_evidence(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture(with_exception=True)
        auth["evidence_registry"] = [{"evidence_id": "evidence-1"}]
        value["exception_decisions"][0]["evidence_ids"] = ["missing-evidence"]
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertFalse(result.valid)
        self.assertIn("exception_decision_evidence_binding_mismatch", result.errors)

    def test_exception_decision_must_reference_candidate_key(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture(with_exception=True)
        value["exception_decisions"][0]["key"] = ["L", "other", "label"]
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertFalse(result.valid)
        self.assertIn("exception_decision_unexpected_tuple", result.errors)

    def test_malformed_exception_key_fails_with_contract_error(self):
        ref, ref_bytes, value, source_hash, input_hash, review_hash, case, auth, candidates = fixture(with_exception=True)
        value["exception_decisions"][0]["key"] = ["L", {}, "label"]
        result = validate(value, ref, ref_bytes, source_hash, input_hash, review_hash, case, auth, candidates)
        self.assertFalse(result.valid)
        self.assertIn("invalid_exception_decision_key", result.errors)


if __name__ == "__main__":
    unittest.main()
