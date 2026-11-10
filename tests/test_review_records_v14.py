"""Synthetic v1.4 human-review artifact tests."""

import hashlib
import json
import unittest
from copy import deepcopy

from acac.review_records_v14 import validate_human_review_v14
from tests.test_case_validation import case


def stored(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def fixture():
    case_value = case()
    eligible = [["L", "r1", "label"]]
    input_value = {"schema_version": "acac-auth-input-1.0", "case_id": case_value["case_id"], "eligible_keys": deepcopy(eligible)}
    reference = {"schema_version": "acac-1.4", "reference_id": "ref-1", "revision": 1, "eligible_keys": deepcopy(eligible)}
    input_bytes = stored(input_value)
    reference_bytes = stored(reference)
    review = {
        "schema_version": "acac-review-1.1",
        "review_id": "review-1",
        "case_id": case_value["case_id"],
        "reviewer_id": "reviewer-1",
        "reviewer_role": "human_reviewer",
        "independence_declaration": True,
        "independence_basis": "Synthetic isolated review",
        "authorization_input_hash": "sha256:" + hashlib.sha256(input_bytes).hexdigest(),
        "reference_id": reference["reference_id"],
        "reference_revision": 1,
        "reference_content_hash": "sha256:" + hashlib.sha256(reference_bytes).hexdigest(),
        "review_scope": deepcopy(eligible),
        "eligible_keys": deepcopy(eligible),
        "proposed_edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"}],
        "ambiguity_notes": [],
        "decision_reason": "Synthetic review decision",
        "completed_at": "2026-10-31T12:00:00+01:00",
    }
    return case_value, input_value, input_bytes, reference, reference_bytes, review


def validate(review, case_value, input_value, input_bytes, reference, reference_bytes):
    return validate_human_review_v14(
        review, review_bytes=stored(review), case=case_value,
        authorization_input=input_value, authorization_input_bytes=input_bytes,
        reference=reference, reference_bytes=reference_bytes,
    )


class ReviewRecordsV14Tests(unittest.TestCase):
    def test_valid_human_review_binds_exact_input_and_reference(self):
        args = fixture()
        result = validate(args[-1], args[0], args[1], args[2], args[3], args[4])
        self.assertTrue(result.valid, result.errors)
        self.assertTrue(result.review_hash.startswith("sha256:"))

    def test_mismatched_reference_hash_is_rejected(self):
        args = fixture()
        review = deepcopy(args[-1])
        review["reference_content_hash"] = "sha256:" + "0" * 64
        result = validate(review, args[0], args[1], args[2], args[3], args[4])
        self.assertFalse(result.valid)
        self.assertIn("reference_content_hash_mismatch", result.errors)

    def test_bool_is_not_a_valid_reference_revision(self):
        args = fixture()
        review = deepcopy(args[-1])
        review["reference_revision"] = True
        result = validate(review, args[0], args[1], args[2], args[3], args[4])
        self.assertFalse(result.valid)
        self.assertIn("reference_revision_must_be_positive_integer", result.errors)

    def test_sidecar_hash_or_other_unrecognized_fields_are_forbidden(self):
        args = fixture()
        review = deepcopy(args[-1])
        review["approval_event_hash"] = "sha256:" + "0" * 64
        result = validate(review, args[0], args[1], args[2], args[3], args[4])
        self.assertFalse(result.valid)
        self.assertIn("review_members", result.errors)

    def test_invalid_proposed_patch_is_rejected(self):
        args = fixture()
        review = deepcopy(args[-1])
        review["proposed_edits"][0]["field"] = "unknown"
        result = validate(review, args[0], args[1], args[2], args[3], args[4])
        self.assertFalse(result.valid)
        self.assertTrue(any(error.startswith("invalid_review_proposed_edits:") for error in result.errors))

    def test_review_scope_and_eligible_keys_must_equal_canonical_input_reference_scope(self):
        args = fixture()
        review = deepcopy(args[-1])
        review["review_scope"] = [["L", "other", "label"]]
        result = validate(review, *args[:-1])
        self.assertFalse(result.valid)
        self.assertIn("review_scope_mismatch", result.errors)

    def test_review_scope_subset_and_superset_are_rejected(self):
        args = fixture()
        review = deepcopy(args[-1])
        review["review_scope"] = []
        result = validate(review, *args[:-1])
        self.assertFalse(result.valid)
        self.assertIn("review_scope_mismatch", result.errors)
        review = deepcopy(args[-1])
        review["review_scope"].append(["L", "r2", "label"])
        result = validate(review, *args[:-1])
        self.assertFalse(result.valid)
        self.assertIn("review_scope_mismatch", result.errors)

    def test_reordered_scope_addresses_are_canonicalized_and_accepted(self):
        args = fixture()
        input_value, reference, review = args[1], args[3], deepcopy(args[-1])
        input_value["eligible_keys"].append(["L", "r0", "label"])
        reference["eligible_keys"].append(["L", "r0", "label"])
        # Recompute retained bytes and the exact hashes because those artifacts
        # are immutable inputs to this validation.
        input_bytes = stored(input_value)
        reference_bytes = stored(reference)
        review["authorization_input_hash"] = "sha256:" + hashlib.sha256(input_bytes).hexdigest()
        review["reference_content_hash"] = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
        review["review_scope"] = [["L", "r1", "label"], ["L", "r0", "label"]]
        review["eligible_keys"] = [["L", "r1", "label"], ["L", "r0", "label"]]
        result = validate_human_review_v14(
            review, review_bytes=stored(review), case=args[0],
            authorization_input=input_value, authorization_input_bytes=input_bytes,
            reference=reference, reference_bytes=reference_bytes,
        )
        self.assertTrue(result.valid, result.errors)

    def test_input_and_reference_scope_must_match(self):
        args = fixture()
        input_value, input_bytes, reference, reference_bytes = args[1], args[2], deepcopy(args[3]), args[4]
        reference["eligible_keys"] = []
        reference_bytes = stored(reference)
        review = deepcopy(args[-1])
        review["reference_content_hash"] = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
        result = validate_human_review_v14(
            review, review_bytes=stored(review), case=args[0],
            authorization_input=input_value, authorization_input_bytes=input_bytes,
            reference=reference, reference_bytes=reference_bytes,
        )
        self.assertFalse(result.valid)
        self.assertIn("authorization_input_reference_scope_mismatch", result.errors)

    def test_review_eligible_keys_must_match_exact_scope(self):
        args = fixture()
        review = deepcopy(args[-1])
        review["eligible_keys"] = []
        result = validate(review, *args[:-1])
        self.assertFalse(result.valid)
        self.assertIn("review_eligible_keys_mismatch", result.errors)

    def test_empty_canonical_scope_is_valid_for_no_op(self):
        args = fixture()
        case_value = deepcopy(args[0])
        case_value["payload"]["notice"] = {
            "notice_id": "notice-1", "operation": "no_op", "authority_text": "No changes",
            "scope": {"fields": []},
        }
        input_value, reference, review = deepcopy(args[1]), deepcopy(args[3]), deepcopy(args[-1])
        input_value["eligible_keys"] = []
        reference["eligible_keys"] = []
        review["review_scope"] = []
        review["eligible_keys"] = []
        review["proposed_edits"] = []
        input_bytes, reference_bytes = stored(input_value), stored(reference)
        review["authorization_input_hash"] = "sha256:" + hashlib.sha256(input_bytes).hexdigest()
        review["reference_content_hash"] = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
        result = validate_human_review_v14(
            review, review_bytes=stored(review), case=case_value,
            authorization_input=input_value, authorization_input_bytes=input_bytes,
            reference=reference, reference_bytes=reference_bytes,
        )
        self.assertTrue(result.valid, result.errors)

    def test_duplicate_scope_addresses_are_rejected(self):
        args = fixture()
        review = deepcopy(args[-1])
        review["review_scope"].append(review["review_scope"][0])
        result = validate(review, *args[:-1])
        self.assertFalse(result.valid)
        self.assertIn("review_scope_duplicate_key", result.errors)


if __name__ == "__main__":
    unittest.main()
