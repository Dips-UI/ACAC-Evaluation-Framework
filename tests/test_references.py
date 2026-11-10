import hashlib
import json
import unittest

from acac.references import validate_reference
from tests.test_case_validation import case


REVIEW_BYTES = b"synthetic human review submission"
REVIEW_HASH = "sha256:" + hashlib.sha256(REVIEW_BYTES).hexdigest()
DECLARATIONS = {("L", "label"): {"type": "string", "mutable": True}}


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def artifacts(case_value, *, final_value="NEW", no_op=False):
    case_value = json.loads(json.dumps(case_value))
    if no_op:
        case_value["payload"]["notice"] = {"notice_id": "notice-1", "operation": "no_op", "authority_text": "No change", "scope": {"fields": []}}
        eligible, values, rationale, per_key = [], [], [], []
        preserved = [["L", "r1", "label"]]
    else:
        eligible = [["L", "r1", "label"]]
        values = [{"key": eligible[0], "value": final_value}]
        rationale = [{"key": eligible[0], "included_by": ["p1"], "excluded_by": [], "instruction_ids": ["notice-1"]}]
        per_key = [{"key": eligible[0], "instruction_ids": ["notice-1"], "reason": "Synthetic reviewed requirement"}]
        preserved = [] if final_value != "OLD" else eligible.copy()
    case_bytes = encoded(case_value)
    source_hash = "sha256:" + hashlib.sha256(case_bytes).hexdigest()
    authorization = {
        "spec_version": "acac-auth-1.0", "case_id": case_value["case_id"], "source_case_hash": source_hash,
        "resolution_status": "resolved", "profile": case_value["profile"], "resolution_issues": [],
        "resolved_by": [{"reviewer_id": "reviewer-1", "role": "human_reviewer", "reviewed_at": "2026-01-01T00:00:00Z", "independence_declaration": True, "review_submission_hash": REVIEW_HASH}],
        "resolution_note": "synthetic test resolution", "governing_instruction_ids": ["notice-1"],
        "predicate_definitions": [{"predicate_id": "p1", "expression": {"record_ids": ["r1"]}}],
        "evidence_registry": [], "eligible_keys": eligible, "eligibility_rationale": rationale,
        "exclusions": [], "exceptions_applied": [], "required_final_values": values,
        "preservation_keys": preserved, "rationale_by_key": per_key,
    }
    auth_bytes = encoded(authorization)
    return case_value, case_bytes, authorization, auth_bytes


def reference_for(case_value, case_bytes, auth_bytes, *, final_value="NEW", no_op=False, expected_edits=None):
    eligible = [] if no_op else [["L", "r1", "label"]]
    patch_edits = [] if no_op else [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": final_value}]
    if expected_edits is not None:
        patch_edits = expected_edits
    final_ledger = case_value["payload"]["ledger"] if no_op else {"L": [{"record_id": "r1", "values": {"label": final_value}}]}
    preservation = [["L", "r1", "label"]] if no_op or final_value == "OLD" else []
    return {
        "schema_version": "acac-1.3", "reference_id": "ref-1", "revision": 1,
        "case_id": case_value["case_id"],
        "source_case_hash": "sha256:" + hashlib.sha256(case_bytes).hexdigest(),
        "authorization_spec_hash": "sha256:" + hashlib.sha256(auth_bytes).hexdigest(),
        "eligible_keys": eligible,
        "expected_output": {"schema_version": "acac-1.3", "edits": patch_edits},
        "final_ledger": final_ledger, "preservation_keys": preservation,
        "rationale": "synthetic reference", "author": {"author_id": "author-1", "role": "reference_author", "created_at": "2026-01-01T00:00:00Z"},
    }


class ReferenceTests(unittest.TestCase):
    def validate(self, reference, case_value, case_bytes, authorization, auth_bytes):
        return validate_reference(
            reference, case_value, DECLARATIONS, authorization,
            source_case_bytes=case_bytes, authorization_spec_bytes=auth_bytes,
            retained_artifacts={REVIEW_HASH: REVIEW_BYTES},
        )

    def test_reference_identity_and_expected_patch(self):
        c, cb, auth, ab = artifacts(case())
        self.validate(reference_for(c, cb, ab), c, cb, auth, ab)

    def test_reference_identity_and_author_identifier_are_validated(self):
        c, cb, auth, ab = artifacts(case())
        reference = reference_for(c, cb, ab)
        for member, value in (("reference_id", ""), ("reference_id", " padded ")):
            candidate = dict(reference, **{member: value})
            with self.subTest(member=member, value=value), self.assertRaisesRegex(ValueError, "invalid_reference_id"):
                self.validate(candidate, c, cb, auth, ab)
        candidate = dict(reference, author={**reference["author"], "author_id": None})
        with self.assertRaisesRegex(ValueError, "invalid_author_id"):
            self.validate(candidate, c, cb, auth, ab)
        candidate = dict(reference, author=None)
        with self.assertRaisesRegex(ValueError, "author"):
            self.validate(candidate, c, cb, auth, ab)

    def test_reference_requires_exact_patch_from_sidecar_values(self):
        c, cb, auth, ab = artifacts(case())
        ref = reference_for(c, cb, ab, expected_edits=[])
        with self.assertRaisesRegex(ValueError, "expected_edit_set_mismatch"):
            self.validate(ref, c, cb, auth, ab)

    def test_reference_rejects_missing_or_extra_eligible_key_coverage(self):
        c, cb, auth, ab = artifacts(case())
        reference = reference_for(c, cb, ab)
        cases = (
            ([], "eligible_key_mismatch"),
            ([["L", "r1", "label"], ["L", "r1", "other"]], "eligible_key_mismatch"),
            ([["L", "r1", "label"], ["L", "r1", "label"]], "duplicate_eligible_keys"),
        )
        for eligible_keys, error in cases:
            with self.subTest(eligible_keys=eligible_keys):
                candidate = {**reference, "eligible_keys": eligible_keys}
                with self.assertRaisesRegex(ValueError, error):
                    self.validate(candidate, c, cb, auth, ab)

    def test_reference_verifies_exact_source_artifact_hashes(self):
        c, cb, auth, ab = artifacts(case())
        ref = reference_for(c, cb, ab)
        self.validate(ref, c, cb, auth, ab)
        with self.assertRaisesRegex(ValueError, "source_case_hash_mismatch"):
            validate_reference(ref, c, DECLARATIONS, auth, source_case_bytes=b"replacement", authorization_spec_bytes=ab, retained_artifacts={REVIEW_HASH: REVIEW_BYTES})

    def test_no_op_sidecar_and_reference_handoff_requires_empty_authorization(self):
        c, cb, auth, ab = artifacts(case(), no_op=True)
        self.validate(reference_for(c, cb, ab, no_op=True), c, cb, auth, ab)
        auth["eligible_keys"] = [["L", "r1", "label"]]
        auth["required_final_values"] = [{"key": ["L", "r1", "label"], "value": "NEW"}]
        bad_ab = encoded(auth)
        bad_ref = reference_for(c, cb, bad_ab, no_op=True)
        with self.assertRaisesRegex(ValueError, "linked_authorization_invalid:.*no_op_authorization_must_be_empty"):
            self.validate(bad_ref, c, cb, auth, bad_ab)

    def test_reference_rejects_authorization_object_different_from_retained_bytes(self):
        c, cb, auth, ab = artifacts(case())
        ref = reference_for(c, cb, ab)
        altered = dict(auth, resolution_note="changed after hashing")
        with self.assertRaisesRegex(ValueError, "retained_artifact_content_mismatch"):
            self.validate(ref, c, cb, altered, ab)


if __name__ == "__main__":
    unittest.main()
