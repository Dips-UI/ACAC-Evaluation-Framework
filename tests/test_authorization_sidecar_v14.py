"""Synthetic v1.4 sidecar binding tests; no protected artifacts are read."""

import hashlib
import unittest
from copy import deepcopy

from acac.authorization_sidecar_v14 import validate_final_sidecar_v14
from acac.canonical import semantic_hash
from tests.test_authorization_input_v14 import input_for, stored


def chain_fixture():
    case_value, case_bytes, auth_input = input_for()
    auth_bytes = stored(auth_input)
    reference = {"schema_version": "acac-1.4", "reference_id": "ref-1", "revision": 1,
                 "eligible_keys": deepcopy(auth_input["eligible_keys"])}
    reference_bytes = stored(reference)
    input_hash = "sha256:" + hashlib.sha256(auth_bytes).hexdigest()
    reference_hash = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
    review = {
        "schema_version": "acac-review-1.1", "review_id": "review-1",
        "case_id": case_value["case_id"], "reviewer_id": "reviewer-1",
        "reviewer_role": "human_reviewer", "independence_declaration": True,
        "independence_basis": "Synthetic independent review",
        "authorization_input_hash": input_hash,
        "reference_id": reference["reference_id"], "reference_revision": reference["revision"],
        "reference_content_hash": reference_hash, "review_scope": deepcopy(auth_input["eligible_keys"]),
        "eligible_keys": deepcopy(auth_input["eligible_keys"]),
        "proposed_edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"}],
        "ambiguity_notes": [], "decision_reason": "Synthetic review",
        "completed_at": "2026-10-31T12:00:00Z",
    }
    review_bytes = stored(review)
    review_hash = "sha256:" + hashlib.sha256(review_bytes).hexdigest()
    sidecar = {
        "spec_version": "acac-auth-1.2", "case_id": case_value["case_id"],
        "source_case_hash": "sha256:" + hashlib.sha256(case_bytes).hexdigest(),
        "authorization_input_hash": input_hash, "review_submission_hashes": [review_hash],
        "resolution_status": "resolved", "profile": case_value["profile"],
        "resolution_issues": [], "resolved_by": [{
            "reviewer_id": review["reviewer_id"], "role": review["reviewer_role"],
            "reviewed_at": review["completed_at"],
            "independence_declaration": review["independence_declaration"],
            "review_submission_hash": review_hash,
        }], "resolution_note": "Reviewed synthetic authorization",
        **{name: deepcopy(item) for name, item in auth_input.items()
           if name not in {"schema_version", "case_id", "source_case_hash", "profile"}},
    }
    sidecar_bytes = stored(sidecar)
    return case_value, case_bytes, auth_input, auth_bytes, reference, reference_bytes, review, review_bytes, review_hash, sidecar, sidecar_bytes


def validate_chain(args, sidecar=None, retained_artifacts=None):
    (case_value, case_bytes, auth_input, auth_bytes, reference, reference_bytes,
     review, review_bytes, review_hash, original_sidecar, original_bytes) = args
    selected = sidecar or original_sidecar
    return validate_final_sidecar_v14(
        selected, sidecar_bytes=stored(selected), case=case_value, case_bytes=case_bytes,
        authorization_input=auth_input, authorization_input_bytes=auth_bytes,
        reference=reference, reference_bytes=reference_bytes,
        reviews_by_hash={review_hash: (review, review_bytes)},
        retained_artifacts=retained_artifacts,
    )


class AuthorizationSidecarV14Tests(unittest.TestCase):
    def test_resolved_sidecar_binds_input_review_and_reference(self):
        args = chain_fixture()
        result = validate_chain(args)
        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.status, "resolved")

    def test_resolved_sidecar_must_repeat_proposed_basis_exactly(self):
        args = chain_fixture()
        sidecar = deepcopy(args[-2])
        sidecar["required_final_values"][0]["value"] = "OTHER"
        result = validate_chain(args, sidecar)
        self.assertFalse(result.valid)
        self.assertIn("sidecar_resolution_differs_from_input", result.errors)

    def test_unlisted_review_provenance_is_rejected(self):
        args = chain_fixture()
        sidecar = deepcopy(args[-2])
        sidecar["resolved_by"][0]["review_submission_hash"] = "sha256:" + "0" * 64
        result = validate_chain(args, sidecar)
        self.assertFalse(result.valid)
        self.assertIn("resolved_by_review_binding", result.errors)

    def test_unresolved_sidecar_issue_and_status_values_are_hash_sensitive(self):
        args = chain_fixture()
        unresolved = deepcopy(args[-2])
        unresolved["resolution_status"] = "ambiguous"
        unresolved["resolution_issues"] = [{
            "issue_id": "issue-1", "category": "ambiguous_authority",
            "source_location": "/payload/original_guideline",
            "description": "Synthetic unresolved instruction interpretation",
            "evidence_ids": [],
        }]
        unresolved["resolved_by"] = []
        for name in (
            "governing_instruction_ids", "predicate_definitions", "evidence_registry",
            "eligible_keys", "eligibility_rationale", "exclusions", "exceptions_applied",
            "required_final_values", "preservation_keys", "rationale_by_key",
        ):
            unresolved.pop(name, None)
        original_result = validate_chain(args, unresolved)
        self.assertTrue(original_result.valid, original_result.errors)
        original_semantic_hash = semantic_hash(unresolved)

        explicit_empty_registry = deepcopy(unresolved)
        explicit_empty_registry["evidence_registry"] = []
        empty_registry_result = validate_chain(args, explicit_empty_registry)
        self.assertTrue(empty_registry_result.valid, empty_registry_result.errors)
        self.assertNotEqual(original_result.sidecar_hash, empty_registry_result.sidecar_hash)
        self.assertNotEqual(original_semantic_hash, semantic_hash(explicit_empty_registry))

        variants = []
        changed_status = deepcopy(unresolved)
        changed_status["resolution_status"] = "quarantined"
        variants.append(changed_status)
        changed_issue = deepcopy(unresolved)
        changed_issue["resolution_issues"][0]["description"] = "Different unresolved interpretation"
        variants.append(changed_issue)
        changed_note = deepcopy(unresolved)
        changed_note["resolution_note"] = "Different unresolved note"
        variants.append(changed_note)

        for candidate in variants:
            with self.subTest(status=candidate["resolution_status"], note=candidate["resolution_note"]):
                result = validate_chain(args, candidate)
                self.assertTrue(result.valid, result.errors)
                self.assertNotEqual(original_result.sidecar_hash, result.sidecar_hash)
                self.assertNotEqual(original_semantic_hash, semantic_hash(candidate))

    def test_unresolved_evidence_registry_values_are_hash_sensitive(self):
        args = chain_fixture()
        evidence_a = b"synthetic evidence A"
        evidence_b = b"synthetic evidence B"
        hash_a = "sha256:" + hashlib.sha256(evidence_a).hexdigest()
        hash_b = "sha256:" + hashlib.sha256(evidence_b).hexdigest()
        unresolved = deepcopy(args[-2])
        unresolved["resolution_status"] = "ambiguous"
        unresolved["resolution_issues"] = [{
            "issue_id": "issue-1", "category": "ambiguous_authority",
            "source_location": "/payload/original_guideline",
            "description": "Synthetic unresolved instruction interpretation",
            "evidence_ids": ["evidence-1"],
        }]
        unresolved["resolved_by"] = []
        for name in (
            "governing_instruction_ids", "predicate_definitions", "evidence_registry",
            "eligible_keys", "eligibility_rationale", "exclusions", "exceptions_applied",
            "required_final_values", "preservation_keys", "rationale_by_key",
        ):
            unresolved.pop(name, None)
        unresolved["evidence_registry"] = [{
            "evidence_id": "evidence-1", "content_hash": hash_a,
            "description": "Synthetic retained evidence",
        }]
        retained = {hash_a: evidence_a, hash_b: evidence_b}
        original_result = validate_chain(args, unresolved, retained)
        self.assertTrue(original_result.valid, original_result.errors)
        original_semantic_hash = semantic_hash(unresolved)

        variants = []
        changed_id = deepcopy(unresolved)
        changed_id["resolution_issues"][0]["evidence_ids"] = ["evidence-2"]
        changed_id["evidence_registry"][0]["evidence_id"] = "evidence-2"
        variants.append(changed_id)
        changed_content_hash = deepcopy(unresolved)
        changed_content_hash["evidence_registry"][0]["content_hash"] = hash_b
        variants.append(changed_content_hash)
        changed_description = deepcopy(unresolved)
        changed_description["evidence_registry"][0]["description"] = "Revised synthetic evidence description"
        variants.append(changed_description)

        for candidate in variants:
            with self.subTest(registry=candidate["evidence_registry"]):
                result = validate_chain(args, candidate, retained)
                self.assertTrue(result.valid, result.errors)
                self.assertNotEqual(original_result.sidecar_hash, result.sidecar_hash)
                self.assertNotEqual(original_semantic_hash, semantic_hash(candidate))

    def test_unresolved_evidence_registry_is_minimal_and_matches_retained_bytes(self):
        args = chain_fixture()
        evidence = b"synthetic unresolved evidence"
        evidence_hash = "sha256:" + hashlib.sha256(evidence).hexdigest()
        retained = {evidence_hash: evidence}

        def unresolved_base(evidence_ids):
            sidecar = deepcopy(args[-2])
            sidecar["resolution_status"] = "ambiguous"
            sidecar["resolution_issues"] = [{
                "issue_id": "issue-1", "category": "ambiguous_authority",
                "source_location": "/payload/original_guideline",
                "description": "Synthetic unresolved issue",
                "evidence_ids": list(evidence_ids),
            }]
            sidecar["resolved_by"] = []
            for name in (
                "governing_instruction_ids", "predicate_definitions", "evidence_registry",
                "eligible_keys", "eligibility_rationale", "exclusions", "exceptions_applied",
                "required_final_values", "preservation_keys", "rationale_by_key",
            ):
                sidecar.pop(name, None)
            return sidecar

        missing = unresolved_base(["e1"])
        empty = unresolved_base(["e1"])
        empty["evidence_registry"] = []
        mismatched = unresolved_base(["e1"])
        mismatched["evidence_registry"] = [{
            "evidence_id": "e2", "content_hash": evidence_hash,
            "description": "Synthetic evidence",
        }]
        extra = unresolved_base([])
        extra["evidence_registry"] = [{
            "evidence_id": "e2", "content_hash": evidence_hash,
            "description": "Synthetic evidence",
        }]
        unretained = unresolved_base(["e1"])
        unretained["evidence_registry"] = [{
            "evidence_id": "e1", "content_hash": evidence_hash,
            "description": "Synthetic evidence",
        }]

        for candidate, expected_error, retained_bytes in (
            (missing, "issue_evidence_registry_mismatch", retained),
            (empty, "issue_evidence_registry_mismatch", retained),
            (mismatched, "issue_evidence_registry_mismatch", retained),
            (extra, "unresolved_evidence_registry_forbidden", retained),
            (unretained, "content_hash_hash_mismatch", {}),
        ):
            with self.subTest(error=expected_error, registry=candidate.get("evidence_registry")):
                result = validate_chain(args, candidate, retained_bytes)
                self.assertFalse(result.valid)
                self.assertIn(expected_error, result.errors)

    def test_approval_hash_cannot_be_added_to_sidecar(self):
        args = chain_fixture()
        sidecar = deepcopy(args[-2])
        sidecar["approval_event_hash"] = "sha256:" + "0" * 64
        result = validate_chain(args, sidecar)
        self.assertFalse(result.valid)
        self.assertIn("sidecar_members", result.errors)


if __name__ == "__main__":
    unittest.main()
