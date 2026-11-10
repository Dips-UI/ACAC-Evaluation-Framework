"""Synthetic v1.4 reference-integrity tests."""

import hashlib
import unittest
from copy import deepcopy

from acac.references_v14 import validate_reference_v14
from tests.test_authorization_input_v14 import input_for, stored
from tests.test_case_validation import case as make_case


def build_chain(no_op=False, temporal=False, case_id="case-001", extra_protected=False,
                reference_id="ref-1", revision=1, input_revision_note=None,
                multiple_original_conditions=False, exception=False):
    case_value = make_case()
    case_value["case_id"] = case_id
    if extra_protected:
        case_value["payload"]["field_declarations"].extend([
            {"table": "L", "field": "memo", "type": "string", "mutable": False},
            {"table": "L", "field": "context", "type": "string", "mutable": False},
        ])
        case_value["payload"]["ledger"]["L"][0]["values"].update({
            "memo": "KEEP", "context": "UNCHANGED",
        })
    if temporal:
        case_value["payload"]["field_declarations"].append({
            "table": "L", "field": "at", "type": "string",
            "format": "rfc3339-timestamp", "mutable": False,
        })
        case_value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-03-01T00:00:00Z"
        locator = {"source": "table_field", "table": "L", "field": "at"}
        threshold = "2026-02-01T00:00:00.123456789Z"
        case_value["payload"]["notice"].update({
            "governing_event": locator,
            "effective_at": threshold,
            "effective_boundary": "inclusive",
        })
        case_value["payload"]["temporal_conditions"] = [{
            "condition_id": "condition-1", "instruction_id": "notice-1",
            "predicate_id": "p1", "governing_event": locator,
            "effective_at": threshold, "effective_boundary": "inclusive",
        }]
        if multiple_original_conditions:
            for index, predicate_id in enumerate(("p2", "p3"), 1):
                case_value["payload"]["temporal_conditions"].append({
                    "condition_id": f"original-condition-{index}", "instruction_id": "original",
                    "predicate_id": predicate_id, "governing_event": locator,
                    "effective_at": f"2026-02-0{index + 1}T00:00:00Z",
                    "effective_boundary": "inclusive" if index == 1 else "exclusive",
                })
    if no_op:
        case_value["payload"]["notice"] = {
            "notice_id": "notice-1", "operation": "no_op", "authority_text": "No changes",
            "scope": {"fields": []},
        }
    if exception:
        case_value["payload"]["notice"]["exclusion_ids"] = ["x1"]
        case_value["payload"]["notice"]["exception_ids"] = ["e1"]
    case_value, case_bytes, auth_input = input_for(case_value)
    resolution = auth_input
    if exception:
        resolution["predicate_definitions"].append({
            "predicate_id": "exclude-r1", "expression": {"record_ids": ["r1"]},
        })
        resolution["exclusions"] = [{
            "exclusion_id": "x1", "predicate_id": "exclude-r1",
            "instruction_ids": ["notice-1"], "reason": "Synthetic exclusion",
        }]
        resolution["exceptions_applied"] = [{
            "exception_id": "e1", "record_ids": ["r1"],
            "instruction_ids": ["notice-1"], "reason": "Synthetic exception",
        }]
        resolution["eligibility_rationale"][0]["excluded_by"] = ["x1"]
    if input_revision_note is not None and not no_op:
        resolution["rationale_by_key"][0]["reason"] = input_revision_note
    if no_op:
        resolution["eligible_keys"] = []
        resolution["eligibility_rationale"] = []
        resolution["required_final_values"] = []
        resolution["preservation_keys"] = [["L", "r1", "label"]]
        resolution["rationale_by_key"] = []
    if temporal:
        resolution["governing_event"] = {"source": "table_field", "table": "L", "field": "at"}
        resolution["temporal_rules"] = [{
            "rule_id": "rule-1", "source_condition_id": "condition-1",
            "source_location": "/payload/temporal_conditions/0", "occurrence_index": 0,
            "instruction_id": "notice-1", "predicate_id": "p1",
            "effective_at": "2026-02-01T00:00:00.123456789Z",
            "effective_boundary": "inclusive",
        }]
        if multiple_original_conditions:
            resolution["predicate_definitions"].extend([
                {"predicate_id": "p2", "expression": {"record_ids": ["r1"]}},
                {"predicate_id": "p3", "expression": {"record_ids": ["r1"]}},
            ])
            for index, condition in enumerate(case_value["payload"]["temporal_conditions"][1:], 1):
                resolution["temporal_rules"].append({
                    "rule_id": f"original-rule-{index}",
                    "source_condition_id": condition["condition_id"],
                    "source_location": f"/payload/temporal_conditions/{index}",
                    "occurrence_index": 0,
                    "instruction_id": condition["instruction_id"],
                    "predicate_id": condition["predicate_id"],
                    "effective_at": condition["effective_at"],
                    "effective_boundary": condition["effective_boundary"],
                })
    auth_bytes = stored(auth_input)
    case_hash = "sha256:" + hashlib.sha256(case_bytes).hexdigest()
    input_hash = "sha256:" + hashlib.sha256(auth_bytes).hexdigest()
    patch = {"schema_version": "acac-1.3", "edits": [] if no_op else [{
        "op": "replace", "table": "L", "record_id": "r1", "field": "label",
        "old_value": "OLD", "new_value": "NEW",
    }]}
    final_ledger = deepcopy(case_value["payload"]["ledger"])
    if not no_op:
        final_ledger["L"][0]["values"]["label"] = "NEW"
    reference = {
        "schema_version": "acac-1.4", "reference_id": reference_id, "revision": revision,
        "case_id": case_value["case_id"], "source_case_hash": case_hash,
        "authorization_input_hash": input_hash,
        "eligible_keys": deepcopy(resolution["eligible_keys"]),
        "expected_output": patch, "final_ledger": final_ledger,
        "preservation_keys": deepcopy(resolution["preservation_keys"]),
        "rationale": "Synthetic reference rationale",
        "author": {"author_id": "author-1", "role": "reference_author", "created_at": "2026-10-30T12:00:00Z"},
    }
    reference_bytes = stored(reference)
    reference_hash = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
    review = {
        "schema_version": "acac-review-1.1", "review_id": "review-1",
        "case_id": case_value["case_id"], "reviewer_id": "reviewer-1",
        "reviewer_role": "human_reviewer", "independence_declaration": True,
        "independence_basis": "Synthetic isolated review",
        "authorization_input_hash": input_hash,
        "reference_id": reference_id, "reference_revision": revision,
        "reference_content_hash": reference_hash, "review_scope": deepcopy(resolution["eligible_keys"]),
        "eligible_keys": deepcopy(resolution["eligible_keys"]),
        "proposed_edits": deepcopy(patch["edits"]), "ambiguity_notes": [],
        "decision_reason": "Synthetic review", "completed_at": "2026-10-31T12:00:00Z",
    }
    review_bytes = stored(review)
    review_hash = "sha256:" + hashlib.sha256(review_bytes).hexdigest()
    sidecar = {
        "spec_version": "acac-auth-1.2", "case_id": case_value["case_id"],
        "source_case_hash": case_hash, "authorization_input_hash": input_hash,
        "review_submission_hashes": [review_hash], "resolution_status": "resolved",
        "profile": case_value["profile"], "resolution_issues": [],
        "resolved_by": [{"reviewer_id": "reviewer-1", "role": "human_reviewer",
                         "reviewed_at": review["completed_at"], "independence_declaration": True,
                         "review_submission_hash": review_hash}],
        "resolution_note": "Synthetic final sidecar",
        **{name: deepcopy(item) for name, item in resolution.items()
           if name not in {"schema_version", "case_id", "source_case_hash", "profile"}},
    }
    if temporal:
        sidecar["temporal_reconciliation"] = {
            "status": "succeeded", "review_submission_hashes": [review_hash],
            "checked_at": "2026-10-31T14:00:00Z",
        }
    sidecar_bytes = stored(sidecar)
    return (case_value, case_bytes, auth_input, auth_bytes, reference, reference_bytes,
            sidecar, sidecar_bytes, {review_hash: (review, review_bytes)})


def validate(chain, reference=None):
    case_value, case_bytes, auth, auth_bytes, original_ref, ref_bytes, sidecar, sidecar_bytes, reviews = chain
    selected = reference or original_ref
    selected_bytes = ref_bytes if selected is original_ref else stored(selected)
    return validate_reference_v14(
        selected, reference_bytes=selected_bytes, case=case_value, case_bytes=case_bytes,
        authorization_input=auth, authorization_input_bytes=auth_bytes,
        sidecar=sidecar, sidecar_bytes=sidecar_bytes, reviews_by_hash=reviews,
    )


def rebind_chain(chain, reference):
    case_value, case_bytes, auth, auth_bytes, _, _, sidecar, _, reviews = chain
    reference_bytes = stored(reference)
    reference_hash = "sha256:" + hashlib.sha256(reference_bytes).hexdigest()
    old_review, old_review_bytes = next(iter(reviews.values()))
    review = deepcopy(old_review)
    review["reference_content_hash"] = reference_hash
    review_bytes = stored(review)
    review_hash = "sha256:" + hashlib.sha256(review_bytes).hexdigest()
    sidecar = deepcopy(sidecar)
    sidecar["review_submission_hashes"] = [review_hash]
    sidecar["resolved_by"][0]["review_submission_hash"] = review_hash
    sidecar_bytes = stored(sidecar)
    return (case_value, case_bytes, auth, auth_bytes, reference, reference_bytes,
            sidecar, sidecar_bytes, {review_hash: (review, review_bytes)})


class ReferenceV14Tests(unittest.TestCase):
    def test_reference_path_rejects_incomplete_predicate_eligibility(self):
        chain = build_chain()
        case_value, case_bytes, auth, _, reference, reference_bytes, sidecar, sidecar_bytes, reviews = chain
        bad_auth = deepcopy(auth)
        resolution = bad_auth
        resolution["eligible_keys"] = []
        resolution["eligibility_rationale"] = []
        resolution["required_final_values"] = []
        resolution["preservation_keys"] = [["L", "r1", "label"]]
        resolution["rationale_by_key"] = []

        result = validate_reference_v14(
            reference, reference_bytes=reference_bytes, case=case_value,
            case_bytes=case_bytes, authorization_input=bad_auth,
            authorization_input_bytes=stored(bad_auth), sidecar=sidecar,
            sidecar_bytes=sidecar_bytes, reviews_by_hash=reviews,
        )

        self.assertFalse(result.valid)
        self.assertTrue(any("eligible_key_missing_from_scope" in error for error in result.errors), result.errors)

    def test_reference_path_rejects_missing_rationale_coverage(self):
        chain = build_chain()
        case_value, case_bytes, auth, _, reference, reference_bytes, sidecar, sidecar_bytes, reviews = chain
        bad_auth = deepcopy(auth)
        bad_auth["rationale_by_key"] = []
        result = validate_reference_v14(
            reference, reference_bytes=reference_bytes, case=case_value,
            case_bytes=case_bytes, authorization_input=bad_auth,
            authorization_input_bytes=stored(bad_auth), sidecar=sidecar,
            sidecar_bytes=sidecar_bytes, reviews_by_hash=reviews,
        )
        self.assertFalse(result.valid)
        self.assertTrue(any("rationale_by_key_coverage" in error for error in result.errors), result.errors)

    def test_reference_integrity_recomputes_expected_transition(self):
        chain = build_chain()
        result = validate(chain)
        self.assertTrue(result.valid, result.errors)
        self.assertTrue(result.reference_hash.startswith("sha256:"))

    def test_final_ledger_mismatch_is_rejected(self):
        chain = build_chain()
        reference = deepcopy(chain[4])
        reference["final_ledger"]["L"][0]["values"]["label"] = "OTHER"
        result = validate(rebind_chain(chain, reference))
        self.assertFalse(result.valid)
        self.assertIn("final_ledger_mismatch", result.errors)

    def test_reference_cannot_bind_a_different_authorization_input(self):
        chain = build_chain()
        reference = deepcopy(chain[4])
        reference["authorization_input_hash"] = "sha256:" + "0" * 64
        result = validate(rebind_chain(chain, reference))
        self.assertFalse(result.valid)
        self.assertIn("authorization_input_hash_mismatch", result.errors)

    def test_no_op_reference_requires_empty_eligibility_and_patch(self):
        chain = build_chain(no_op=True)
        result = validate(chain)
        self.assertTrue(result.valid, result.errors)
        reference = deepcopy(chain[4])
        reference["expected_output"]["edits"] = [{
            "op": "replace", "table": "L", "record_id": "r1", "field": "label",
            "old_value": "OLD", "new_value": "NEW",
        }]
        result = validate(rebind_chain(chain, reference))
        self.assertFalse(result.valid)


if __name__ == "__main__":
    unittest.main()
