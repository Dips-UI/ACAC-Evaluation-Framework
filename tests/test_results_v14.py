"""Synthetic v1.4 result schema and canonical-ordering tests."""
import unittest

from acac.canonical import semantic_hash
from acac.results_v14 import ResultV14Error, validate_result_v14


def result():
    digest = "sha256:" + "a" * 64
    return {
        "schema_version": "acac-1.4",
        "case_id": "case-1",
        "run_id": "run-1",
        "contract_valid": True,
        "exact_edit_set_valid": True,
        "metrics": {
            "correct_target_count": 1,
            "correct_replacement_count": 1,
            "missed_corrections": 0,
            "unauthorized_edits": 0,
            "scope_violations": 0,
            "collateral_changes": 0,
            "preservation_accuracy": {"numerator": "1", "denominator": "1"},
        },
        "diagnostics": [],
        "provenance": {
            "case_exact_hash": digest,
            "authorization_input_hash": digest,
            "review_submission_hashes": [digest],
            "final_authorization_sidecar_hash": digest,
            "reference_hash": digest,
            "adjudication_hash": digest,
            "approval_event_hash": digest,
            "reference_governance_status": "approved_unfrozen",
            "raw_output_hash": digest,
            "prompt_hash": digest,
            "configuration_hash": digest,
            "grader_version": "acac-grader-1.4",
        },
    }


class ResultV14Tests(unittest.TestCase):
    def test_result_with_exact_ratio_is_valid(self):
        validate_result_v14(result())

    def test_result_rejects_unreduced_ratio_and_bad_na(self):
        value = result()
        value["metrics"]["preservation_accuracy"] = {"numerator": "2", "denominator": "2"}
        with self.assertRaisesRegex(ResultV14Error, "invalid_ratio_metric"):
            validate_result_v14(value)
        value = result()
        value["metrics"]["preservation_accuracy"] = {"status": "not_applicable", "reason": "structural_invalidity"}
        with self.assertRaisesRegex(ResultV14Error, "valid_contract_count_metric_na|invalid_preservation_na"):
            validate_result_v14(value)

    def test_set_arrays_are_canonical_but_temporal_conditions_preserve_source_order(self):
        left = {"review_submission_hashes": ["sha256:" + "b" * 64, "sha256:" + "a" * 64]}
        right = {"review_submission_hashes": list(reversed(left["review_submission_hashes"]))}
        self.assertEqual(semantic_hash(left), semantic_hash(right))
        conditions_a = {"temporal_conditions": [{"condition_id": "one"}, {"condition_id": "two"}]}
        conditions_b = {"temporal_conditions": list(reversed(conditions_a["temporal_conditions"]))}
        self.assertNotEqual(semantic_hash(conditions_a), semantic_hash(conditions_b))


if __name__ == "__main__":
    unittest.main()
