import unittest
from decimal import Decimal

from acac.results import validate_result


def result():
    return {
        "schema_version": "acac-1.3", "case_id": "c1", "run_id": "r1",
        "contract_valid": True, "exact_edit_set_valid": True,
        "metrics": {"correct_target_count": 1, "correct_replacement_count": 1, "missed_corrections": 0, "unauthorized_edits": 0, "scope_violations": 0, "collateral_changes": 0, "preservation_accuracy": Decimal("1")},
        "diagnostics": [],
        "provenance": {"case_exact_hash": "sha256:" + "0" * 64, "authorization_spec_hash": "sha256:" + "1" * 64, "reference_hash": "sha256:" + "2" * 64, "approval_event_hash": "sha256:" + "3" * 64, "reference_governance_status": "approved_unfrozen", "raw_output_hash": "sha256:" + "4" * 64, "prompt_hash": "sha256:" + "5" * 64, "configuration_hash": "sha256:" + "6" * 64, "grader_version": "acac-grader-1.3"},
    }


class ResultTests(unittest.TestCase):
    def test_result_schema_and_tagged_na_metrics(self):
        value = result()
        validate_result(value)
        value["metrics"]["preservation_accuracy"] = {"status": "not_applicable", "reason": "empty_preservation_denominator"}
        validate_result(value)
        value["metrics"]["preservation_accuracy"] = None
        with self.assertRaisesRegex(ValueError, "null_metric"):
            validate_result(value)

    def test_metrics_accept_exact_decimal_ratios_and_reject_float_null_and_boolean(self):
        value = result()
        for invalid in (0.125, None, True, Decimal("NaN")):
            value["metrics"]["preservation_accuracy"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_result(value)
        value["metrics"]["preservation_accuracy"] = Decimal("1")
        value["exact_edit_set_valid"] = 1
        with self.assertRaisesRegex(ValueError, "result_flags"):
            validate_result(value)

    def test_frozen_result_requires_freeze_hash_binding(self):
        value = result()
        value["provenance"]["reference_governance_status"] = "frozen"
        with self.assertRaisesRegex(ValueError, "freeze_event_hash_conditional"):
            validate_result(value)
        value["provenance"]["freeze_event_hash"] = "sha256:" + "7" * 64
        validate_result(value)

    def test_result_enforces_metric_applicability_from_contract_validity(self):
        value = result()
        value["metrics"]["correct_target_count"] = {"status": "not_applicable", "reason": "structural_invalidity"}
        with self.assertRaisesRegex(ValueError, "ledger_metric_not_applicable"):
            validate_result(value)
        value = result()
        value["contract_valid"] = False
        value["exact_edit_set_valid"] = False
        value["diagnostics"] = ["synthetic structural error"]
        for name in value["metrics"]:
            value["metrics"][name] = {"status": "not_applicable", "reason": "structural_invalidity"}
        validate_result(value)
        value["metrics"]["scope_violations"] = 0
        with self.assertRaisesRegex(ValueError, "structural_invalidity_metrics_must_be_na"):
            validate_result(value)
        value["metrics"]["scope_violations"] = {"status": "not_applicable", "reason": "structural_invalidity"}
        value["diagnostics"] = []
        with self.assertRaisesRegex(ValueError, "structural_failure_diagnostics_required"):
            validate_result(value)

    def test_result_rejects_unknown_metric_value_types(self):
        value = result()
        value["metrics"]["correct_target_count"] = "one"
        with self.assertRaisesRegex(ValueError, "invalid_metric"):
            validate_result(value)


if __name__ == "__main__":
    unittest.main()
