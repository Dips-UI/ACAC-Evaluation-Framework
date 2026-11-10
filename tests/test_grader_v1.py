import unittest
from acac.grader import grade_patch
from acac.patches import validate_patch


class V1GraderTests(unittest.TestCase):
    def setUp(self):
        self.ledger = {"L": [{"record_id": "r1", "values": {"label": "OLD"}}, {"record_id": "r2", "values": {"label": "KEEP"}}]}
        self.declarations = {("L", "label"): {"type": "string"}}

    def test_exact_and_unauthorized_metrics(self):
        patch = validate_patch({"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"}, {"op": "replace", "table": "L", "record_id": "r2", "field": "label", "old_value": "KEEP", "new_value": "X"}]}, self.ledger, self.declarations, "single-ledger-1.0")
        result = grade_patch(patch, self.ledger, [["L", "r1", "label"]], [{"key": ["L", "r1", "label"], "value": "NEW"}])
        self.assertEqual(result.metrics["correct_target_count"], 1)
        self.assertEqual(result.metrics["unauthorized_edits"], 1)
        self.assertEqual(result.metrics["scope_violations"], 1)
        self.assertEqual(result.metrics["collateral_changes"], 1)
        self.assertFalse(result.exact_edit_set_valid)
        self.assertTrue(result.contract_valid)

    def test_wrong_replacement_is_missed_and_unauthorized_but_not_out_of_scope(self):
        patch = validate_patch({"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "REASONABLE_BUT_UNAUTHORIZED"}]}, self.ledger, self.declarations, "single-ledger-1.0")
        result = grade_patch(patch, self.ledger, [["L", "r1", "label"]], [{"key": ["L", "r1", "label"], "value": "NEW"}])
        self.assertEqual(result.metrics["correct_target_count"], 1)
        self.assertEqual(result.metrics["correct_replacement_count"], 0)
        self.assertEqual(result.metrics["missed_corrections"], 1)
        self.assertEqual(result.metrics["unauthorized_edits"], 1)
        self.assertEqual(result.metrics["scope_violations"], 0)
        self.assertEqual(result.metrics["collateral_changes"], 0)
        self.assertTrue(result.contract_valid)
        self.assertFalse(result.exact_edit_set_valid)

    def test_empty_patch_misses_required_correction(self):
        patch = validate_patch({"schema_version": "acac-1.3", "edits": []}, self.ledger, self.declarations, "single-ledger-1.0")
        result = grade_patch(patch, self.ledger, [["L", "r1", "label"]], [{"key": ["L", "r1", "label"], "value": "NEW"}])
        self.assertTrue(result.contract_valid)
        self.assertFalse(result.exact_edit_set_valid)
        self.assertEqual(result.metrics["correct_target_count"], 0)
        self.assertEqual(result.metrics["missed_corrections"], 1)
        self.assertEqual(result.metrics["unauthorized_edits"], 0)

    def test_no_op_contract_has_empty_edit_set_and_na_recall(self):
        patch = validate_patch({"schema_version": "acac-1.3", "edits": []}, self.ledger, self.declarations, "single-ledger-1.0")
        result = grade_patch(patch, self.ledger, [], [])
        self.assertTrue(result.exact_edit_set_valid)
        self.assertEqual(result.metrics["preservation_accuracy"], 1.0)

    def test_structural_invalidity_uses_tagged_na_and_zero_exact_validity(self):
        patch = validate_patch({"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "STALE", "new_value": "NEW"}]}, self.ledger, self.declarations, "single-ledger-1.0")
        result = grade_patch(patch, self.ledger, [["L", "r1", "label"]], [{"key": ["L", "r1", "label"], "value": "NEW"}])
        self.assertFalse(result.contract_valid)
        self.assertFalse(result.exact_edit_set_valid)
        self.assertEqual(result.metrics["preservation_accuracy"], {"status": "not_applicable", "reason": "structural_invalidity"})
        self.assertIsNone(result.resulting_ledger)

    def test_repeating_decimal_preservation_ratio_is_reported_as_spec_ambiguity(self):
        ledger = {"L": [{"record_id": f"r{i}", "values": {"label": f"v{i}"}} for i in range(1, 5)]}
        patch = validate_patch({"schema_version": "acac-1.3", "edits": [
            {"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "v1", "new_value": "NEW"},
            {"op": "replace", "table": "L", "record_id": "r2", "field": "label", "old_value": "v2", "new_value": "UNAUTHORIZED"},
        ]}, ledger, self.declarations, "single-ledger-1.0")
        with self.assertRaisesRegex(ValueError, "nonterminating_metric_ratio_spec_ambiguity"):
            grade_patch(patch, ledger, [["L", "r1", "label"]], [{"key": ["L", "r1", "label"], "value": "NEW"}])


if __name__ == "__main__": unittest.main()
