import unittest

from acac.patches import validate_patch


class PatchTests(unittest.TestCase):
    def setUp(self):
        self.ledger = {"L": [{"record_id": "r1", "values": {"label": "OLD"}}]}
        self.declarations = {("L", "label"): {"type": "string"}}

    def test_valid_patch_applies_to_isolated_copy(self):
        result = validate_patch({"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"}]}, self.ledger, self.declarations, "single-ledger-1.0")
        self.assertTrue(result.valid)
        self.assertEqual(result.isolated_ledger["L"][0]["values"]["label"], "NEW")
        self.assertEqual(self.ledger["L"][0]["values"]["label"], "OLD")

    def test_structural_failures_are_all_or_nothing(self):
        patch = {"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"}, {"op": "replace", "table": "L", "record_id": "missing", "field": "label", "old_value": "OLD", "new_value": "X"}]}
        result = validate_patch(patch, self.ledger, self.declarations, "single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIsNone(result.isolated_ledger)

    def test_rejects_stale_and_noop_writes(self):
        for new, old in (("OLD", "OLD"), ("NEW", "WRONG")):
            result = validate_patch({"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": old, "new_value": new}]}, self.ledger, self.declarations, "single-ledger-1.0")
            self.assertFalse(result.valid)

    def test_duplicate_targets_are_patch_conflicts_not_isolated_operation_failures(self):
        edits = [
            {"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"},
            {"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "OTHER"},
        ]
        result = validate_patch({"schema_version": "acac-1.3", "edits": edits}, self.ledger, self.declarations, "single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIsNone(result.isolated_ledger)
        self.assertTrue(any(error.startswith("patch:duplicate_target:") for error in result.errors))
        self.assertEqual(result.operation_diagnostics, ((0, True, ()), (1, True, ())))
        self.assertEqual(self.ledger["L"][0]["values"]["label"], "OLD")

    def test_mixed_validity_reports_each_operation_without_partial_application(self):
        self.ledger["L"][0]["values"]["note"] = "KEEP"
        self.declarations[("L", "note")] = {"type": "string"}
        edits = [
            {"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"},
            {"op": "replace", "table": "L", "record_id": "r1", "field": "note", "old_value": "STALE", "new_value": "CHANGED"},
        ]
        result = validate_patch({"schema_version": "acac-1.3", "edits": edits}, self.ledger, self.declarations, "single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIsNone(result.isolated_ledger)
        self.assertEqual(result.operation_diagnostics, ((0, True, ()), (1, False, ("stale_old_value",))))
        self.assertEqual(self.ledger["L"][0]["values"], {"label": "OLD", "note": "KEEP"})

    def test_distinct_edits_in_one_row_apply_together_only_when_all_valid(self):
        self.ledger["L"][0]["values"]["note"] = "KEEP"
        self.declarations[("L", "note")] = {"type": "string"}
        edits = [
            {"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"},
            {"op": "replace", "table": "L", "record_id": "r1", "field": "note", "old_value": "KEEP", "new_value": "UPDATED"},
        ]
        result = validate_patch({"schema_version": "acac-1.3", "edits": edits}, self.ledger, self.declarations, "single-ledger-1.0")
        self.assertTrue(result.valid)
        self.assertEqual(result.isolated_ledger["L"][0]["values"], {"label": "NEW", "note": "UPDATED"})
        self.assertEqual(self.ledger["L"][0]["values"], {"label": "OLD", "note": "KEEP"})
        self.assertEqual(result.operation_diagnostics, ((0, True, ()), (1, True, ())))

    def test_invalid_envelope_still_reports_isolated_operation_diagnostics(self):
        patch = {
            "schema_version": "unsupported",
            "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"}],
            "extra": "invalid envelope",
        }
        result = validate_patch(patch, self.ledger, self.declarations, "single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIsNone(result.isolated_ledger)
        self.assertIn("invalid_patch_members", result.errors)
        self.assertIn("invalid_patch_version_or_edits", result.errors)
        self.assertEqual(result.operation_diagnostics, ((0, True, ()),))

    def test_malformed_operation_is_reported_without_partial_application(self):
        patch = {
            "schema_version": "acac-1.3",
            "edits": [
                {"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "NEW"},
                {"op": "replace", "table": "L", "record_id": "r1", "old_value": "OLD", "new_value": "BROKEN"},
            ],
        }
        result = validate_patch(patch, self.ledger, self.declarations, "single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIsNone(result.isolated_ledger)
        self.assertEqual(result.operation_diagnostics, ((0, True, ()), (1, False, ("invalid_patch_members",))))
        self.assertEqual(self.ledger["L"][0]["values"]["label"], "OLD")

    def test_timestamp_declared_patch_values_must_parse(self):
        ledger = {"L": [{"record_id": "r1", "values": {"at": "2026-01-01T00:00:00Z"}}]}
        declarations = {("L", "at"): {"type": "string", "format": "rfc3339-timestamp"}}
        valid = {"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "at", "old_value": "2026-01-01T00:00:00Z", "new_value": "2026-01-02T00:00:00Z"}]}
        self.assertTrue(validate_patch(valid, ledger, declarations, "single-ledger-1.0").valid)
        valid["edits"][0]["new_value"] = "not-a-timestamp"
        result = validate_patch(valid, ledger, declarations, "single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("invalid_timestamp_value", result.errors[0])


if __name__ == "__main__": unittest.main()
