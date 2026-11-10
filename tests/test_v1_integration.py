import unittest
from tests.test_case_validation import case
from acac.case_validation import validate_case
from acac.patches import validate_patch
from acac.grader import grade_patch
from acac.aggregate import aggregate_cases


class V1IntegrationTests(unittest.TestCase):
    def test_selective_authorized_edit_preserves_unaffected_record(self):
        value = case(); self.assertTrue(validate_case(value).valid)
        ledger = value["payload"]["ledger"]
        declarations = {("L", "label"): {"type": "string"}}
        patch = validate_patch({"schema_version": "acac-1.3", "edits": [{"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "OLD", "new_value": "CANCEL"}]}, ledger, declarations, value["profile"])
        grade = grade_patch(patch, ledger, [["L", "r1", "label"]], [{"key": ["L", "r1", "label"], "value": "CANCEL"}])
        self.assertTrue(grade.exact_edit_set_valid)
        self.assertEqual(aggregate_cases([{"case_id": value["case_id"], "resolution_status": "resolved", "hash_valid": True, "governance_status": "approved_unfrozen"}])["included_count"], 1)


if __name__ == "__main__": unittest.main()
