import copy
import unittest
from tests.test_case_validation import case
from acac.projections import instruction_resolution, resolved_contract


class ProjectionTests(unittest.TestCase):
    def test_instruction_projection_redacts_authorization_fields(self):
        value = case()
        value["payload"]["updates"] = [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x", "effective_at": "2026-01-01T00:00:00Z", "effective_boundary": "inclusive", "applies_to": {"predicate_id": "p"}}]
        result = instruction_resolution(value)
        self.assertNotIn("temporal_conditions", result["payload"])
        self.assertEqual(set(result["payload"]["updates"][0]), {"update_id", "sequence", "kind", "text"})

    def test_instruction_projection_matches_exact_visible_case_fields(self):
        value = case()
        value["payload"]["metadata_declarations"] = [{"field": "batch", "type": "string"}]
        value["payload"]["record_metadata"] = {"r1": {"batch": "B1"}}
        value["payload"]["updates"] = [{
            "update_id": "u1", "sequence": 1, "kind": "amendment", "text": "Update text",
            "effective_at": "2026-01-01T00:00:00Z", "effective_boundary": "inclusive",
            "applies_to": {"predicate_id": "p1"}, "supersedes": [],
        }]
        value["payload"]["notice"].update({
            "issued_at": "2026-01-01T00:00:00Z", "governing_event": {"source": "table_field", "table": "L", "field": "at"},
            "effective_at": "2026-01-01T00:00:00Z", "effective_boundary": "exclusive",
            "scope": {"fields": ["label"], "predicate_id": "p1"},
            "exclusion_ids": ["x1"], "exception_ids": ["x2"], "evidence_ids": ["e1"],
        })
        value["payload"]["temporal_conditions"] = [{
            "condition_id": "tc1", "instruction_id": "notice-1", "predicate_id": "p1",
            "governing_event": {"source": "table_field", "table": "L", "field": "at"},
            "effective_at": "2026-01-01T00:00:00Z", "effective_boundary": "exclusive",
        }]
        original = copy.deepcopy(value)
        expected = {
            **{key: value[key] for key in ("schema_version", "profile", "case_id", "task")},
            "payload": {
                "field_declarations": value["payload"]["field_declarations"],
                "ledger": value["payload"]["ledger"],
                "original_guideline": value["payload"]["original_guideline"],
                "updates": [{key: value["payload"]["updates"][0][key] for key in ("update_id", "sequence", "kind", "text")}],
                "notice": {key: value["payload"]["notice"][key] for key in ("notice_id", "operation", "issued_at", "authority_text")},
                "metadata_declarations": value["payload"]["metadata_declarations"],
                "record_metadata": value["payload"]["record_metadata"],
            },
        }

        self.assertEqual(instruction_resolution(value), expected)
        self.assertEqual(value, original)  # projection does not mutate the trusted source object

    def test_contract_projection_has_exact_contract_member_set(self):
        value = case()
        contract = {"contract_version": "1", "profile": value["profile"], "target_fields": [], "predicate_definitions": [], "governing_event": {"source": "table_field", "table": "L", "field": "at"}, "temporal_conditions": [], "exclusions": [], "exceptions_applied": []}
        self.assertIn("scope_contract", resolved_contract(value, contract))
        with self.assertRaises(ValueError): resolved_contract(value, {**contract, "extra": 1})
        with self.assertRaisesRegex(ValueError, "json_null_forbidden"):
            resolved_contract(value, {**contract, "predicate_definitions": [{"predicate_id": "p", "expression": None}]})


if __name__ == "__main__": unittest.main()
