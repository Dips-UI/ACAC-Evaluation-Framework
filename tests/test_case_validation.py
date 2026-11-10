"""Synthetic Phase 2 case validation tests; no protected artifacts are used."""

import unittest
import copy

from acac.case_validation import validate_case


def case(profile="single-ledger-1.0"):
    table = "L" if profile == "single-ledger-1.0" else "W"
    payload = {
        "field_declarations": [{"table": table, "field": "label", "type": "string", "mutable": True}],
        "ledger": {"L": [{"record_id": "r1", "values": {"label": "OLD"}}]} if table == "L" else {
            "M": [{"record_id": "r1", "values": {"text": "Stop"}}],
            "H": [{"record_id": "r1", "values": {"label": "OLD"}}],
            "W": [{"record_id": "r1", "values": {"label": "OLD"}}],
        },
        "original_guideline": "Classify explicit cancellation requests as CANCEL.",
        "updates": [],
        "notice": {"notice_id": "notice-1", "operation": "case_correction", "authority_text": "Correct label.", "scope": {"fields": ["label"], "predicate_id": "p1"}},
    }
    if profile == "historical-ledger-1.0":
        payload["field_declarations"] = [
            {"table": "M", "field": "text", "type": "string", "mutable": False},
            {"table": "H", "field": "label", "type": "string", "mutable": False},
            {"table": "W", "field": "label", "type": "string", "mutable": True},
        ]
    return {"schema_version": "acac-1.3", "profile": profile, "case_id": "case-001", "task": "correct_ledger", "payload": payload}


class CaseValidationTests(unittest.TestCase):
    def test_profiles_and_envelope(self):
        self.assertTrue(validate_case(case()).valid)
        self.assertTrue(validate_case(case("historical-ledger-1.0")).valid)
        bad = case(); bad["schema_version"] = "acac-1.0"
        self.assertFalse(validate_case(bad).valid)

    def test_metadata_has_separate_schema(self):
        value = case(); value["payload"]["metadata_declarations"] = [{"field": "batch", "type": "string"}]
        value["payload"]["record_metadata"] = {"r1": {"batch": "B1"}}
        self.assertTrue(validate_case(value).valid)
        value["payload"]["metadata_declarations"][0]["mutable"] = False
        self.assertFalse(validate_case(value).valid)

    def test_supersedes_is_structural_only(self):
        value = case(); value["payload"]["updates"] = [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x", "supersedes": ["u1"]}]
        self.assertTrue(validate_case(value).valid)
        value["payload"]["updates"].append({"update_id": "u2", "sequence": 2, "kind": "amendment", "text": "y", "supersedes": ["u1"]})
        self.assertTrue(validate_case(value).valid)  # repeated reference across arrays is allowed
        value["payload"]["updates"][1]["supersedes"] = ["u1", "u1"]
        self.assertTrue(validate_case(value).valid)
        value["payload"]["updates"].pop()
        value["payload"]["updates"][0]["supersedes"] = ["missing"]
        self.assertFalse(validate_case(value).valid)

    def test_temporal_conditions_reconcile_notice_and_updates(self):
        value = case()
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        value["payload"]["notice"].update({"effective_at": "2026-02-03T00:00:00.1Z", "effective_boundary": "inclusive", "governing_event": {"source": "table_field", "table": "L", "field": "at"}})
        value["payload"]["updates"] = [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x", "effective_at": "2026-02-03T00:00:00.2Z", "effective_boundary": "exclusive"}]
        locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["temporal_conditions"] = [
            {"condition_id": "tc-n", "instruction_id": "notice-1", "predicate_id": "p1", "governing_event": locator, "effective_at": "2026-02-03T00:00:00.1Z", "effective_boundary": "inclusive"},
            {"condition_id": "tc-u", "instruction_id": "u1", "predicate_id": "p1", "governing_event": locator, "effective_at": "2026-02-03T00:00:00.2Z", "effective_boundary": "exclusive"},
        ]
        self.assertTrue(validate_case(value).valid)
        value["payload"]["temporal_conditions"].pop()
        self.assertFalse(validate_case(value).valid)

    def test_temporal_mapping_mismatches_are_rejected(self):
        value = case()
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        notice_locator = {"source": "table_field", "table": "L", "field": "at"}
        condition_locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["notice"].update({"effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive", "governing_event": notice_locator})
        value["payload"]["temporal_conditions"] = [{"condition_id": "tc", "instruction_id": "notice-1", "predicate_id": "p1", "governing_event": condition_locator, "effective_at": "2026-02-03T00:00:01Z", "effective_boundary": "inclusive"}]
        self.assertFalse(validate_case(value).valid)  # timestamp mismatch
        value["payload"]["temporal_conditions"][0]["effective_at"] = "2026-02-03T00:00:00Z"
        value["payload"]["temporal_conditions"][0]["effective_boundary"] = "exclusive"
        self.assertFalse(validate_case(value).valid)  # boundary mismatch
        value["payload"]["temporal_conditions"][0]["effective_boundary"] = "inclusive"
        value["payload"]["temporal_conditions"][0]["instruction_id"] = "missing"
        self.assertFalse(validate_case(value).valid)  # unknown instruction

    def test_duplicate_temporal_instruction_and_locator_mismatch(self):
        value = case()
        for field in ("at", "other_at"):
            value["payload"]["field_declarations"].append({"table": "L", "field": field, "type": "string", "format": "rfc3339-timestamp", "mutable": False})
            value["payload"]["ledger"]["L"][0]["values"][field] = "2026-02-03T00:00:00Z"
        locator = {"source": "table_field", "table": "L", "field": "at"}
        other = {"source": "table_field", "table": "L", "field": "other_at"}
        value["payload"]["notice"].update({"effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive", "governing_event": locator})
        condition = {"condition_id": "tc", "instruction_id": "notice-1", "predicate_id": "p1", "governing_event": locator, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"}
        value["payload"]["temporal_conditions"] = [condition, dict(condition, condition_id="tc-2")]
        self.assertFalse(validate_case(value).valid)
        value["payload"]["temporal_conditions"] = [dict(condition, governing_event=other)]
        self.assertFalse(validate_case(value).valid)

    def test_extra_condition_for_update_without_effective_at(self):
        value = case()
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        value["payload"]["updates"] = [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x"}]
        value["payload"]["temporal_conditions"] = [{"condition_id": "tc", "instruction_id": "u1", "predicate_id": "p1", "governing_event": {"source": "table_field", "table": "L", "field": "at"}, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"}]
        result = validate_case(value)
        self.assertFalse(result.valid)
        self.assertIn("extra_update_temporal_condition", result.errors)

    def test_multiple_original_temporal_conditions_preserve_canonical_records(self):
        value = case()
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        locator = {"source": "table_field", "table": "L", "field": "at"}
        conditions = [
            {"condition_id": "tc-original-1", "instruction_id": "original", "predicate_id": "p1", "governing_event": locator, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"},
            {"condition_id": "tc-original-2", "instruction_id": "original", "predicate_id": "p2", "governing_event": locator, "effective_at": "2026-02-04T00:00:00Z", "effective_boundary": "exclusive"},
        ]
        value["payload"]["temporal_conditions"] = copy.deepcopy(conditions)

        result = validate_case(value)

        self.assertTrue(result.valid, result.errors)
        self.assertEqual(result.temporal_validation_status, "validated")
        self.assertEqual(result.normalized_case["payload"]["temporal_conditions"], conditions)
        self.assertEqual([item["condition_id"] for item in result.normalized_case["payload"]["temporal_conditions"]], ["tc-original-1", "tc-original-2"])
        self.assertEqual([item["predicate_id"] for item in result.normalized_case["payload"]["temporal_conditions"]], ["p1", "p2"])

    def test_duplicate_temporal_condition_ids_are_rejected(self):
        value = case()
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        condition = {"condition_id": "tc", "instruction_id": "original", "predicate_id": "p1", "governing_event": {"source": "table_field", "table": "L", "field": "at"}, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"}
        value["payload"]["temporal_conditions"] = [condition, dict(condition, predicate_id="p2")]

        result = validate_case(value)

        self.assertFalse(result.valid)
        self.assertIn("duplicate_condition_id", result.errors)

    def test_notice_without_temporal_fields_rejects_matching_condition(self):
        value = case()
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        value["payload"]["temporal_conditions"] = [{"condition_id": "tc", "instruction_id": "notice-1", "predicate_id": "p1", "governing_event": {"source": "table_field", "table": "L", "field": "at"}, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"}]

        result = validate_case(value)

        self.assertFalse(result.valid)
        self.assertIn("extra_notice_temporal_condition", result.errors)

    def test_original_only_temporal_condition_is_structural(self):
        value = case()
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        value["payload"]["temporal_conditions"] = [{"condition_id": "tc", "instruction_id": "original", "predicate_id": "p1", "governing_event": {"source": "table_field", "table": "L", "field": "at"}, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"}]
        self.assertEqual(validate_case(value).temporal_validation_status, "validated")

    def test_governing_event_requires_timestamp_declaration(self):
        value = case(); value["payload"]["notice"].update({"effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive", "governing_event": {"source": "table_field", "table": "L", "field": "label"}})
        self.assertFalse(validate_case(value).valid)

    def test_metadata_timestamp_governing_event(self):
        value = case(); value["payload"]["metadata_declarations"] = [{"field": "at", "type": "string", "format": "rfc3339-timestamp"}]
        value["payload"]["record_metadata"] = {"r1": {"at": "2026-02-03T00:00:00Z"}}
        value["payload"]["notice"].update({"effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive", "governing_event": {"source": "record_metadata", "field": "at"}})
        value["payload"]["temporal_conditions"] = [{"condition_id": "tc", "instruction_id": "notice-1", "predicate_id": "p1", "governing_event": {"source": "record_metadata", "field": "at"}, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"}]
        self.assertTrue(validate_case(value).valid)

    def test_notice_reference_arrays_and_malformed_values_fail_safely(self):
        value = case(); value["payload"]["notice"]["evidence_ids"] = ["e1", "e2"]
        self.assertTrue(validate_case(value).valid)
        value["payload"]["notice"]["evidence_ids"] = "e1"
        result = validate_case(value)
        self.assertFalse(result.valid)
        value["payload"]["notice"]["evidence_ids"] = [1]
        self.assertFalse(validate_case(value).valid)
        malformed = case(); malformed["payload"]["field_declarations"] = None
        self.assertFalse(validate_case(malformed).valid)

    def test_identifier_whitespace_rules(self):
        value = case(); value["case_id"] = " id "
        self.assertFalse(validate_case(value).valid)
        value["case_id"] = "id with space"
        self.assertTrue(validate_case(value).valid)
        value["case_id"] = "案件 α"
        self.assertTrue(validate_case(value).valid)
        value["case_id"] = "A\u0085B"
        self.assertFalse(validate_case(value).valid)
        value["case_id"] = "A\u200BB"
        self.assertFalse(validate_case(value).valid)
        value["case_id"] = " id"
        self.assertFalse(validate_case(value).valid)
        value["case_id"] = "id "
        self.assertFalse(validate_case(value).valid)

    def test_no_op_handoff_is_empty_without_sidecar_claims(self):
        value = case(); value["payload"]["notice"] = {"notice_id": "n", "operation": "no_op", "authority_text": "No change.", "scope": {"fields": []}}
        result = validate_case(value)
        self.assertTrue(result.valid)
        self.assertEqual(result.no_op_handoff_status, "empty")
        value["payload"]["notice"]["scope"]["fields"] = ["label"]
        self.assertFalse(validate_case(value).valid)

    def test_explicit_null_temporal_conditions_are_rejected(self):
        value = case()
        value["payload"]["temporal_conditions"] = None
        result = validate_case(value)
        self.assertFalse(result.valid)
        self.assertIn("temporal_conditions_null_forbidden", result.errors)

    def test_structured_original_temporal_condition(self):
        value = case(); value["payload"]["notice"].update({"effective_at": "2026-02-03T00:00:00.0000000001Z", "effective_boundary": "inclusive", "governing_event": {"source": "table_field", "table": "L", "field": "annotated_at"}})
        value["payload"]["field_declarations"].append({"table": "L", "field": "annotated_at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["annotated_at"] = "2026-02-03T00:00:00Z"
        value["payload"]["temporal_conditions"] = [{"condition_id": "tc", "instruction_id": "notice-1", "predicate_id": "p1", "governing_event": {"source": "table_field", "table": "L", "field": "annotated_at"}, "effective_at": "2026-02-03T00:00:00.0000000001Z", "effective_boundary": "inclusive"}]
        result = validate_case(value)
        self.assertTrue(result.valid)
        self.assertEqual(result.temporal_validation_status, "validated")

    def test_duplicate_supersedes_references_are_allowed(self):
        value = case()
        value["payload"]["updates"] = [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x"}, {"update_id": "u2", "sequence": 2, "kind": "amendment", "text": "y", "supersedes": ["u1", "u1"]}]
        self.assertTrue(validate_case(value).valid)
        value["payload"]["updates"][1]["supersedes"] = ["unknown"]
        self.assertFalse(validate_case(value).valid)

    def test_envelope_and_payload_rejections(self):
        value = case(); value["extra"] = 1
        self.assertFalse(validate_case(value).valid)
        value = case(); value["payload"]["extra"] = 1
        self.assertFalse(validate_case(value).valid)
        value = case(); del value["case_id"]
        self.assertFalse(validate_case(value).valid)
        value = case(); value["profile"] = None
        self.assertFalse(validate_case(value).valid)
        self.assertFalse(validate_case([]).valid)
        value = case(); value["payload"] = []
        self.assertFalse(validate_case(value).valid)

    def test_field_declaration_boundaries(self):
        value = case(); value["payload"]["field_declarations"].append(dict(value["payload"]["field_declarations"][0]))
        self.assertFalse(validate_case(value).valid)
        for key, bad in (("type", "number"), ("format", "bad"), ("description", 1), ("table", "X")):
            value = case(); decl = value["payload"]["field_declarations"][0]; decl[key] = bad
            self.assertFalse(validate_case(value).valid)
        value = case("historical-ledger-1.0"); value["payload"]["field_declarations"][0]["mutable"] = True
        self.assertFalse(validate_case(value).valid)
        value = case("historical-ledger-1.0"); value["payload"]["field_declarations"].append({"table": "W", "field": "note", "type": "string", "mutable": True})
        for row in value["payload"]["ledger"]["W"]: row["values"]["note"] = "ok"
        self.assertTrue(validate_case(value).valid)

    def test_ledger_structure_and_types(self):
        value = case(); value["payload"]["ledger"]["L"].append(copy.deepcopy(value["payload"]["ledger"]["L"][0]))
        self.assertFalse(validate_case(value).valid)
        for values in ({}, {"label": "OLD", "extra": "x"}, {"label": 1}, {"label": None}):
            value = case(); value["payload"]["ledger"]["L"][0]["values"] = values
            self.assertFalse(validate_case(value).valid)
        value = case(); value["payload"]["ledger"]["X"] = []
        self.assertFalse(validate_case(value).valid)
        value = case(); value["payload"]["ledger"]["L"] = []
        self.assertTrue(validate_case(value).valid)
        value = case("historical-ledger-1.0"); value["payload"]["ledger"]["H"][0]["record_id"] = "r2"
        self.assertFalse(validate_case(value).valid)

    def test_metadata_structure_and_types(self):
        value = case(); value["payload"]["metadata_declarations"] = [{"field": "batch", "type": "string"}, {"field": "batch", "type": "string"}]
        value["payload"]["record_metadata"] = {"r1": {"batch": "B"}}
        self.assertFalse(validate_case(value).valid)
        for metadata in ({}, {"r1": {}}, {"r1": {"batch": "B", "extra": "x"}}, {"r1": {"batch": 1}}, {"r1": {"batch": None}}):
            value = case(); value["payload"]["metadata_declarations"] = [{"field": "batch", "type": "string"}]; value["payload"]["record_metadata"] = metadata
            self.assertFalse(validate_case(value).valid)
        value = case(); value["payload"]["metadata_declarations"] = [{"field": "at", "type": "string", "format": "rfc3339-timestamp"}]; value["payload"]["record_metadata"] = {"r1": {"at": "not-a-time"}}
        self.assertFalse(validate_case(value).valid)

    def test_update_validation_boundaries(self):
        value = case(); value["payload"]["updates"] = []
        self.assertTrue(validate_case(value).valid)
        for updates in ([{"update_id": "u1", "sequence": 0, "kind": "amendment", "text": "x"}], [{"update_id": "u1", "sequence": 1, "kind": "bad", "text": "x"}], [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x", "effective_at": "bad"}], [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x", "effective_boundary": "inclusive"}], [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x", "applies_to": []}], [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": None}]):
            value = case(); value["payload"]["updates"] = updates
            self.assertFalse(validate_case(value).valid)
        for kind in ("clarification", "amendment", "temporary", "rollback", "administrative"):
            value = case(); value["payload"]["updates"] = [{"update_id": "u1", "sequence": 1, "kind": kind, "text": "x"}]
            self.assertTrue(validate_case(value).valid)
        value = case(); value["payload"]["updates"] = [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x"}, {"update_id": "u2", "sequence": 1, "kind": "amendment", "text": "y"}]
        self.assertFalse(validate_case(value).valid)

    def test_notice_operations_and_rejections(self):
        for operation in ("prospective", "retrospective_backfill", "case_correction", "rollback", "no_op"):
            value = case(); value["payload"]["notice"]["operation"] = operation
            if operation == "no_op": value["payload"]["notice"]["scope"] = {"fields": []}
            self.assertTrue(validate_case(value).valid)
        for key, bad in (("operation", "bad"), ("authority_text", 1), ("issued_at", "bad"), ("scope", None), ("exclusion_ids", [1]), ("exception_ids", "x"), ("evidence_ids", None)):
            value = case(); value["payload"]["notice"][key] = bad
            self.assertFalse(validate_case(value).valid)
        value = case(); value["payload"]["notice"]["scope"]["fields"] = ["unknown"]
        self.assertFalse(validate_case(value).valid)

    def test_temporal_condition_edge_cases(self):
        value = case(); value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False}); value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["notice"].update({"effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive", "governing_event": locator})
        condition = {"condition_id": "tc", "instruction_id": "notice-1", "predicate_id": "p1", "governing_event": locator, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"}
        value["payload"]["temporal_conditions"] = [condition, dict(condition, condition_id="tc2")]
        self.assertFalse(validate_case(value).valid)
        value["payload"]["temporal_conditions"] = [dict(condition, effective_at=None)]
        self.assertFalse(validate_case(value).valid)
        value = case(); value["payload"]["notice"]["governing_event"] = locator
        self.assertFalse(validate_case(value).valid)
        value = case(); value["payload"]["notice"]["effective_at"] = "2026-02-03T00:00:00Z"
        self.assertFalse(validate_case(value).valid)

    def test_multiple_update_temporal_conditions_reconcile(self):
        value = case()
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["updates"] = [
            {"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x", "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"},
            {"update_id": "u2", "sequence": 2, "kind": "clarification", "text": "y", "effective_at": "2026-02-03T00:00:01Z", "effective_boundary": "exclusive"},
        ]
        value["payload"]["temporal_conditions"] = [
            {"condition_id": "tc1", "instruction_id": "u1", "predicate_id": "p1", "governing_event": locator, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"},
            {"condition_id": "tc2", "instruction_id": "u2", "predicate_id": "p1", "governing_event": locator, "effective_at": "2026-02-03T00:00:01Z", "effective_boundary": "exclusive"},
        ]
        self.assertTrue(validate_case(value).valid)

    def test_update_temporal_condition_remains_exactly_one(self):
        value = case()
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        value["payload"]["updates"] = [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x", "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"}]
        condition = {"condition_id": "tc1", "instruction_id": "u1", "predicate_id": "p1", "governing_event": {"source": "table_field", "table": "L", "field": "at"}, "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive"}
        value["payload"]["temporal_conditions"] = [condition, dict(condition, condition_id="tc2")]

        result = validate_case(value)

        self.assertFalse(result.valid)
        self.assertIn("duplicate_temporal_instruction_mapping", result.errors)

    def test_malformed_nested_values_fail_safely(self):
        for malformed in ({1: "x"}, {"payload": {1: "x"}}):
            result = validate_case(malformed)
            self.assertFalse(result.valid)
            self.assertTrue(result.errors)
        value = case(); value["payload"]["notice"]["scope"] = {"fields": [None]}
        self.assertFalse(validate_case(value).valid)
        value = case(); value["payload"]["temporal_conditions"] = [{}]
        self.assertFalse(validate_case(value).valid)


if __name__ == "__main__":
    unittest.main()
