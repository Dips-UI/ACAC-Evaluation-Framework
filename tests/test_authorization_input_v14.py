"""Synthetic v1.4 authorization-input tests; no protected artifacts are read."""

import hashlib
import json
import unittest
from copy import deepcopy

from acac.authorization_input import validate_authorization_input
from acac.canonical import semantic_hash
from tests.test_case_validation import case as make_case


def stored(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def input_for(case_value=None):
    case_value = deepcopy(case_value or make_case())
    case_bytes = stored(case_value)
    case_hash = "sha256:" + hashlib.sha256(case_bytes).hexdigest()
    notice_id = case_value["payload"]["notice"]["notice_id"]
    table = "L" if case_value["profile"] == "single-ledger-1.0" else "W"
    eligible_key = [table, "r1", "label"]
    ledger_cells = {
        (table_name, row["record_id"], field): cell
        for table_name, rows in case_value["payload"]["ledger"].items()
        for row in rows
        for field, cell in row["values"].items()
    }
    resolution = {
        "governing_instruction_ids": [notice_id],
        "predicate_definitions": [{"predicate_id": "p1", "expression": {"record_ids": ["r1"]}}],
        "evidence_registry": [],
        "eligible_keys": [eligible_key],
        "eligibility_rationale": [{
            "key": eligible_key, "included_by": ["p1"],
            "excluded_by": [], "instruction_ids": [notice_id],
        }],
        "exclusions": [],
        "exceptions_applied": [],
        "required_final_values": [{"key": eligible_key, "value": "NEW"}],
        "preservation_keys": [list(key) for key, old in ledger_cells.items() if list(key) != eligible_key and old != "NEW"],
        "rationale_by_key": [{"key": eligible_key, "instruction_ids": [notice_id], "reason": "Synthetic authorization"}],
    }
    value = {
        "schema_version": "acac-auth-input-1.0",
        "case_id": case_value["case_id"],
        "source_case_hash": case_hash,
        "profile": case_value["profile"],
        **resolution,
    }
    return case_value, case_bytes, value


def validate(value, case_value, case_bytes):
    return validate_authorization_input(
        value, case_value, authorization_input_bytes=stored(value), case_bytes=case_bytes
    )


class AuthorizationInputV14Tests(unittest.TestCase):
    def test_evidence_registry_content_hash_is_semantic_hash_sensitive(self):
        case_value, case_bytes, base = input_for()
        evidence_one = b"synthetic retained evidence one"
        evidence_two = b"synthetic retained evidence two"
        hash_one = "sha256:" + hashlib.sha256(evidence_one).hexdigest()
        hash_two = "sha256:" + hashlib.sha256(evidence_two).hexdigest()

        first = deepcopy(base)
        first["evidence_registry"] = [{
            "evidence_id": "evidence-1", "content_hash": hash_one,
            "description": "Synthetic evidence",
        }]
        second = deepcopy(first)
        second["evidence_registry"][0]["content_hash"] = hash_two
        retained = {hash_one: evidence_one, hash_two: evidence_two}

        first_result = validate_authorization_input(
            first, case_value, authorization_input_bytes=stored(first),
            case_bytes=case_bytes, retained_artifacts=retained,
        )
        second_result = validate_authorization_input(
            second, case_value, authorization_input_bytes=stored(second),
            case_bytes=case_bytes, retained_artifacts=retained,
        )

        self.assertTrue(first_result.valid, first_result.errors)
        self.assertTrue(second_result.valid, second_result.errors)
        self.assertNotEqual(semantic_hash(first), semantic_hash(second))

    def test_explicit_notice_record_and_field_scope_derives_exact_key(self):
        case_value, case_bytes, value = input_for()
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)

        unsupported = deepcopy(value)
        resolution = unsupported
        case_value["payload"]["field_declarations"].append({
            "table": "L", "field": "other", "type": "string", "mutable": True,
        })
        case_value["payload"]["ledger"]["L"][0]["values"]["other"] = "OLD"
        case_bytes = stored(case_value)
        unsupported["source_case_hash"] = "sha256:" + hashlib.sha256(case_bytes).hexdigest()
        extra_key = ["L", "r1", "other"]
        resolution["eligible_keys"].append(extra_key)
        resolution["required_final_values"].append({"key": extra_key, "value": "NEW"})
        resolution["eligibility_rationale"].append({
            "key": extra_key, "included_by": ["p1"], "excluded_by": [],
            "instruction_ids": ["notice-1"],
        })
        resolution["rationale_by_key"].append({
            "key": extra_key, "instruction_ids": ["notice-1"],
            "reason": "Synthetic unsupported field inclusion",
        })
        resolution["preservation_keys"] = []
        result = validate(unsupported, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("eligible_key_unsupported_by_scope", result.errors)

    def test_eligible_key_completeness_rejects_missing_key(self):
        case_value, case_bytes, value = input_for()
        resolution = value
        resolution["eligible_keys"] = []
        resolution["eligibility_rationale"] = []
        resolution["required_final_values"] = []
        resolution["preservation_keys"] = [["L", "r1", "label"]]
        resolution["rationale_by_key"] = []
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("eligible_key_missing_from_scope", result.errors)

    def test_rationale_by_key_requires_exact_eligible_key_coverage(self):
        case_value, case_bytes, value = input_for()
        variants = (
            [],
            [*value["rationale_by_key"], deepcopy(value["rationale_by_key"][0])],
            [{**deepcopy(value["rationale_by_key"][0]), "key": ["L", "other", "label"]}],
        )
        for rationale in variants:
            with self.subTest(rationale=rationale):
                candidate = deepcopy(value)
                candidate["rationale_by_key"] = rationale
                result = validate(candidate, case_value, case_bytes)
                self.assertFalse(result.valid)
                self.assertIn("rationale_by_key_coverage", result.errors)

    def test_non_governing_update_does_not_expand_or_conflict_with_notice_scope(self):
        case_value = make_case()
        case_value["payload"]["updates"] = [{
            "update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x",
            "applies_to": {"predicate_id": "p2"},
        }]
        case_value, case_bytes, value = input_for(case_value)
        value["predicate_definitions"].append({
            "predicate_id": "p2", "expression": {"record_ids": ["r-other"]},
        })
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)

    def test_exception_reference_can_use_known_instruction_outside_governing_list(self):
        case_value = make_case()
        case_value["payload"]["updates"] = [{
            "update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x",
            "applies_to": {"predicate_id": "p1"},
        }]
        case_value["payload"]["notice"]["exclusion_ids"] = ["x1"]
        case_value["payload"]["notice"]["exception_ids"] = ["e1"]
        case_value, case_bytes, value = input_for(case_value)
        value["exclusions"] = [{
            "exclusion_id": "x1", "predicate_id": "p1",
            "instruction_ids": ["notice-1", "u1"], "reason": "Synthetic exclusion",
        }]
        value["exceptions_applied"] = [{
            "exception_id": "e1", "record_ids": ["r1"],
            "instruction_ids": ["notice-1", "u1"], "reason": "Reviewed exception",
        }]
        value["eligibility_rationale"][0]["excluded_by"] = ["x1"]
        value["required_final_values"][0]["value"] = "OLD"
        value["preservation_keys"] = [["L", "r1", "label"]]
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)
        self.assertNotIn("u1", value["governing_instruction_ids"])

    def test_unknown_exception_instruction_reference_is_rejected(self):
        case_value = make_case()
        case_value["payload"]["notice"]["exception_ids"] = ["e1"]
        case_value, case_bytes, value = input_for(case_value)
        value["exceptions_applied"] = [{
            "exception_id": "e1", "record_ids": ["r1"],
            "instruction_ids": ["missing-instruction"], "reason": "Synthetic exception",
        }]
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("unknown_exception_instruction", result.errors)

    def test_differing_instruction_predicate_scopes_fail_closed(self):
        case_value = make_case()
        case_value["payload"]["updates"] = [{
            "update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x",
            "applies_to": {"predicate_id": "p2"},
        }]
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["governing_instruction_ids"].append("u1")
        resolution["predicate_definitions"].append({
            "predicate_id": "p2", "expression": {"record_ids": ["r-other"]},
        })
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("eligibility_instruction_scope_composition_unresolved", result.errors)

    def test_missing_notice_record_scope_fails_closed(self):
        case_value = make_case()
        case_value["payload"]["notice"]["scope"].pop("predicate_id")
        case_value, case_bytes, value = input_for(case_value)
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("eligibility_record_scope_unresolved", result.errors)

    def test_governing_update_without_structured_scope_fails_closed(self):
        case_value = make_case()
        case_value["payload"]["updates"] = [{
            "update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x",
        }]
        case_value, case_bytes, value = input_for(case_value)
        value["governing_instruction_ids"].append("u1")
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("eligibility_update_scope_unresolved", result.errors)

    def test_identical_explicit_notice_and_update_predicates_reconcile(self):
        case_value = make_case()
        case_value["payload"]["updates"] = [{
            "update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x",
            "applies_to": {"predicate_id": "p2"},
        }]
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["governing_instruction_ids"].append("u1")
        resolution["predicate_definitions"].append({
            "predicate_id": "p2", "expression": {"record_ids": ["r1"]},
        })
        resolution["eligibility_rationale"][0]["included_by"].append("p2")
        resolution["eligibility_rationale"][0]["instruction_ids"].append("u1")
        resolution["rationale_by_key"][0]["instruction_ids"].append("u1")
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)

    def test_exclusion_removes_matching_key_but_not_matches_outside_scope(self):
        case_value = make_case()
        case_value["payload"]["ledger"]["L"].append({
            "record_id": "r2", "values": {"label": "OLD"},
        })
        case_value["payload"]["notice"]["exclusion_ids"] = ["x1"]
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["predicate_definitions"].append({
            "predicate_id": "exclude-r2", "expression": {"record_ids": ["r2"]},
        })
        resolution["exclusions"] = [{
            "exclusion_id": "x1", "predicate_id": "exclude-r2",
            "instruction_ids": ["notice-1"], "reason": "Outside selected records",
        }]
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)

        case_value["payload"]["ledger"]["L"].append({
            "record_id": "r3", "values": {"label": "OLD"},
        })
        case_value["payload"]["notice"]["scope"]["predicate_id"] = "p1"
        case_bytes = stored(case_value)
        value["source_case_hash"] = "sha256:" + hashlib.sha256(case_bytes).hexdigest()
        value["predicate_definitions"][1]["expression"] = {"record_ids": ["r1"]}
        value["eligible_keys"] = []
        value["eligibility_rationale"] = []
        value["required_final_values"] = []
        value["preservation_keys"] = [
            ["L", record_id, "label"] for record_id in ("r1", "r2", "r3")
        ]
        value["rationale_by_key"] = []
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)

    def test_explicit_exception_authority_preserves_eligible_preservation_overlap(self):
        case_value = make_case()
        case_value["payload"]["notice"]["exclusion_ids"] = ["x1"]
        case_value["payload"]["notice"]["exception_ids"] = ["e1"]
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["predicate_definitions"].append({
            "predicate_id": "exclude-r1", "expression": {"record_ids": ["r1"]},
        })
        resolution["exclusions"] = [{
            "exclusion_id": "x1", "predicate_id": "exclude-r1",
            "instruction_ids": ["notice-1"], "reason": "Synthetic exclusion",
        }]
        resolution["exceptions_applied"] = [{
            "exception_id": "e1", "record_ids": ["r1"],
            "instruction_ids": ["notice-1"], "reason": "Explicitly authorized exception",
        }]
        resolution["eligibility_rationale"][0]["excluded_by"] = ["x1"]
        resolution["required_final_values"][0]["value"] = "OLD"
        resolution["preservation_keys"] = [["L", "r1", "label"]]
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)

    def test_exception_without_exclusion_authority_fails_closed(self):
        case_value = make_case()
        case_value["payload"]["notice"]["exclusion_ids"] = ["x1"]
        case_value["payload"]["notice"]["exception_ids"] = ["e1"]
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["governing_instruction_ids"].append("original")
        resolution["predicate_definitions"].append({
            "predicate_id": "exclude-r1", "expression": {"record_ids": ["r1"]},
        })
        resolution["exclusions"] = [{
            "exclusion_id": "x1", "predicate_id": "exclude-r1",
            "instruction_ids": ["notice-1"], "reason": "Synthetic exclusion",
        }]
        resolution["exceptions_applied"] = [{
            "exception_id": "e1", "record_ids": ["r1"],
            "instruction_ids": ["original"], "reason": "No matching override authority",
        }]
        resolution["eligibility_rationale"][0]["instruction_ids"].append("original")
        resolution["rationale_by_key"][0]["instruction_ids"].append("original")
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("exception_exclusion_association_unresolved", result.errors)

    def test_exception_without_exclusion_applicability_fails_closed(self):
        case_value = make_case()
        case_value["payload"]["notice"]["exclusion_ids"] = ["x1"]
        case_value["payload"]["notice"]["exception_ids"] = ["e1"]
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["predicate_definitions"].append({
            "predicate_id": "exclude-r1", "expression": {"record_ids": ["r1"]},
        })
        resolution["exclusions"] = [{
            "exclusion_id": "x1", "predicate_id": "exclude-r1",
            "instruction_ids": ["notice-1"], "reason": "Synthetic exclusion",
        }]
        resolution["exceptions_applied"] = [{
            "exception_id": "e1", "record_ids": ["other-record"],
            "instruction_ids": ["notice-1"], "reason": "Nonmatching exception",
        }]
        resolution["eligibility_rationale"][0]["excluded_by"] = ["x1"]
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("exception_applicability_unresolved", result.errors)

    def test_exception_cannot_be_inferred_to_override_multiple_exclusions(self):
        case_value = make_case()
        case_value["payload"]["notice"]["exclusion_ids"] = ["x1", "x2"]
        case_value["payload"]["notice"]["exception_ids"] = ["e1"]
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["predicate_definitions"].extend([
            {"predicate_id": "exclude-1", "expression": {"record_ids": ["r1"]}},
            {"predicate_id": "exclude-2", "expression": {"record_ids": ["r1"]}},
        ])
        resolution["exclusions"] = [
            {"exclusion_id": "x1", "predicate_id": "exclude-1", "instruction_ids": ["notice-1"], "reason": "First exclusion"},
            {"exclusion_id": "x2", "predicate_id": "exclude-2", "instruction_ids": ["notice-1"], "reason": "Second exclusion"},
        ]
        resolution["exceptions_applied"] = [{
            "exception_id": "e1", "record_ids": ["r1"],
            "instruction_ids": ["notice-1"], "reason": "Ambiguous exclusion target",
        }]
        resolution["eligibility_rationale"][0]["excluded_by"] = ["x1", "x2"]
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("exception_exclusion_association_unresolved", result.errors)

    def test_temporal_predicate_must_not_be_combined_implicitly(self):
        case_value = make_case()
        case_value["payload"]["field_declarations"].append({
            "table": "L", "field": "at", "type": "string",
            "format": "rfc3339-timestamp", "mutable": False,
        })
        case_value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-01-01T00:00:00Z"
        case_value["payload"]["ledger"]["L"].append({
            "record_id": "r2", "values": {"label": "OLD", "at": "2026-03-01T00:00:00Z"},
        })
        locator = {"source": "table_field", "table": "L", "field": "at"}
        case_value["payload"]["notice"].update({
            "effective_at": "2026-02-01T00:00:00Z", "effective_boundary": "inclusive",
            "governing_event": locator,
        })
        case_value["payload"]["temporal_conditions"] = [{
            "condition_id": "tc1", "instruction_id": "notice-1", "predicate_id": "p2",
            "governing_event": locator, "effective_at": "2026-02-01T00:00:00Z",
            "effective_boundary": "inclusive",
        }]
        case_value, case_bytes, value = input_for(case_value)
        value["governing_event"] = locator
        value["predicate_definitions"].append({
            "predicate_id": "p2", "expression": {"record_ids": ["r2"]},
        })
        value["temporal_rules"] = [{
            "rule_id": "rule1", "source_condition_id": "tc1",
            "source_location": "/payload/temporal_conditions/0", "occurrence_index": 0,
            "instruction_id": "notice-1", "predicate_id": "p2",
            "effective_at": "2026-02-01T00:00:00Z", "effective_boundary": "inclusive",
        }]
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("eligibility_predicate_composition_unresolved", result.errors)

    def test_status_free_input_validates_with_exact_retained_case_bytes(self):
        case_value, case_bytes, value = input_for()
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)
        self.assertIsNone(result.status)
        self.assertTrue(result.input_hash.startswith("sha256:"))

    def test_historical_profile_accepts_mutable_working_cell(self):
        case_value, case_bytes, value = input_for(make_case("historical-ledger-1.0"))
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)
        value["eligible_keys"] = [["H", "r1", "label"]]
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("eligible_key_not_mutable_or_missing", result.errors)

    def test_source_case_hash_mismatch_fails_closed(self):
        case_value, case_bytes, value = input_for()
        value["source_case_hash"] = "sha256:" + "0" * 64
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("source_case_hash_mismatch", result.errors)

    def test_no_op_requires_empty_eligibility_value_and_rationale_arrays(self):
        case_value = make_case()
        case_value["payload"]["notice"] = {
            "notice_id": "notice-1", "operation": "no_op", "authority_text": "No changes",
            "scope": {"fields": []},
        }
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["eligible_keys"] = []
        resolution["eligibility_rationale"] = []
        resolution["required_final_values"] = []
        resolution["preservation_keys"] = [["L", "r1", "label"]]
        resolution["rationale_by_key"] = []
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)
        resolution["eligible_keys"] = [["L", "r1", "label"]]
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("no_op_authorization_must_be_empty", result.errors)

    def test_no_op_cannot_claim_an_applied_exception_without_scope(self):
        case_value = make_case()
        case_value["payload"]["notice"] = {
            "notice_id": "notice-1", "operation": "no_op", "authority_text": "No changes",
            "scope": {"fields": []}, "exception_ids": ["e1"],
        }
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["eligible_keys"] = []
        resolution["eligibility_rationale"] = []
        resolution["required_final_values"] = []
        resolution["preservation_keys"] = [["L", "r1", "label"]]
        resolution["rationale_by_key"] = []
        resolution["exceptions_applied"] = [{
            "exception_id": "e1", "record_ids": ["r1"],
            "instruction_ids": ["notice-1"], "reason": "No target key exists",
        }]
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("exception_applicability_unresolved", result.errors)

    def test_status_and_resolution_fields_are_forbidden_from_pre_review_input(self):
        case_value, case_bytes, value = input_for()
        for member, invalid_value in (
            ("resolution_status", "resolved"),
            ("resolution_issues", []),
            ("resolution", {}),
            ("resolved_by", []),
            ("resolution_note", "proposal"),
        ):
            with self.subTest(member=member):
                candidate = dict(value)
                candidate[member] = invalid_value
                result = validate(candidate, case_value, case_bytes)
                self.assertFalse(result.valid)
                self.assertIn("invalid_members", result.errors)

    def test_status_free_input_validates_as_a_proposed_basis(self):
        case_value, case_bytes, value = input_for()
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)
        self.assertIsNone(result.status)

    def test_explicit_null_and_extra_members_are_rejected(self):
        case_value, case_bytes, value = input_for()
        value["unexpected"] = None
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("json_null_forbidden", result.errors)
        value.pop("unexpected")
        value["extra"] = "x"
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("invalid_members", result.errors)

    def test_retained_bytes_comparison_distinguishes_boolean_and_integer(self):
        case_value, case_bytes, value = input_for()
        encoded_as_integer = deepcopy(value)
        encoded_as_integer["required_final_values"][0]["value"] = 1
        result = validate_authorization_input(
            value, case_value, authorization_input_bytes=stored(encoded_as_integer), case_bytes=case_bytes
        )
        self.assertFalse(result.valid)
        self.assertIn("retained_artifact_content_mismatch", result.errors)

    def test_temporal_input_maps_multiple_original_conditions_independently(self):
        case_value = make_case()
        case_value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        case_value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-02T00:00:00Z"
        locator = {"source": "table_field", "table": "L", "field": "at"}
        conditions = [
            {"condition_id": "tc-original-1", "instruction_id": "original", "predicate_id": "p1", "governing_event": locator, "effective_at": "2026-02-01T00:00:00Z", "effective_boundary": "inclusive"},
            {"condition_id": "tc-original-2", "instruction_id": "original", "predicate_id": "p2", "governing_event": locator, "effective_at": "2026-03-01T00:00:00Z", "effective_boundary": "exclusive"},
        ]
        case_value["payload"]["temporal_conditions"] = deepcopy(conditions)
        case_value, case_bytes, value = input_for(case_value)
        resolution = value
        resolution["governing_event"] = locator
        resolution["predicate_definitions"].append({"predicate_id": "p2", "expression": {"record_ids": ["r1"]}})
        resolution["temporal_rules"] = [
            {"rule_id": "rule-original-1", "source_condition_id": "tc-original-1", "source_location": "/payload/temporal_conditions/0", "occurrence_index": 0, "instruction_id": "original", "predicate_id": "p1", "effective_at": conditions[0]["effective_at"], "effective_boundary": "inclusive"},
            {"rule_id": "rule-original-2", "source_condition_id": "tc-original-2", "source_location": "/payload/temporal_conditions/1", "occurrence_index": 0, "instruction_id": "original", "predicate_id": "p2", "effective_at": conditions[1]["effective_at"], "effective_boundary": "exclusive"},
        ]

        result = validate(value, case_value, case_bytes)

        self.assertTrue(result.valid, result.errors)
        self.assertEqual([rule["source_condition_id"] for rule in resolution["temporal_rules"]], [condition["condition_id"] for condition in conditions])
        bad_mapping = deepcopy(value)
        bad_mapping["temporal_rules"][1]["predicate_id"] = "p1"
        result = validate(bad_mapping, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("temporal_predicate_mismatch", result.errors)

    def test_temporal_input_maps_rule_and_governing_event_to_case(self):
        case_value = make_case()
        case_value["payload"]["field_declarations"].append({
            "table": "L", "field": "at", "type": "string",
            "format": "rfc3339-timestamp", "mutable": False,
        })
        case_value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-02T00:00:00Z"
        locator = {"source": "table_field", "table": "L", "field": "at"}
        threshold = "2026-02-01T00:00:00.123456789Z"
        case_value["payload"]["notice"].update({
            "governing_event": locator, "effective_at": threshold,
            "effective_boundary": "inclusive",
        })
        case_value["payload"]["temporal_conditions"] = [{
            "condition_id": "condition-1", "instruction_id": "notice-1",
            "predicate_id": "p1", "governing_event": locator,
            "effective_at": threshold, "effective_boundary": "inclusive",
        }]
        case_value, case_bytes, value = input_for(case_value)
        value["governing_event"] = locator
        value["temporal_rules"] = [{
            "rule_id": "rule-1", "source_condition_id": "condition-1",
            "source_location": "/payload/temporal_conditions/0", "occurrence_index": 0,
            "instruction_id": "notice-1", "predicate_id": "p1",
            "effective_at": threshold, "effective_boundary": "inclusive",
        }]
        value["preservation_keys"] = [["L", "r1", "at"]]
        result = validate(value, case_value, case_bytes)
        self.assertTrue(result.valid, result.errors)
        boolean_index = deepcopy(value)
        boolean_index["temporal_rules"][0]["occurrence_index"] = False
        result = validate(boolean_index, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("invalid_occurrence_index", result.errors)
        value["temporal_rules"][0]["effective_boundary"] = "exclusive"
        result = validate(value, case_value, case_bytes)
        self.assertFalse(result.valid)
        self.assertIn("temporal_threshold_mismatch", result.errors)


if __name__ == "__main__":
    unittest.main()
