import unittest
from copy import deepcopy
from acac.temporal import reconcile, applies
from tests.test_case_validation import case


class TemporalTests(unittest.TestCase):
    def test_rule_reconciles_structured_condition(self):
        value = case(); locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False}); value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-01-01T00:00:00Z"
        condition = {"condition_id": "tc", "instruction_id": "original", "predicate_id": "p", "governing_event": locator, "effective_at": "2026-01-01T00:00:00Z", "effective_boundary": "inclusive"}
        value["payload"]["temporal_conditions"] = [condition]
        sidecar = {"spec_version": "acac-auth-1.1", "governing_event": locator, "predicate_definitions": [{"predicate_id": "p", "expression": {"record_ids": ["r1"]}}], "temporal_rules": [{"rule_id": "r", "source_condition_id": "tc", "source_location": "/payload/temporal_conditions/0", "occurrence_index": 0, "instruction_id": "original", "predicate_id": "p", "effective_at": condition["effective_at"], "effective_boundary": "inclusive"}], "temporal_reconciliation": {"status": "succeeded", "review_submission_hash": "sha256:" + "0" * 64, "checked_at": "2026-01-02T00:00:00Z"}}
        reconcile(value, sidecar)
        wrong_source_identity = deepcopy(sidecar)
        wrong_source_identity["temporal_rules"][0]["source_condition_id"] = "not-tc"
        with self.assertRaisesRegex(ValueError, "temporal_source_condition_id_mismatch"):
            reconcile(value, wrong_source_identity)
        extra = deepcopy(sidecar)
        extra["temporal_rules"].append({**extra["temporal_rules"][0], "rule_id": "extra", "source_condition_id": "extra-condition", "source_location": "/payload/temporal_conditions/1"})
        with self.assertRaisesRegex(ValueError, "temporal_rule_count_mismatch"):
            reconcile(value, extra)
        for member, wrong in (("effective_at", "2026-01-02T00:00:00Z"), ("effective_boundary", "exclusive"), ("instruction_id", "notice-1")):
            mismatch = deepcopy(sidecar)
            mismatch["temporal_rules"][0][member] = wrong
            with self.subTest(member=member), self.assertRaisesRegex(ValueError, "temporal_rule_source_mismatch"):
                reconcile(value, mismatch)
        wrong_instruction = deepcopy(sidecar)
        wrong_instruction["temporal_rules"][0]["instruction_id"] = "unknown"
        with self.assertRaisesRegex(ValueError, "unknown_temporal_instruction_id"):
            reconcile(value, wrong_instruction)
        wrong_predicate = deepcopy(sidecar)
        wrong_predicate["predicate_definitions"].append({"predicate_id": "p2", "expression": {"record_ids": ["r1"]}})
        wrong_predicate["temporal_rules"][0]["predicate_id"] = "p2"
        with self.assertRaisesRegex(ValueError, "temporal_rule_source_mismatch"):
            reconcile(value, wrong_predicate)
        failed_gate = deepcopy(sidecar)
        failed_gate["temporal_reconciliation"]["status"] = "failed"
        with self.assertRaisesRegex(ValueError, "temporal_reconciliation_required"):
            reconcile(value, failed_gate)

    def test_multiple_original_conditions_reconcile_one_to_one(self):
        value = case()
        locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-01-01T00:00:00Z"
        conditions = [
            {"condition_id": "tc-original-1", "instruction_id": "original", "predicate_id": "p1", "governing_event": locator, "effective_at": "2026-01-01T00:00:00Z", "effective_boundary": "inclusive"},
            {"condition_id": "tc-original-2", "instruction_id": "original", "predicate_id": "p2", "governing_event": locator, "effective_at": "2026-01-02T00:00:00Z", "effective_boundary": "exclusive"},
        ]
        value["payload"]["temporal_conditions"] = deepcopy(conditions)
        rules = [
            {"rule_id": "rule-original-1", "source_condition_id": "tc-original-1", "source_location": "/payload/temporal_conditions/0", "occurrence_index": 0, "instruction_id": "original", "predicate_id": "p1", "effective_at": conditions[0]["effective_at"], "effective_boundary": "inclusive"},
            {"rule_id": "rule-original-2", "source_condition_id": "tc-original-2", "source_location": "/payload/temporal_conditions/1", "occurrence_index": 0, "instruction_id": "original", "predicate_id": "p2", "effective_at": conditions[1]["effective_at"], "effective_boundary": "exclusive"},
        ]
        sidecar = {"spec_version": "acac-auth-1.1", "governing_event": locator,
                   "predicate_definitions": [{"predicate_id": "p1", "expression": {"record_ids": ["r1"]}}, {"predicate_id": "p2", "expression": {"record_ids": ["r1"]}}],
                   "temporal_rules": rules,
                   "temporal_reconciliation": {"status": "succeeded", "review_submission_hash": "sha256:" + "0" * 64, "checked_at": "2026-01-03T00:00:00Z"}}
        reconcile(value, sidecar)

        mismatched = deepcopy(sidecar)
        mismatched["temporal_rules"][1]["source_condition_id"] = "missing-condition"
        with self.assertRaisesRegex(ValueError, "temporal_source_condition_id_mismatch"):
            reconcile(value, mismatched)

    def test_rule_mismatch_rejected(self):
        with self.assertRaises(ValueError): reconcile({"payload": {"temporal_conditions": [{}]}}, {"temporal_rules": []})

    def test_effective_time_comparators_preserve_exact_ordering(self):
        threshold = "2026-01-01T00:00:00.500Z"
        before = "2026-01-01T00:00:00.499Z"
        after = "2026-01-01T00:00:00.501Z"
        equivalent_offset = "2026-01-01T01:00:00.500+01:00"

        # inclusive means event >= threshold; exclusive means event > threshold.
        self.assertFalse(applies(before, threshold, "inclusive"))
        self.assertTrue(applies(threshold, threshold, "inclusive"))
        self.assertFalse(applies(threshold, threshold, "exclusive"))
        self.assertTrue(applies(after, threshold, "exclusive"))
        self.assertFalse(applies(equivalent_offset, threshold, "exclusive"))

        # Arbitrarily long fractions must remain distinct beyond Decimal's
        # default precision, including when only the final digit differs.
        early_fraction = "0" * 120 + "1"
        late_fraction = "0" * 120 + "2"
        early = f"2026-01-01T00:00:00.{early_fraction}Z"
        late = f"2026-01-01T00:00:00.{late_fraction}Z"
        self.assertTrue(applies(late, early, "exclusive"))
        self.assertFalse(applies(early, late, "inclusive"))

        # Ordering remains exact when the comparison crosses a second boundary.
        just_before_second = "2026-01-01T00:00:00." + ("9" * 140) + "Z"
        next_second = "2026-01-01T00:00:01.000Z"
        self.assertTrue(applies(next_second, just_before_second, "exclusive"))
        self.assertFalse(applies(just_before_second, next_second, "inclusive"))

    def test_duplicate_rule_ids_and_invalid_occurrence_are_rejected(self):
        value = case(); locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-01-01T00:00:00Z"
        condition = {"condition_id": "tc", "instruction_id": "original", "predicate_id": "p", "governing_event": locator, "effective_at": "2026-01-01T00:00:00Z", "effective_boundary": "inclusive"}
        value["payload"]["temporal_conditions"] = [condition]
        sidecar = {"spec_version": "acac-auth-1.1", "governing_event": locator, "temporal_rules": [{"rule_id": "r", "source_condition_id": "tc", "source_location": "/payload/temporal_conditions/0", "occurrence_index": 1, "instruction_id": "original", "predicate_id": "p", "effective_at": condition["effective_at"], "effective_boundary": "inclusive"}], "temporal_reconciliation": {"status": "succeeded", "review_submission_hash": "sha256:" + "0" * 64, "checked_at": "2026-01-02T00:00:00Z"}}
        with self.assertRaisesRegex(ValueError, "source_location"):
            reconcile(value, sidecar)

    def test_duplicate_source_condition_and_pointer_identities_are_rejected(self):
        value = case(); locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-01-01T00:00:00Z"
        value["payload"]["updates"] = [{"update_id": "u1", "sequence": 1, "kind": "amendment", "text": "update"}]
        first = {"condition_id": "tc1", "instruction_id": "original", "predicate_id": "p", "governing_event": locator, "effective_at": "2026-01-01T00:00:00Z", "effective_boundary": "inclusive"}
        second = {**first, "condition_id": "tc2", "instruction_id": "u1"}
        value["payload"]["temporal_conditions"] = [first, second]
        base = {"spec_version": "acac-auth-1.1", "governing_event": locator,
                "predicate_definitions": [{"predicate_id": "p", "expression": {"record_ids": ["r1"]}}],
                "temporal_rules": [
                    {"rule_id": "r1", "source_condition_id": "tc1", "source_location": "/payload/temporal_conditions/0", "occurrence_index": 0, "instruction_id": "original", "predicate_id": "p", "effective_at": first["effective_at"], "effective_boundary": "inclusive"},
                    {"rule_id": "r2", "source_condition_id": "tc2", "source_location": "/payload/temporal_conditions/1", "occurrence_index": 0, "instruction_id": "u1", "predicate_id": "p", "effective_at": second["effective_at"], "effective_boundary": "inclusive"},
                ],
                "temporal_reconciliation": {"status": "succeeded", "review_submission_hash": "sha256:" + "0" * 64, "checked_at": "2026-01-02T00:00:00Z"}}
        reconcile(value, base)
        duplicate_id = deepcopy(base)
        duplicate_id["temporal_rules"][1]["source_condition_id"] = "tc1"
        with self.assertRaisesRegex(ValueError, "duplicate_temporal_rule_identity"):
            reconcile(value, duplicate_id)
        duplicate_pointer = deepcopy(base)
        duplicate_pointer["temporal_rules"][1]["source_location"] = "/payload/temporal_conditions/0"
        with self.assertRaisesRegex(ValueError, "duplicate_temporal_rule_identity"):
            reconcile(value, duplicate_pointer)


if __name__ == "__main__": unittest.main()
