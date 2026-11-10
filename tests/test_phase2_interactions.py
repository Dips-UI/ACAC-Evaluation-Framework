"""Cross-validator Phase 2 tests using synthetic case bundles only."""

import copy
import unittest

from acac.case_validation import validate_case
from acac.temporal import TemporalError, reconcile
from tests.test_case_validation import case


class Phase2InteractionTests(unittest.TestCase):
    def test_notice_scope_and_ledger_declarations_are_checked_together(self):
        value = case()
        value["payload"]["notice"]["scope"]["fields"] = ["missing"]
        result = validate_case(value)
        self.assertFalse(result.valid)
        self.assertIn("unknown_notice_field", result.errors)

    def test_historical_mutability_and_notice_target_boundary_interact(self):
        value = case("historical-ledger-1.0")
        value["payload"]["notice"]["scope"]["fields"] = ["text"]
        result = validate_case(value)
        self.assertFalse(result.valid)
        self.assertIn("unknown_notice_field", result.errors)

    def test_metadata_timestamp_locator_requires_metadata_and_record_values(self):
        value = case()
        value["payload"]["metadata_declarations"] = [{
            "field": "annotated_at",
            "type": "string",
            "format": "rfc3339-timestamp",
        }]
        value["payload"]["record_metadata"] = {"r1": {"annotated_at": "2026-02-03T00:00:00Z"}}
        locator = {"source": "record_metadata", "field": "annotated_at"}
        value["payload"]["notice"].update({
            "effective_at": "2026-02-03T00:00:00Z",
            "effective_boundary": "inclusive",
            "governing_event": locator,
        })
        value["payload"]["temporal_conditions"] = [{
            "condition_id": "tc",
            "instruction_id": "notice-1",
            "predicate_id": "p1",
            "governing_event": locator,
            "effective_at": "2026-02-03T00:00:00Z",
            "effective_boundary": "inclusive",
        }]
        self.assertTrue(validate_case(value).valid)
        del value["payload"]["record_metadata"]["r1"]
        self.assertFalse(validate_case(value).valid)

    def test_no_op_scope_remains_structural_and_cannot_gain_targets(self):
        value = case()
        value["payload"]["notice"] = {
            "notice_id": "n",
            "operation": "no_op",
            "authority_text": "No change.",
            "scope": {"fields": []},
        }
        self.assertTrue(validate_case(value).valid)
        value["payload"]["notice"]["scope"]["predicate_id"] = "p1"
        self.assertFalse(validate_case(value).valid)

    def test_temporal_notice_and_update_require_distinct_matching_conditions(self):
        value = case()
        value["payload"]["field_declarations"].append({
            "table": "L", "field": "at", "type": "string",
            "format": "rfc3339-timestamp", "mutable": False,
        })
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["notice"].update({
            "effective_at": "2026-02-03T00:00:00Z",
            "effective_boundary": "inclusive",
            "governing_event": locator,
        })
        value["payload"]["updates"] = [{
            "update_id": "u1", "sequence": 1, "kind": "amendment", "text": "x",
            "effective_at": "2026-02-04T00:00:00Z", "effective_boundary": "exclusive",
        }]
        value["payload"]["temporal_conditions"] = [{
            "condition_id": "notice-condition", "instruction_id": "notice-1",
            "predicate_id": "p1", "governing_event": locator,
            "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive",
        }, {
            "condition_id": "update-condition", "instruction_id": "u1",
            "predicate_id": "p1", "governing_event": locator,
            "effective_at": "2026-02-04T00:00:00Z", "effective_boundary": "exclusive",
        }]
        self.assertTrue(validate_case(value).valid)
        value["payload"]["temporal_conditions"][1]["effective_boundary"] = "inclusive"
        self.assertFalse(validate_case(value).valid)

    def test_case_and_sidecar_share_one_temporal_governing_event(self):
        value = case()
        value["payload"]["field_declarations"].append({
            "table": "L", "field": "at", "type": "string",
            "format": "rfc3339-timestamp", "mutable": False,
        })
        value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-02-03T00:00:00Z"
        locator = {"source": "table_field", "table": "L", "field": "at"}
        value["payload"]["notice"].update({
            "effective_at": "2026-02-03T00:00:00Z",
            "effective_boundary": "inclusive",
            "governing_event": locator,
        })
        value["payload"]["updates"] = [{
            "update_id": "u1", "sequence": 1, "kind": "amendment", "text": "Synthetic amendment",
            "effective_at": "2026-02-04T00:00:00Z", "effective_boundary": "exclusive",
            "applies_to": {"predicate_id": "p1"},
        }]
        value["payload"]["temporal_conditions"] = [
            {
                "condition_id": "tc-notice", "instruction_id": "notice-1", "predicate_id": "p1",
                "governing_event": locator, "effective_at": "2026-02-03T00:00:00Z",
                "effective_boundary": "inclusive",
            },
            {
                "condition_id": "tc-update", "instruction_id": "u1", "predicate_id": "p1",
                "governing_event": locator, "effective_at": "2026-02-04T00:00:00Z",
                "effective_boundary": "exclusive",
            },
        ]
        case_result = validate_case(value)
        self.assertTrue(case_result.valid, case_result.errors)

        sidecar = {
            "spec_version": "acac-auth-1.1",
            "governing_event": locator,
            "predicate_definitions": [{"predicate_id": "p1", "expression": {"record_ids": ["r1"]}}],
            "temporal_rules": [{
                "rule_id": "rule-notice", "source_condition_id": "tc-notice",
                "source_location": "/payload/temporal_conditions/0", "occurrence_index": 0,
                "instruction_id": "notice-1", "predicate_id": "p1",
                "effective_at": "2026-02-03T00:00:00Z", "effective_boundary": "inclusive",
            }, {
                "rule_id": "rule-update", "source_condition_id": "tc-update",
                "source_location": "/payload/temporal_conditions/1", "occurrence_index": 0,
                "instruction_id": "u1", "predicate_id": "p1",
                "effective_at": "2026-02-04T00:00:00Z", "effective_boundary": "exclusive",
            }],
            "temporal_reconciliation": {
                "status": "succeeded", "review_submission_hash": "sha256:" + "0" * 64,
                "checked_at": "2026-02-04T00:00:00Z",
            },
        }
        reconcile(value, sidecar)

        sidecar["governing_event"] = {"source": "table_field", "table": "L", "field": "other_at"}
        with self.assertRaisesRegex(TemporalError, "governing_event_mismatch"):
            reconcile(value, sidecar)


if __name__ == "__main__":
    unittest.main()
