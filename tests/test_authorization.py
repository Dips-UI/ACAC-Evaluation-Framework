import unittest
import hashlib

from acac.authorization import AuthorizationError, validate_resolved_coverage, validate_sidecar
from tests.test_case_validation import case as valid_case


ARTIFACT = b"synthetic retained artifact"
HASH = "sha256:" + hashlib.sha256(ARTIFACT).hexdigest()


def validate(value, **kwargs):
    kwargs.setdefault("retained_artifacts", {HASH: ARTIFACT})
    if value.get("resolution_status") == "resolved":
        case_value = valid_case()
        case_value["case_id"] = value.get("case_id", "case-1")
        kwargs.setdefault("case", case_value)
    return validate_sidecar(value, **kwargs)


def sidecar():
    return {
        "spec_version": "acac-auth-1.0",
        "case_id": "case-1",
        "source_case_hash": HASH,
        "resolution_status": "resolved",
        "profile": "single-ledger-1.0",
        "resolution_issues": [],
        "resolved_by": [{"reviewer_id": "human-1", "role": "human_reviewer", "reviewed_at": "2026-01-01T00:00:00Z", "independence_declaration": True, "review_submission_hash": HASH}],
        "resolution_note": "resolved",
        "governing_instruction_ids": ["notice-1"],
        "predicate_definitions": [{"predicate_id": "p1", "expression": {"record_ids": ["r1"]}}],
        "evidence_registry": [],
        "eligible_keys": [],
        "eligibility_rationale": [],
        "exclusions": [],
        "exceptions_applied": [],
        "required_final_values": [],
        "preservation_keys": [["L", "r1", "label"]],
        "rationale_by_key": [],
    }


class AuthorizationTests(unittest.TestCase):
    def test_resolved_non_temporal_empty_scope_is_valid(self):
        self.assertTrue(validate(sidecar(), case_id="case-1", profile="single-ledger-1.0").valid)
        missing_bytes = validate_sidecar(sidecar(), case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(missing_bytes.valid)
        self.assertIn("retained_source_case_hash_required", missing_bytes.errors)

    def test_no_op_sidecar_handoff_requires_empty_eligibility_and_exact_preservation(self):
        value = sidecar()
        case_value = valid_case()
        case_value["case_id"] = "case-1"
        case_value["payload"]["notice"] = {"notice_id": "notice-1", "operation": "no_op", "authority_text": "No change", "scope": {"fields": []}}
        self.assertTrue(validate(value, case_id="case-1", profile="single-ledger-1.0", case=case_value).valid)
        value["eligible_keys"] = [["L", "r1", "label"]]
        value["required_final_values"] = [{"key": ["L", "r1", "label"], "value": "OLD"}]
        value["eligibility_rationale"] = [{"key": ["L", "r1", "label"], "included_by": ["p1"], "excluded_by": [], "instruction_ids": ["notice-1"]}]
        value["rationale_by_key"] = [{"key": ["L", "r1", "label"], "instruction_ids": ["notice-1"], "reason": "No-op must not authorize changes"}]
        result = validate(value, case_id="case-1", profile="single-ledger-1.0", case=case_value)
        self.assertFalse(result.valid)
        self.assertIn("no_op_authorization_must_be_empty", result.errors)

    def test_duplicate_predicate_definitions_are_rejected(self):
        value = sidecar()
        value["predicate_definitions"].append(dict(value["predicate_definitions"][0]))
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("duplicate_predicate_definition", result.errors)

    def test_non_temporal_sidecar_rejects_temporal_members(self):
        value = sidecar(); value["temporal_rules"] = []
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("temporal_members_forbidden", result.errors)

    def test_temporal_sidecar_requires_exact_rule_and_reconciliation(self):
        value = sidecar()
        value["spec_version"] = "acac-auth-1.1"
        value["predicate_definitions"] = [{"predicate_id": "p1", "expression": {"record_ids": ["r1"]}}]
        value["temporal_rules"] = [{
            "rule_id": "r1", "source_condition_id": "tc1", "source_location": "/payload/temporal_conditions/0",
            "occurrence_index": 0, "instruction_id": "notice-1", "predicate_id": "p1",
            "effective_at": "2026-01-01T00:00:00Z", "effective_boundary": "inclusive",
        }]
        value["temporal_reconciliation"] = {"status": "succeeded", "review_submission_hash": HASH, "checked_at": "2026-01-02T00:00:00Z"}
        case_value = valid_case()
        case_value["case_id"] = "case-1"
        case_value["payload"]["field_declarations"].append({"table": "L", "field": "at", "type": "string", "format": "rfc3339-timestamp", "mutable": False})
        case_value["payload"]["ledger"]["L"][0]["values"]["at"] = "2026-01-01T00:00:00Z"
        value["preservation_keys"].append(["L", "r1", "at"])
        locator = {"source": "table_field", "table": "L", "field": "at"}
        threshold = "2026-01-01T00:00:00Z"
        case_value["payload"]["notice"].update({"governing_event": locator, "effective_at": threshold, "effective_boundary": "inclusive"})
        case_value["payload"]["temporal_conditions"] = [{"condition_id": "tc1", "instruction_id": "notice-1", "predicate_id": "p1", "governing_event": locator, "effective_at": threshold, "effective_boundary": "inclusive"}]
        value["governing_event"] = locator
        # The validated case, not a caller-controlled flag, requires this gate.
        self.assertTrue(validate(value, case_id="case-1", profile="single-ledger-1.0", case=case_value).valid)
        missing_reconciliation = dict(value)
        missing_reconciliation.pop("temporal_reconciliation")
        result = validate(missing_reconciliation, case_id="case-1", profile="single-ledger-1.0", case=case_value)
        self.assertFalse(result.valid)
        self.assertIn("temporal_members_required", result.errors)
        value["temporal_rules"][0]["occurrence_index"] = 1
        self.assertFalse(validate(value, case_id="case-1", profile="single-ledger-1.0", temporal=True, case=case_value).valid)

    def test_resolved_coverage_requires_mutable_cells_and_exact_preservation(self):
        value = sidecar()
        value["eligible_keys"] = [["L", "r1", "label"]]
        value["required_final_values"] = [{"key": ["L", "r1", "label"], "value": "NEW"}]
        value["eligibility_rationale"] = [{"key": ["L", "r1", "label"], "included_by": ["notice-1"], "excluded_by": [], "instruction_ids": ["notice-1"]}]
        value["preservation_keys"] = []
        ledger = {"L": [{"record_id": "r1", "values": {"label": "OLD", "other": "x"}}]}
        declarations = {("L", "label"): {"type": "string", "mutable": True}, ("L", "other"): {"type": "string", "mutable": False}}
        with self.assertRaisesRegex(AuthorizationError, "preservation_keys_mismatch"):
            validate_resolved_coverage(value, ledger, declarations, "single-ledger-1.0")
        value["preservation_keys"] = [["L", "r1", "other"]]
        validate_resolved_coverage(value, ledger, declarations, "single-ledger-1.0")

    def test_resolved_sidecar_requires_per_key_rationale_and_declared_final_type(self):
        value = sidecar()
        value["eligible_keys"] = [["L", "r1", "label"]]
        value["required_final_values"] = [{"key": ["L", "r1", "label"], "value": "OLD"}]
        value["eligibility_rationale"] = [{"key": ["L", "r1", "label"], "included_by": ["p1"], "excluded_by": [], "instruction_ids": ["notice-1"]}]
        value["rationale_by_key"] = [{"key": ["L", "r1", "label"], "instruction_ids": ["notice-1"], "reason": "Required unchanged value"}]
        self.assertTrue(validate(value, case_id="case-1", profile="single-ledger-1.0").valid)
        value["rationale_by_key"] = []
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("rationale_by_key_coverage", result.errors)
        value["rationale_by_key"] = [{"key": ["L", "r1", "label"], "instruction_ids": ["notice-1"], "reason": "Required unchanged value"}]
        value["required_final_values"][0]["value"] = 1
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("required_final_value_type_mismatch", result.errors)

    def test_exclusion_and_exception_shapes_are_structural(self):
        value = sidecar()
        value["exclusions"] = [{"exclusion_id": "x1", "predicate_id": "p1", "instruction_ids": ["notice-1"], "reason": "frozen"}]
        value["exceptions_applied"] = [{"exception_id": "e1", "record_ids": ["r1"], "instruction_ids": ["notice-1"], "reason": "approved"}]
        self.assertTrue(validate(value, case_id="case-1", profile="single-ledger-1.0").valid)
        value["exceptions_applied"][0]["predicate_id"] = "p1"
        self.assertFalse(validate(value, case_id="case-1", profile="single-ledger-1.0").valid)

    def test_exception_record_ids_must_be_valid_identifiers(self):
        value = sidecar()
        value["exceptions_applied"] = [{"exception_id": "e1", "record_ids": [None], "instruction_ids": ["notice-1"], "reason": "approved"}]
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("record_ids_null_forbidden", result.errors)

    def test_unresolved_evidence_descriptions_must_be_strings(self):
        value = sidecar()
        value["resolution_status"] = "quarantined"
        for member in ("governing_instruction_ids", "predicate_definitions", "eligible_keys", "eligibility_rationale", "exclusions", "exceptions_applied", "required_final_values", "preservation_keys", "rationale_by_key"):
            value.pop(member)
        value["resolution_issues"] = [{"issue_id": "i1", "category": "ambiguous", "source_location": "/payload", "description": "unclear", "evidence_ids": ["ev1"]}]
        value["evidence_registry"] = [{"evidence_id": "ev1", "content_hash": HASH, "description": None}]
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("invalid_evidence_description", result.errors)

    def test_unresolved_sidecar_requires_minimal_issue_evidence_registry(self):
        value = sidecar()
        value["resolution_status"] = "quarantined"
        for member in ("governing_instruction_ids", "predicate_definitions", "eligible_keys", "eligibility_rationale", "exclusions", "exceptions_applied", "required_final_values", "preservation_keys", "rationale_by_key"):
            value.pop(member)
        value["resolution_issues"] = [{"issue_id": "i1", "category": "ambiguous", "source_location": "/payload", "description": "unclear", "evidence_ids": ["ev1"]}]
        value["evidence_registry"] = [{"evidence_id": "ev1", "content_hash": HASH, "description": "retained"}]
        self.assertTrue(validate(value, case_id="case-1", profile="single-ledger-1.0").valid)
        value["evidence_registry"] = []
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("issue_evidence_registry_mismatch", result.errors)

    def test_unresolved_empty_evidence_registry_omitted_or_empty(self):
        resolved_only = (
            "governing_instruction_ids", "predicate_definitions", "eligible_keys", "eligibility_rationale",
            "exclusions", "exceptions_applied", "required_final_values", "preservation_keys", "rationale_by_key",
        )
        for status in ("ambiguous", "quarantined"):
            for include_registry in (False, True):
                with self.subTest(status=status, include_registry=include_registry):
                    value = sidecar(); value["resolution_status"] = status
                    for member in (*resolved_only, "evidence_registry"):
                        value.pop(member)
                    if include_registry:
                        value["evidence_registry"] = []
                    value["resolution_issues"] = [{
                        "issue_id": "i1", "category": "unclear", "source_location": "/payload",
                        "description": "synthetic unresolved issue", "evidence_ids": [],
                    }]
                    self.assertTrue(validate(value, case_id="case-1", profile="single-ledger-1.0").valid)

    def test_resolved_sidecar_rejects_missing_or_extra_final_coverage(self):
        value = sidecar()
        value["eligible_keys"] = [["L", "r1", "label"]]
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertTrue(any("required_final_values_coverage" in error for error in result.errors))
        value = sidecar()
        value["required_final_values"] = [{"key": ["L", "r1", "label"], "value": "OLD"}]
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertTrue(any("required_final_values_coverage" in error for error in result.errors))
        value = sidecar()
        value["eligible_keys"] = [["L", "r1", "label"]]
        duplicate = {"key": ["L", "r1", "label"], "value": "OLD"}
        value["required_final_values"] = [duplicate, dict(duplicate)]
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertTrue(any("required_final_values_coverage" in error for error in result.errors))

    def test_unresolved_sidecar_rejects_resolved_only_leakage(self):
        value = sidecar(); value["resolution_status"] = "ambiguous"
        value["resolution_issues"] = [{"issue_id": "i1", "category": "unclear", "source_location": "/payload", "description": "unclear", "evidence_ids": []}]
        result = validate(value, case_id="case-1", profile="single-ledger-1.0")
        self.assertFalse(result.valid)
        self.assertIn("resolved_members_forbidden", result.errors)


if __name__ == "__main__":
    unittest.main()
