import unittest
from copy import deepcopy
from decimal import Decimal

from acac.canonical import exact_hash, semantic_bytes, semantic_hash


class CanonicalTests(unittest.TestCase):
    def test_object_key_order_is_semantic_invariant(self):
        self.assertEqual(semantic_hash({"b": 2, "a": 1}), semantic_hash({"a": 1, "b": 2}))
        first = {"outer": {"z": {"beta": 2, "alpha": 1}, "a": [{"y": 2, "x": 1}]}}
        reordered = {"outer": {"a": [{"x": 1, "y": 2}], "z": {"alpha": 1, "beta": 2}}}
        self.assertEqual(semantic_hash(first), semantic_hash(reordered))

    def test_canonical_boolean_and_integer_tokens_remain_distinct(self):
        value = {"truth": True, "count": 1, "disabled": False, "zero": 0}
        self.assertEqual(
            semantic_bytes(value),
            b'{"count":1,"disabled":false,"truth":true,"zero":0}',
        )
        self.assertNotEqual(semantic_hash(True), semantic_hash(1))

    def test_exact_hash_is_byte_sensitive(self):
        self.assertNotEqual(exact_hash(b"{}"), exact_hash(b"{}\n"))

    def test_exact_hash_tracks_whitespace_line_endings_key_order_and_token_spelling(self):
        raw_variants = (
            b'{"a":1,"b":2}',
            b'{ "a":1,"b":2}',
            b'{"a":1,"b":2}\r\n',
            b'{"b":2,"a":1}',
            b'{"a":1.0,"b":2}',
        )
        hashes = [exact_hash(raw) for raw in raw_variants]
        self.assertEqual(len(hashes), len(set(hashes)))

    def test_semantic_hash_sorts_declared_set_arrays(self):
        self.assertEqual(semantic_hash({"scheduled_case_ids": ["b", "a"]}), semantic_hash({"scheduled_case_ids": ["a", "b"]}))

    def test_all_section_7_set_arrays_are_order_invariant(self):
        first = {
            "evidence_registry": [{"evidence_id": "e2"}, {"evidence_id": "e1"}],
            "predicate_definitions": [{"predicate_id": "p2"}, {"predicate_id": "p1"}],
            "exclusions": [{"exclusion_id": "x2"}, {"exclusion_id": "x1"}],
            "exceptions_applied": [{"exception_id": "a2"}, {"exception_id": "a1"}],
            "temporal_rules": [
                {"source_location": "/z", "occurrence_index": 0, "rule_id": "r2"},
                {"source_location": "/a", "occurrence_index": 0, "rule_id": "r1"},
            ],
            "resolution_issues": [{"issue_id": "i2"}, {"issue_id": "i1"}],
            "excluded_cases": [{"case_id": "c2"}, {"case_id": "c1"}],
            "review_submission_hashes": ["sha256:" + "b" * 64, "sha256:" + "a" * 64],
            "exception_decisions": [
                {"exception_id": "e2", "exclusion_id": "x1", "key": ["L", "r2", "label"]},
                {"exception_id": "e1", "exclusion_id": "x1", "key": ["L", "r1", "label"]},
            ],
            "scheduled_case_ids": ["c2", "c1"],
            "executed_case_ids": ["c2", "c1"],
        }
        second = {name: list(reversed(items)) for name, items in first.items()}
        self.assertEqual(semantic_hash(first), semantic_hash(second))

    def test_source_order_arrays_remain_order_sensitive(self):
        value = {
            "temporal_conditions": [
                {"condition_id": "tc1", "effective_at": "2026-01-01T00:00:00Z"},
                {"condition_id": "tc2", "effective_at": "2026-02-01T00:00:00Z"},
            ],
            "updates": [
                {"update_id": "u1", "sequence": 1},
                {"update_id": "u2", "sequence": 2},
            ],
        }
        reversed_conditions = {**value, "temporal_conditions": list(reversed(value["temporal_conditions"]))}
        reversed_updates = {**value, "updates": list(reversed(value["updates"]))}
        self.assertNotEqual(semantic_hash(value), semantic_hash(reversed_conditions))
        self.assertNotEqual(semantic_hash(value), semantic_hash(reversed_updates))

    def test_semantic_hash_is_sensitive_to_identity_values_and_timestamps(self):
        original = {"case_id": "case-1", "ledger": {"L": [{"record_id": "r1", "values": {"label": "OLD"}}]}, "created_at": "2026-01-01T00:00:00Z"}
        variants = (
            {**original, "case_id": "case-2"},
            {"case_id": original["case_id"], "ledger": {"L": [{"record_id": "r1", "values": {"label": "NEW"}}]}, "created_at": original["created_at"]},
            {**original, "created_at": "2026-01-01T00:00:00.0000001Z"},
        )
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertNotEqual(semantic_hash(original), semantic_hash(variant))

    def test_object_keys_sort_by_unicode_code_point(self):
        encoded = semantic_bytes({"\ue000": 1, "😀": 2, "a": 3})
        self.assertEqual(encoded, '{"a":3,"":1,"😀":2}'.encode("utf-8"))

    def test_semantic_strings_preserve_whitespace_and_unicode_normalization(self):
        plain = {"label": "caf\u00e9"}
        leading_space = {"label": " caf\u00e9"}
        trailing_space = {"label": "caf\u00e9 "}
        decomposed = {"label": "cafe\u0301"}
        self.assertNotEqual(semantic_hash(plain), semantic_hash(leading_space))
        self.assertNotEqual(semantic_hash(plain), semantic_hash(trailing_space))
        self.assertNotEqual(semantic_hash(plain), semantic_hash(decomposed))

    def test_v14_artifact_bindings_and_metric_values_are_hash_sensitive(self):
        h1 = "sha256:" + "1" * 64
        h2 = "sha256:" + "2" * 64
        base = {
            "authorization_input": {"case_id": "case-1", "source_case_hash": h1},
            "review": {
                "authorization_input_hash": h1, "reference_id": "ref-1",
                "reference_revision": 1, "reference_content_hash": h2,
            },
            "sidecar": {
                "resolution_status": "resolved", "review_submission_hashes": [h1],
            },
            "reference": {"authorization_input_hash": h1, "revision": 1},
            "approval": {
                "authorization_input_hash": h1,
                "final_authorization_sidecar_hash": h2,
                "review_submission_hashes": [h1],
                "adjudication_hash": h2,
                "approved_reference_hash": h1,
            },
            "manifest": {
                "authorization_input_hashes": {"case-1": h1},
                "review_submission_hashes": {"case-1": [h1]},
                "final_authorization_sidecar_hashes": {"case-1": h2},
                "reference_hashes": {"case-1": h2},
                "adjudication_hashes": {"case-1": h2},
                "approval_event_hashes": {"case-1": h1},
            },
            "result": {
                "metric": {"numerator": "1", "denominator": "2"},
                "not_applicable": {"status": "not_applicable", "reason": "empty_denominator"},
            },
        }
        mutations = (
            (("authorization_input", "case_id"), "case-2"),
            (("authorization_input", "source_case_hash"), h2),
            (("review", "authorization_input_hash"), h2),
            (("review", "reference_revision"), 2),
            (("review", "reference_content_hash"), h1),
            (("sidecar", "resolution_status"), "quarantined"),
            (("sidecar", "review_submission_hashes"), [h2]),
            (("reference", "authorization_input_hash"), h2),
            (("reference", "revision"), 2),
            (("approval", "authorization_input_hash"), h2),
            (("approval", "final_authorization_sidecar_hash"), h1),
            (("approval", "review_submission_hashes"), [h2]),
            (("approval", "adjudication_hash"), h1),
            (("approval", "approved_reference_hash"), h2),
            (("manifest", "authorization_input_hashes"), {"case-1": h2}),
            (("manifest", "review_submission_hashes"), {"case-1": [h2]}),
            (("manifest", "final_authorization_sidecar_hashes"), {"case-1": h1}),
            (("manifest", "reference_hashes"), {"case-1": h1}),
            (("manifest", "adjudication_hashes"), {"case-1": h1}),
            (("manifest", "approval_event_hashes"), {"case-1": h2}),
            (("result", "metric"), {"numerator": "2", "denominator": "3"}),
            (("result", "not_applicable"), {"status": "not_applicable", "reason": "structural_invalidity"}),
        )
        original_hash = semantic_hash(base)
        superseding_review = deepcopy(base)
        superseding_review["review"]["supersedes_review_id"] = "review-previous"
        self.assertNotEqual(original_hash, semantic_hash(superseding_review))

        for path, replacement in mutations:
            with self.subTest(path=path):
                variant = deepcopy(base)
                variant[path[0]][path[1]] = replacement
                self.assertNotEqual(original_hash, semantic_hash(variant))

        for field, replacement in (("numerator", "2"), ("denominator", "3")):
            with self.subTest(metric_field=field):
                variant = deepcopy(base)
                variant["result"]["metric"][field] = replacement
                self.assertNotEqual(original_hash, semantic_hash(variant))

        with self.subTest(metric_field="not_applicable.reason"):
            variant = deepcopy(base)
            variant["result"]["not_applicable"]["reason"] = "structural_invalidity"
            self.assertNotEqual(original_hash, semantic_hash(variant))

    def test_semantic_hash_is_sensitive_to_temporal_and_adjudication_bindings(self):
        h1 = "sha256:" + "1" * 64
        h2 = "sha256:" + "2" * 64
        base = {
            "case": {
                "temporal_conditions": [{
                    "condition_id": "tc-1", "instruction_id": "original",
                    "predicate_id": "p-1", "effective_at": "2026-01-01T00:00:00Z",
                    "effective_boundary": "inclusive",
                }],
            },
            "authorization_input": {
                "temporal_rules": [{
                    "rule_id": "rule-1", "source_condition_id": "tc-1",
                    "source_location": "/payload/temporal_conditions/0",
                    "occurrence_index": 0, "instruction_id": "original",
                    "predicate_id": "p-1", "effective_at": "2026-01-01T00:00:00Z",
                    "effective_boundary": "inclusive",
                }],
            },
            "sidecar": {"temporal_reconciliation": {
                "status": "succeeded", "review_submission_hashes": [h1],
            }},
            "adjudication": {
                "reference_content_hash": h1, "considered_review_hashes": [h1],
                "disagreement_disposition": ["accepted"],
            },
            "lifecycle": {"approval": {
                "authorization_input_hash": h1, "adjudication_hash": h1,
                "approved_reference_hash": h1,
            }},
            "manifest": {"approval_event_hashes": {"case-1": h1}},
        }
        mutations = (
            (("case", "temporal_conditions"), [{
                "condition_id": "tc-2", "instruction_id": "original",
                "predicate_id": "p-1", "effective_at": "2026-01-01T00:00:00Z",
                "effective_boundary": "inclusive",
            }]),
            (("authorization_input", "temporal_rules"), [{
                "rule_id": "rule-2", "source_condition_id": "tc-1",
                "source_location": "/payload/temporal_conditions/0",
                "occurrence_index": 0, "instruction_id": "original",
                "predicate_id": "p-1", "effective_at": "2026-01-01T00:00:00Z",
                "effective_boundary": "inclusive",
            }]),
            (("sidecar", "temporal_reconciliation"), {
                "status": "succeeded", "review_submission_hashes": [h2],
            }),
            (("adjudication", "reference_content_hash"), h2),
            (("adjudication", "considered_review_hashes"), [h2]),
            (("adjudication", "disagreement_disposition"), ["rejected"]),
            (("lifecycle", "approval"), {
                "authorization_input_hash": h2, "adjudication_hash": h1,
                "approved_reference_hash": h1,
            }),
            (("manifest", "approval_event_hashes"), {"case-1": h2}),
        )
        original_hash = semantic_hash(base)
        for path, replacement in mutations:
            with self.subTest(path=path):
                variant = deepcopy(base)
                variant[path[0]][path[1]] = replacement
                self.assertNotEqual(original_hash, semantic_hash(variant))

    def test_exception_decisions_are_set_semantic_and_value_sensitive(self):
        first = {
            "exception_id": "e1", "exclusion_id": "x1", "key": ["L", "r1", "label"],
            "decision": "authorized",
        }
        second = {
            "exception_id": "e2", "exclusion_id": "x1", "key": ["L", "r2", "label"],
            "decision": "unresolved",
        }
        base = {"adjudication": {"exception_decisions": [first, second]}}
        reordered = {"adjudication": {"exception_decisions": [second, first]}}
        self.assertEqual(semantic_hash(base), semantic_hash(reordered))
        changed = deepcopy(base)
        changed["adjudication"]["exception_decisions"][0]["decision"] = "not_authorized"
        self.assertNotEqual(semantic_hash(base), semantic_hash(changed))

    def test_semantic_hash_is_sensitive_to_artifact_versions(self):
        base = {
            "case": {"schema_version": "acac-1.3"},
            "authorization_input": {"schema_version": "acac-auth-input-1.0"},
            "review": {"schema_version": "acac-review-1.1"},
            "sidecar": {"spec_version": "acac-auth-1.2"},
            "reference": {"schema_version": "acac-1.4"},
            "lifecycle": {"schema_version": "acac-lifecycle-1.1"},
            "manifest": {"manifest_version": "1.4"},
            "result": {"schema_version": "acac-1.4", "grader_version": "acac-grader-1.4"},
        }
        versions = (
            ("case", "schema_version", "acac-1.2"),
            ("authorization_input", "schema_version", "acac-auth-input-0.9"),
            ("review", "schema_version", "acac-review-1.0"),
            ("sidecar", "spec_version", "acac-auth-1.1"),
            ("reference", "schema_version", "acac-1.3"),
            ("lifecycle", "schema_version", "acac-lifecycle-1.0"),
            ("manifest", "manifest_version", "1.3"),
            ("result", "schema_version", "acac-1.3"),
            ("result", "grader_version", "acac-grader-1.3"),
        )
        original_hash = semantic_hash(base)
        for artifact, field, replacement in versions:
            with self.subTest(artifact=artifact, field=field):
                variant = deepcopy(base)
                variant[artifact][field] = replacement
                self.assertNotEqual(original_hash, semantic_hash(variant))

    def test_semantic_hash_sorts_schema_defined_addresses_rows_and_edits(self):
        first = {
            "field_declarations": [{"table": "L", "field": "z"}, {"table": "L", "field": "a"}],
            "ledger": {"L": [{"record_id": "r2"}, {"record_id": "r1"}]},
            "eligible_keys": [["L", "r2", "z"], ["L", "r1", "a"]],
            "preservation_keys": [["L", "r2", "z"], ["L", "r1", "a"]],
            "edits": [{"table": "L", "record_id": "r2", "field": "z"}, {"table": "L", "record_id": "r1", "field": "a"}],
            "temporal_conditions": ["source-2", "source-1"],
        }
        second = {
            "field_declarations": list(reversed(first["field_declarations"])),
            "ledger": {"L": list(reversed(first["ledger"]["L"]))},
            "eligible_keys": list(reversed(first["eligible_keys"])),
            "preservation_keys": list(reversed(first["preservation_keys"])),
            "edits": list(reversed(first["edits"])),
            "temporal_conditions": ["source-2", "source-1"],
        }
        self.assertEqual(semantic_hash(first), semantic_hash(second))
        self.assertIn(b'["source-2","source-1"]', semantic_bytes(first))

    def test_exhaustive_v14_field_level_hash_sensitivity(self):
        h1 = "sha256:" + "1" * 64
        h2 = "sha256:" + "2" * 64
        base = {
            "case": {
                "profile": "single-ledger-1.0",
                "task": "correct_ledger",
                "payload": {
                    "field_declarations": [{"table": "L", "field": "f1", "type": "string"}],
                    "notice": {"notice_id": "n1", "operation": "update", "authority_text": "text1"},
                },
            },
            "authorization_input": {
                "profile": "single-ledger-1.0",
                "governing_instruction_ids": ["n1"],
                "predicate_definitions": [{"predicate_id": "p1", "expression": {"field": "f1", "eq": "v1"}}],
                "evidence_registry": [{"evidence_id": "ev1", "description": "desc1", "content_hash": h1}],
                "eligible_keys": [["L", "r1", "f1"]],
                "required_final_values": {"L:r1:f1": "val1"},
                "preservation_keys": [["L", "r1", "f2"]],
                "rationale_by_key": {"L:r1:f1": "rat1"},
                "exclusions": [{"exclusion_id": "x1", "predicate_id": "p1"}],
                "exceptions_applied": [{"exception_id": "e1", "instruction_ids": ["n1"]}],
            },
            "review": {
                "reviewer_role": "human_reviewer",
                "reviewer_id": "rev-1",
                "review_scope": [["L", "r1", "f1"]],
                "proposed_edits": [{"table": "L", "record_id": "r1", "field": "f1", "new_value": "val1"}],
                "ambiguity_notes": ["note1"],
                "decision_reason": "reason1",
                "completed_at": "2026-01-01T00:00:00Z",
                "independence_declaration": True,
                "independence_basis": "basis1",
            },
            "sidecar": {
                "resolution_issues": [{"issue_id": "iss1", "evidence_ids": ["ev1"]}],
                "resolved_by": [{"reviewer_id": "rev-1", "review_submission_hash": h1}],
                "resolution_note": "res_note",
            },
            "adjudication": {
                "adjudicator_id": "adj-1",
                "disagreement_disposition": ["disp1"],
                "decision_rationale": "adj_rationale",
                "independence_declaration": True,
                "independence_basis": "adj_basis",
                "completed_at": "2026-01-01T00:00:00Z",
            },
            "reference": {
                "author": {"author_id": "auth-1"},
                "expected_patch": [{"op": "replace", "table": "L", "record_id": "r1", "field": "f1", "old_value": "old", "new_value": "new"}],
                "final_ledger": {"L": [{"record_id": "r1", "values": {"f1": "new"}}]},
                "rationale": "ref_rationale",
            },
            "lifecycle": {
                "event_id": "evt-1",
                "sequence": 1,
                "timestamp": "2026-01-01T00:00:00Z",
                "actor": {"actor_id": "act-1", "actor_role": "author"},
            },
            "manifest": {
                "run_id": "run-1",
                "grader_version": "acac-grader-1.4",
                "created_at": "2026-01-01T00:00:00Z",
                "prompt_hashes": {"p1": h1},
                "configuration_hashes": {"c1": h1},
                "model": {"name": "model-1", "settings": {"temperature": Decimal("0.7")}},
            },
        }
        mutations = (
            (("case", "profile"), "historical-ledger-1.0"),
            (("case", "task"), "audit_ledger"),
            (("case", "payload", "notice", "authority_text"), "text2"),
            (("case", "payload", "notice", "operation"), "no_op"),
            (("case", "payload", "field_declarations"), [{"table": "L", "field": "f1", "type": "integer"}]),
            (("authorization_input", "profile"), "historical-ledger-1.0"),
            (("authorization_input", "governing_instruction_ids"), ["n2"]),
            (("authorization_input", "predicate_definitions"), [{"predicate_id": "p1", "expression": {"field": "f1", "eq": "v2"}}]),
            (("authorization_input", "evidence_registry"), [{"evidence_id": "ev1", "description": "desc2", "content_hash": h1}]),
            (("authorization_input", "eligible_keys"), [["L", "r2", "f1"]]),
            (("authorization_input", "required_final_values"), {"L:r1:f1": "val2"}),
            (("authorization_input", "preservation_keys"), [["L", "r2", "f2"]]),
            (("authorization_input", "rationale_by_key"), {"L:r1:f1": "rat2"}),
            (("authorization_input", "exclusions"), [{"exclusion_id": "x2", "predicate_id": "p1"}]),
            (("authorization_input", "exceptions_applied"), [{"exception_id": "e2", "instruction_ids": ["n1"]}]),
            (("review", "reviewer_role"), "ai_auditor"),
            (("review", "reviewer_id"), "rev-2"),
            (("review", "review_scope"), [["L", "r2", "f1"]]),
            (("review", "proposed_edits"), [{"table": "L", "record_id": "r1", "field": "f1", "new_value": "val2"}]),
            (("review", "ambiguity_notes"), ["note2"]),
            (("review", "decision_reason"), "reason2"),
            (("review", "completed_at"), "2026-02-01T00:00:00Z"),
            (("review", "independence_declaration"), False),
            (("review", "independence_basis"), "basis2"),
            (("sidecar", "resolution_issues"), [{"issue_id": "iss2", "evidence_ids": ["ev1"]}]),
            (("sidecar", "resolved_by"), [{"reviewer_id": "rev-2", "review_submission_hash": h1}]),
            (("sidecar", "resolution_note"), "different_note"),
            (("adjudication", "adjudicator_id"), "adj-2"),
            (("adjudication", "disagreement_disposition"), ["disp2"]),
            (("adjudication", "decision_rationale"), "different_rationale"),
            (("adjudication", "independence_declaration"), False),
            (("adjudication", "independence_basis"), "different_basis"),
            (("adjudication", "completed_at"), "2026-02-01T00:00:00Z"),
            (("reference", "author"), {"author_id": "auth-2"}),
            (("reference", "expected_patch"), [{"op": "replace", "table": "L", "record_id": "r1", "field": "f1", "old_value": "old", "new_value": "alt"}]),
            (("reference", "final_ledger"), {"L": [{"record_id": "r1", "values": {"f1": "alt"}}]}),
            (("reference", "rationale"), "alt_rationale"),
            (("lifecycle", "event_id"), "evt-2"),
            (("lifecycle", "sequence"), 2),
            (("lifecycle", "timestamp"), "2026-02-01T00:00:00Z"),
            (("lifecycle", "actor"), {"actor_id": "act-2", "actor_role": "author"}),
            (("manifest", "run_id"), "run-2"),
            (("manifest", "grader_version"), "acac-grader-1.5"),
            (("manifest", "created_at"), "2026-02-01T00:00:00Z"),
            (("manifest", "prompt_hashes"), {"p1": h2}),
            (("manifest", "configuration_hashes"), {"c1": h2}),
            (("manifest", "model"), {"name": "model-2", "settings": {"temperature": Decimal("0.7")}}),
            (("manifest", "model", "settings"), {"temperature": Decimal("0.8")}),
        )
        original_hash = semantic_hash(base)
        for path, replacement in mutations:
            with self.subTest(path=path):
                variant = deepcopy(base)
                target = variant
                for step in path[:-1]:
                    target = target[step]
                target[path[-1]] = replacement
                self.assertNotEqual(original_hash, semantic_hash(variant))

    def test_exact_decimal_normalization_without_float_conversion(self):
        a = {"model": {"settings": {"x": Decimal("1E+3"), "negative_zero": Decimal("-0.000")}}, "metrics": {"ratio": Decimal("1.2300E-2")}}
        b = {"model": {"settings": {"x": Decimal("1000.0"), "negative_zero": Decimal("0")}}, "metrics": {"ratio": Decimal("0.0123")}}
        self.assertEqual(semantic_bytes(a), b'{"metrics":{"ratio":0.0123},"model":{"settings":{"negative_zero":0,"x":1000}}}')
        self.assertEqual(semantic_hash(a), semantic_hash(b))

    def test_rejects_floats_null_and_decimals_outside_permitted_locations(self):
        for value in ({"x": 1.5}, {"model": {"settings": {"x": 1.5}}}, {"x": None}, {"x": Decimal("1.5")}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                semantic_bytes(value)
        with self.assertRaisesRegex(ValueError, "integer_out_of_range"):
            semantic_bytes({"x": 2**63})
        semantic_bytes({"min": -(2**63), "max": 2**63 - 1})


if __name__ == "__main__": unittest.main()
