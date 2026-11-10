import unittest

from acac.predicates import PredicateContext, PredicateError, evaluate, validate_definition


class PredicateTests(unittest.TestCase):
    def setUp(self):
        self.declarations = {("L", "status"): {"type": "string"}, ("L", "at"): {"type": "string", "format": "rfc3339-timestamp"}}
        self.metadata = {"batch": {"type": "string"}}
        self.context = PredicateContext({"L": [{"record_id": "r1", "values": {"status": "OPEN"}}, {"record_id": "r2", "values": {"status": "CLOSED"}}]}, {"r1": {"batch": "B1"}, "r2": {"batch": "B2"}})

    def test_supported_nodes_and_evaluation(self):
        validate_definition({"predicate_id": "p", "expression": {"field": {"field": {"source": "table_field", "table": "L", "name": "status"}, "op": "eq", "value": "OPEN"}}}, self.declarations, self.metadata)
        self.assertEqual(evaluate({"record_ids": ["r1"]}, self.context), {"r1"})
        self.assertEqual(evaluate({"field": {"field": {"source": "table_field", "table": "L", "name": "status"}, "op": "neq", "value": "OPEN"}}, self.context), {"r2"})

    def test_bounded_grammar_rejects_timestamp_and_invalid_nodes(self):
        with self.assertRaisesRegex(PredicateError, "timestamp"):
            validate_definition({"predicate_id": "p", "expression": {"field": {"field": {"source": "table_field", "table": "L", "name": "at"}, "op": "eq", "value": "x"}}}, self.declarations, self.metadata)
        with self.assertRaises(PredicateError):
            validate_definition({"predicate_id": "p", "expression": {"not": {"record_ids": ["r1"]}}}, self.declarations, self.metadata)

    def test_predicate_literal_type_must_match_declaration(self):
        with self.assertRaisesRegex(PredicateError, "type_mismatch"):
            validate_definition({"predicate_id": "p", "expression": {"field": {"field": {"source": "table_field", "table": "L", "name": "status"}, "op": "eq", "value": 1}}}, self.declarations, self.metadata)
        with self.assertRaisesRegex(PredicateError, "type_mismatch"):
            validate_definition({"predicate_id": "p", "expression": {"field": {"field": {"source": "table_field", "table": "L", "name": "status"}, "op": "in", "values": [True]}}}, self.declarations, self.metadata)

    def test_historical_table_field_predicate_uses_only_declared_table(self):
        context = PredicateContext({
            "M": [{"record_id": "r1", "values": {"status": "OPEN"}}],
            "H": [{"record_id": "r1", "values": {"status": "CLOSED"}}],
            "W": [{"record_id": "r1", "values": {"status": "CLOSED"}}],
        }, {})
        expression = {"field": {"field": {"source": "table_field", "table": "M", "name": "status"}, "op": "eq", "value": "OPEN"}}
        declarations = {("M", "status"): {"type": "string"}}
        validate_definition({"predicate_id": "p", "expression": expression}, declarations, {})
        self.assertEqual(evaluate(expression, context), {"r1"})

    def test_depth_and_node_limits_accept_boundary_and_reject_overflow(self):
        at_depth_eight = {"record_ids": ["r1"]}
        for _ in range(7):
            at_depth_eight = {"all": [at_depth_eight]}
        validate_definition({"predicate_id": "depth-ok", "expression": at_depth_eight}, self.declarations, self.metadata)
        too_deep = {"all": [at_depth_eight]}
        with self.assertRaisesRegex(PredicateError, "depth_exceeded"):
            validate_definition({"predicate_id": "depth-over", "expression": too_deep}, self.declarations, self.metadata)

        exactly_64_nodes = {"all": [{"record_ids": ["r1"]} for _ in range(63)]}
        validate_definition({"predicate_id": "nodes-ok", "expression": exactly_64_nodes}, self.declarations, self.metadata)
        over_64_nodes = {"all": [{"record_ids": ["r1"]} for _ in range(64)]}
        with self.assertRaisesRegex(PredicateError, "nodes_exceeded"):
            validate_definition({"predicate_id": "nodes-over", "expression": over_64_nodes}, self.declarations, self.metadata)

    def test_limits_are_counted_independently_per_definition(self):
        definitions = [
            {"predicate_id": "p1", "expression": {"all": [{"record_ids": ["r1"]} for _ in range(39)]}},
            {"predicate_id": "p2", "expression": {"all": [{"record_ids": ["r1"]} for _ in range(39)]}},
        ]
        for definition in definitions:
            validate_definition(definition, self.declarations, self.metadata)

    def test_all_authorization_operators_are_forbidden_on_timestamp_fields_and_metadata(self):
        timestamp_declarations = {("L", "at"): {"type": "string", "format": "rfc3339-timestamp"}}
        timestamp_metadata = {"seen_at": {"type": "string", "format": "rfc3339-timestamp"}}
        for op in ("eq", "neq", "in", "not_in", "lt", "lte", "gt", "gte"):
            for reference in ({"source": "table_field", "table": "L", "name": "at"}, {"source": "record_metadata", "name": "seen_at"}):
                node = {"field": reference, "op": op, "value": "2026-01-01T00:00:00Z"} if op in {"eq", "neq", "lt", "lte", "gt", "gte"} else {"field": reference, "op": op, "values": ["2026-01-01T00:00:00Z"]}
                with self.subTest(op=op, reference=reference), self.assertRaisesRegex(PredicateError, "timestamp_predicate_forbidden"):
                    validate_definition({"predicate_id": "p", "expression": {"field": node}}, timestamp_declarations, timestamp_metadata)


if __name__ == "__main__":
    unittest.main()
