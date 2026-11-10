"""Bounded V1 predicate validation and deterministic evaluation.

This module handles only the explicit predicate grammar from the V1 contract.
It does not resolve authorization sidecars or infer semantics from prose.
"""

from dataclasses import dataclass
from typing import Any, Mapping

from .strict_json import is_integer, matches_type


MAX_DEPTH = 8
MAX_NODES = 64
_OPS = {"eq", "neq", "in", "not_in"}


class PredicateError(ValueError):
    pass


@dataclass(frozen=True)
class PredicateContext:
    ledger: Mapping[str, list[Mapping[str, Any]]]
    record_metadata: Mapping[str, Mapping[str, Any]]


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise PredicateError(f"invalid_{label}")
    return value


def _exact_keys(obj: Any, required: set[str], optional: set[str] = set()) -> None:
    if not isinstance(obj, dict):
        raise PredicateError("object_required")
    keys = set(obj)
    if any(not isinstance(k, str) for k in keys):
        raise PredicateError("string_keys_required")
    if keys - required - optional:
        raise PredicateError("unsupported_predicate_members")
    if required - keys:
        raise PredicateError("missing_predicate_members")


def validate_expression(expression: Any, declarations: Mapping[tuple[str, str], Mapping[str, Any]], metadata: Mapping[str, Mapping[str, Any]], *, depth: int = 1) -> int:
    if depth > MAX_DEPTH:
        raise PredicateError("predicate_depth_exceeded")
    if not isinstance(expression, dict):
        raise PredicateError("predicate_object_required")
    if len(expression) != 1:
        raise PredicateError("predicate_node_must_have_one_member")
    key = next(iter(expression))
    if key == "record_ids":
        values = expression[key]
        if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values) or len(set(values)) != len(values):
            raise PredicateError("invalid_record_ids")
    elif key == "batch_ids":
        value = expression[key]
        _exact_keys(value, {"field", "values"})
        _validate_field_ref(value["field"], declarations, metadata, require_string=True)
        if not isinstance(value["values"], list) or not value["values"] or any(not isinstance(v, str) for v in value["values"]):
            raise PredicateError("invalid_batch_values")
    elif key == "field":
        value = expression[key]
        _exact_keys(value, {"field", "op"}, {"value", "values"})
        _validate_field_ref(value["field"], declarations, metadata)
        if not isinstance(value["op"], str) or value["op"] not in _OPS:
            raise PredicateError("unsupported_predicate_operator")
        op = value["op"]
        reference = value["field"]
        declaration = declarations.get((reference["table"], reference["name"])) if reference.get("source") == "table_field" else metadata.get(reference.get("name"))
        if op in {"eq", "neq"}:
            if "value" not in value or "values" in value or value["value"] is None:
                raise PredicateError("invalid_scalar_predicate_value")
            if declaration is None or not _matches_declared(value["value"], declaration):
                raise PredicateError("predicate_value_type_mismatch")
        else:
            if "values" not in value or "value" in value or not isinstance(value["values"], list) or not value["values"]:
                raise PredicateError("invalid_set_predicate_value")
            if declaration is None or any(not _matches_declared(item, declaration) for item in value["values"]):
                raise PredicateError("predicate_value_type_mismatch")
    elif key in {"all", "any"}:
        children = expression[key]
        if not isinstance(children, list) or not children:
            raise PredicateError("predicate_children_required")
        total = 1
        for child in children:
            total += validate_expression(child, declarations, metadata, depth=depth + 1)
        if total > MAX_NODES:
            raise PredicateError("predicate_nodes_exceeded")
        return total
    else:
        raise PredicateError("unsupported_predicate_node")
    return 1


def _validate_field_ref(reference: Any, declarations: Mapping[tuple[str, str], Mapping[str, Any]], metadata: Mapping[str, Mapping[str, Any]], *, require_string: bool = False) -> None:
    if not isinstance(reference, dict) or set(reference) not in ({"source", "table", "name"}, {"source", "name"}):
        raise PredicateError("invalid_field_reference")
    source = reference.get("source")
    name = reference.get("name")
    _string(name, "field_name")
    if source == "table_field" and set(reference) == {"source", "table", "name"}:
        _string(reference.get("table"), "table")
        declaration = declarations.get((reference["table"], name))
    elif source == "record_metadata" and set(reference) == {"source", "name"}:
        declaration = metadata.get(name)
    else:
        raise PredicateError("invalid_field_reference")
    if declaration is None:
        raise PredicateError("unknown_predicate_field")
    if declaration.get("format") == "rfc3339-timestamp":
        raise PredicateError("timestamp_predicate_forbidden")
    if require_string and declaration.get("type") != "string":
        raise PredicateError("batch_field_must_be_string")


def _matches_declared(value: Any, declaration: Mapping[str, Any]) -> bool:
    declared = declaration.get("type")
    if declared == "string":
        return type(value) is str
    if declared == "integer":
        return is_integer(value)
    if declared == "boolean":
        return type(value) is bool
    return False


def validate_definition(definition: Any, declarations: Mapping[tuple[str, str], Mapping[str, Any]], metadata: Mapping[str, Mapping[str, Any]]) -> None:
    _exact_keys(definition, {"predicate_id", "expression"})
    _string(definition["predicate_id"], "predicate_id")
    nodes = validate_expression(definition["expression"], declarations, metadata)
    if nodes > MAX_NODES:
        raise PredicateError("predicate_nodes_exceeded")


def evaluate(expression: Any, context: PredicateContext) -> set[str]:
    if "record_ids" in expression:
        return set(expression["record_ids"])
    if "all" in expression:
        result = None
        for child in expression["all"]:
            ids = evaluate(child, context)
            result = ids if result is None else result & ids
        return result or set()
    if "any" in expression:
        result: set[str] = set()
        for child in expression["any"]:
            result |= evaluate(child, context)
        return result
    if "batch_ids" in expression:
        node = expression["batch_ids"]
        field = node["field"]
        values = set(node["values"])
        return {row["record_id"] for row in context.ledger[field["table"]] if row.get("values", {}).get(field["name"]) in values}
    node = expression["field"]
    ref = node["field"]
    # Historical profiles intentionally repeat record IDs across M/H/W. A
    # table-field predicate must inspect only its declared table; otherwise a
    # later table with the same record ID can overwrite the selected value.
    if ref["source"] == "table_field":
        rows = ((ref["table"], row) for row in context.ledger[ref["table"]])
    else:
        rows = ((table, row) for table, values in context.ledger.items() for row in values)
    selected = {}
    for table, row in rows:
        selected[row["record_id"]] = row.get("values", {}).get(ref["name"]) if ref["source"] == "table_field" else context.record_metadata.get(row["record_id"], {}).get(ref["name"])
    op = node["op"]
    expected = node.get("value")
    values = set(node.get("values", []))
    if op == "eq": return {rid for rid, value in selected.items() if value == expected}
    if op == "neq": return {rid for rid, value in selected.items() if value != expected}
    if op == "in": return {rid for rid, value in selected.items() if value in values}
    return {rid for rid, value in selected.items() if value not in values}
