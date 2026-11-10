"""V1 semantic canonicalization and exact-byte hashing helpers."""

import hashlib
import json
from decimal import Decimal
from typing import Any


_SET_ARRAY_KEYS = {
    "evidence_registry": "evidence_id",
    "predicate_definitions": "predicate_id",
    "exclusions": "exclusion_id",
    "exceptions_applied": "exception_id",
    "resolution_issues": "issue_id",
    "excluded_cases": "case_id",
    "review_submission_hashes": None,
    "exception_decisions": None,
}


def _address_sort_key(item: Any) -> tuple[str, ...]:
    if not isinstance(item, (list, tuple)) or not all(isinstance(part, str) for part in item):
        raise ValueError("invalid_semantic_address")
    return tuple(item)


def _array_key(parent: str | None, values: list[Any]) -> Any:
    if parent in _SET_ARRAY_KEYS:
        member = _SET_ARRAY_KEYS[parent]
        if member is None:
            if parent == "exception_decisions":
                return lambda item: (
                    item["exception_id"], item["exclusion_id"],
                    _address_sort_key(item["key"]),
                )
            return lambda item: item
        return lambda item: item[member]
    if parent == "temporal_rules":
        return lambda item: (item["source_location"], item["occurrence_index"], item["rule_id"])
    if parent in {"scheduled_case_ids", "executed_case_ids"}:
        return lambda item: item
    if parent in {"eligible_keys", "preservation_keys"}:
        return _address_sort_key
    if parent == "edits":
        return lambda item: (item["table"], item["record_id"], item["field"])
    if parent == "field_declarations":
        return lambda item: (item["table"], item["field"])
    if parent in {"L", "M", "H", "W"}:
        if values and all(isinstance(item, dict) and "record_id" in item for item in values):
            return lambda item: item["record_id"]
    return None


def semantic_value(value: Any, _parent: str | None = None) -> Any:
    """Return the deterministic semantic structure, preserving source-order arrays."""
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("semantic_object_keys_must_be_strings")
        return {key: semantic_value(value[key], key) for key in sorted(value, key=lambda item: tuple(map(ord, item)))}
    if isinstance(value, list):
        result = [semantic_value(item) for item in value]
        key = _array_key(_parent, result)
        return sorted(result, key=key) if key is not None else result
    if value is None:
        raise ValueError("semantic_null_forbidden")
    if isinstance(value, float):
        raise ValueError("semantic_float_forbidden")
    if isinstance(value, Decimal) and not value.is_finite():
        raise ValueError("semantic_nonfinite_decimal")
    if isinstance(value, int) and not isinstance(value, bool) and not -(2**63) <= value <= 2**63 - 1:
        raise ValueError("semantic_integer_out_of_range")
    return value


def _decimal_token(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("semantic_nonfinite_decimal")
    token = format(value, "f")
    if "." in token:
        token = token.rstrip("0").rstrip(".")
    if token in {"", "-", "-0"}:
        return "0"
    return token


def _encode(value: Any, *, decimal_allowed: bool = False) -> str:
    if isinstance(value, dict):
        members = []
        for key in sorted(value, key=lambda item: tuple(map(ord, item))):
            child = value[key]
            allow_child_decimal = decimal_allowed or key == "settings" or key == "metrics"
            members.append(json.dumps(key, ensure_ascii=False) + ":" + _encode(child, decimal_allowed=allow_child_decimal))
        return "{" + ",".join(members) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_encode(item, decimal_allowed=decimal_allowed) for item in value) + "]"
    if isinstance(value, Decimal):
        if not decimal_allowed:
            raise ValueError("semantic_decimal_forbidden")
        return _decimal_token(value)
    if value is None:
        raise ValueError("semantic_null_forbidden")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("semantic_float_forbidden")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    raise ValueError("unsupported_semantic_value")


def semantic_bytes(value: Any) -> bytes:
    normalized = semantic_value(value)
    return _encode(normalized).encode("utf-8")


def semantic_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(semantic_bytes(value)).hexdigest()


def exact_hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
