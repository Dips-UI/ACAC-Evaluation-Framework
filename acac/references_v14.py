"""Immutable ACAC v1.4 reference validation against trusted artifacts."""

from dataclasses import dataclass
import hashlib
from typing import Any

from .authorization_sidecar_v14 import validate_final_sidecar_v14
from .case_validation import validate_case
from .patches import validate_patch
from .strict_json import is_integer, loads_bytes, matches_type, parse_rfc3339_timestamp, equal


class ReferenceV14Error(ValueError):
    pass


@dataclass(frozen=True)
class ReferenceValidationResult:
    valid: bool
    reference_hash: str | None
    errors: tuple[str, ...]


_FIELDS = {
    "schema_version", "reference_id", "revision", "case_id", "source_case_hash",
    "authorization_input_hash", "eligible_keys", "expected_output", "final_ledger",
    "preservation_keys", "rationale", "author",
}


def _identifier(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise ReferenceV14Error(f"invalid_{label}")


def _hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise ReferenceV14Error(f"invalid_{label}")


def _address(value: Any, label: str) -> tuple[str, str, str]:
    if not isinstance(value, list) or len(value) != 3:
        raise ReferenceV14Error(f"invalid_{label}")
    for part in value:
        _identifier(part, label)
    return tuple(value)


def _same_json_value(left: Any, right: Any) -> bool:
    if isinstance(left, dict) or isinstance(right, dict):
        return isinstance(left, dict) and isinstance(right, dict) and set(left) == set(right) and all(_same_json_value(left[k], right[k]) for k in left)
    if isinstance(left, list) or isinstance(right, list):
        return isinstance(left, list) and isinstance(right, list) and len(left) == len(right) and all(_same_json_value(a, b) for a, b in zip(left, right))
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is bool and type(right) is bool and left is right
    if is_integer(left) or is_integer(right):
        return is_integer(left) and is_integer(right) and int(left) == int(right)
    return type(left) is type(right) and left == right


def _cells(ledger: Any, tables: set[str]) -> dict[tuple[str, str, str], Any]:
    if not isinstance(ledger, dict) or set(ledger) != tables:
        raise ReferenceV14Error("final_ledger_tables")
    result: dict[tuple[str, str, str], Any] = {}
    for table, rows in ledger.items():
        if not isinstance(rows, list):
            raise ReferenceV14Error("final_ledger_rows")
        record_ids: set[str] = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"record_id", "values"} or not isinstance(row["values"], dict):
                raise ReferenceV14Error("final_ledger_row_shape")
            record_id = row["record_id"]
            _identifier(record_id, "final_record_id")
            if record_id in record_ids:
                raise ReferenceV14Error("duplicate_final_record_id")
            record_ids.add(record_id)
            for field, value in row["values"].items():
                _identifier(field, "final_field")
                result[(table, record_id, field)] = value
    return result


def validate_reference_v14(
    value: Any,
    *,
    reference_bytes: bytes,
    case: Any,
    case_bytes: bytes,
    authorization_input: Any,
    authorization_input_bytes: bytes,
    sidecar: Any,
    sidecar_bytes: bytes,
    reviews_by_hash: dict[str, tuple[dict, bytes]],
) -> ReferenceValidationResult:
    """Verify reference identity, sidecar eligibility, and exact transition.

    This component verifies artifact integrity only. It does not make a
    reference eligible for grading; lifecycle approval and the integrated
    manifest-bound coordinator are separate gates.
    """
    try:
        if not all(isinstance(raw, bytes) for raw in (reference_bytes, case_bytes, authorization_input_bytes, sidecar_bytes)):
            raise ReferenceV14Error("retained_exact_bytes_required")
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value) or set(value) != _FIELDS:
            raise ReferenceV14Error("reference_members")
        if not _same_json_value(loads_bytes(reference_bytes), value):
            raise ReferenceV14Error("reference_bytes_content_mismatch")
        case_result = validate_case(case)
        if not case_result.valid or not _same_json_value(loads_bytes(case_bytes), case):
            raise ReferenceV14Error("invalid_or_mismatched_case")
        sidecar_result = validate_final_sidecar_v14(
            sidecar, sidecar_bytes=sidecar_bytes, case=case, case_bytes=case_bytes,
            authorization_input=authorization_input,
            authorization_input_bytes=authorization_input_bytes,
            reference=value, reference_bytes=reference_bytes,
            reviews_by_hash=reviews_by_hash,
        )
        if not sidecar_result.valid:
            raise ReferenceV14Error("linked_sidecar_invalid:" + ",".join(sidecar_result.errors))
        if sidecar_result.status != "resolved":
            raise ReferenceV14Error("authorization_not_resolved")
        if value["schema_version"] != "acac-1.4" or value["case_id"] != case["case_id"]:
            raise ReferenceV14Error("reference_identity")
        _identifier(value["reference_id"], "reference_id")
        if not is_integer(value["revision"]) or int(value["revision"]) <= 0:
            raise ReferenceV14Error("reference_revision_must_be_positive_integer")
        case_hash = "sha256:" + hashlib.sha256(case_bytes).hexdigest()
        input_hash = "sha256:" + hashlib.sha256(authorization_input_bytes).hexdigest()
        if value["source_case_hash"] != case_hash or sidecar["source_case_hash"] != case_hash:
            raise ReferenceV14Error("source_case_hash_mismatch")
        if value["authorization_input_hash"] != input_hash or sidecar["authorization_input_hash"] != input_hash:
            raise ReferenceV14Error("authorization_input_hash_mismatch")
        author = value["author"]
        if not isinstance(author, dict) or set(author) != {"author_id", "role", "created_at"} or author["role"] != "reference_author":
            raise ReferenceV14Error("reference_author_shape")
        _identifier(author["author_id"], "author_id")
        parse_rfc3339_timestamp(author["created_at"])
        if not isinstance(value["rationale"], str):
            raise ReferenceV14Error("reference_rationale_must_be_string")

        payload = case["payload"]
        declarations = {(item["table"], item["field"]): item for item in payload["field_declarations"]}
        initial_cells = _cells(payload["ledger"], set(payload["ledger"]))
        eligible_list = [_address(key, "eligible_key") for key in value["eligible_keys"]] if isinstance(value["eligible_keys"], list) else None
        if eligible_list is None or len(eligible_list) != len(set(eligible_list)):
            raise ReferenceV14Error("eligible_keys_shape_or_duplicates")
        sidecar_eligible = [_address(key, "sidecar_eligible_key") for key in sidecar["eligible_keys"]]
        if set(eligible_list) != set(sidecar_eligible) or len(sidecar_eligible) != len(set(sidecar_eligible)):
            raise ReferenceV14Error("eligible_key_mismatch")

        required_values = sidecar["required_final_values"]
        required_by_key: dict[tuple[str, str, str], Any] = {}
        for entry in required_values:
            key = _address(entry["key"], "required_final_value_key")
            if key in required_by_key:
                raise ReferenceV14Error("duplicate_required_final_value")
            declaration = declarations.get((key[0], key[2]))
            if key not in initial_cells or declaration is None or not matches_type(entry["value"], declaration["type"]):
                raise ReferenceV14Error("required_final_value_type_mismatch")
            required_by_key[key] = entry["value"]
        if set(required_by_key) != set(eligible_list):
            raise ReferenceV14Error("required_final_values_coverage")

        patch = validate_patch(value["expected_output"], payload["ledger"], declarations, case["profile"])
        if not patch.valid:
            raise ReferenceV14Error("invalid_expected_output:" + ",".join(patch.errors))
        expected_changes = {
            key: new_value for key, new_value in required_by_key.items()
            if not equal(initial_cells[key], new_value)
        }
        actual_edits = {(edit["table"], edit["record_id"], edit["field"]): edit for edit in patch.edits}
        if set(actual_edits) != set(expected_changes):
            raise ReferenceV14Error("expected_edit_set_mismatch")
        for key, new_value in expected_changes.items():
            edit = actual_edits[key]
            if not equal(edit["old_value"], initial_cells[key]) or not equal(edit["new_value"], new_value):
                raise ReferenceV14Error("expected_edit_value_mismatch")

        final_cells = _cells(value["final_ledger"], set(payload["ledger"]))
        if set(final_cells) != set(initial_cells):
            raise ReferenceV14Error("final_ledger_cells")
        computed = _cells(patch.isolated_ledger, set(payload["ledger"]))
        if set(final_cells) != set(computed) or any(not equal(final_cells[key], computed[key]) for key in computed):
            raise ReferenceV14Error("final_ledger_mismatch")
        unchanged = {key for key in initial_cells if equal(initial_cells[key], final_cells[key])}
        preservation_values = value["preservation_keys"]
        if not isinstance(preservation_values, list):
            raise ReferenceV14Error("preservation_keys_shape")
        preservation = [_address(key, "preservation_key") for key in preservation_values]
        if len(preservation) != len(set(preservation)) or set(preservation) != unchanged:
            raise ReferenceV14Error("preservation_keys_mismatch")
        if payload["notice"]["operation"] == "no_op" and (eligible_list or patch.edits):
            raise ReferenceV14Error("no_op_authorization_must_be_empty")
        return ReferenceValidationResult(True, "sha256:" + hashlib.sha256(reference_bytes).hexdigest(), ())
    except Exception as exc:
        return ReferenceValidationResult(False, None, (str(exc),))
