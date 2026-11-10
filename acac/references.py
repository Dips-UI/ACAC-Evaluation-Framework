"""Immutable reference-content structural and ledger-integrity checks."""
from copy import deepcopy
import hashlib
from .patches import validate_patch
from .strict_json import equal, loads_bytes, matches_type, parse_rfc3339_timestamp
from .authorization import validate_sidecar


class ReferenceError(ValueError):
    pass


def _identifier(value: object, label: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise ReferenceError(f"invalid_{label}")


def _hash_matches(expected: object, raw: bytes | None, label: str) -> None:
    if not isinstance(expected, str) or len(expected) != 71 or not expected.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in expected[7:]):
        raise ReferenceError(f"invalid_{label}")
    if raw is not None and expected != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise ReferenceError(f"{label.removesuffix('_hash')}_hash_mismatch")


def validate_reference(reference: dict, case: dict, declarations: dict, authorization: dict, *, source_case_bytes: bytes | None = None, authorization_spec_bytes: bytes | None = None, retained_artifacts: dict[str, bytes] | None = None) -> None:
    required = {"schema_version", "reference_id", "revision", "case_id", "source_case_hash", "authorization_spec_hash", "eligible_keys", "expected_output", "final_ledger", "preservation_keys", "rationale", "author"}
    if not isinstance(reference, dict) or set(reference) != required:
        raise ReferenceError("reference_members")
    if reference["schema_version"] != "acac-1.3" or reference["case_id"] != case["case_id"] or type(reference["revision"]) is not int or reference["revision"] < 1:
        raise ReferenceError("reference_identity")
    _identifier(reference["reference_id"], "reference_id")
    if authorization.get("resolution_status") != "resolved":
        raise ReferenceError("authorization_not_resolved")
    if source_case_bytes is None or authorization_spec_bytes is None:
        raise ReferenceError("retained_source_artifact_bytes_required")
    for name in ("source_case_hash", "authorization_spec_hash"):
        _hash_matches(reference[name], source_case_bytes if name == "source_case_hash" else authorization_spec_bytes, name)
    try:
        retained_case = loads_bytes(source_case_bytes)
        retained_authorization = loads_bytes(authorization_spec_bytes)
    except Exception as exc:
        raise ReferenceError("retained_source_artifact_json_invalid") from exc
    if retained_case != case or retained_authorization != authorization:
        raise ReferenceError("retained_artifact_content_mismatch")
    retained = dict(retained_artifacts or {})
    retained["sha256:" + hashlib.sha256(source_case_bytes).hexdigest()] = source_case_bytes
    sidecar_result = validate_sidecar(
        retained_authorization,
        case_id=case["case_id"],
        profile=case["profile"],
        case=retained_case,
        retained_artifacts=retained,
    )
    if not sidecar_result.valid:
        raise ReferenceError("linked_authorization_invalid:" + ",".join(sidecar_result.errors))
    authorization = retained_authorization
    author = reference["author"]
    if not isinstance(author, dict) or set(author) != {"author_id", "role", "created_at"} or author["role"] != "reference_author":
        raise ReferenceError("author")
    _identifier(author["author_id"], "author_id")
    parse_rfc3339_timestamp(author["created_at"])
    if not isinstance(reference["rationale"], str):
        raise ReferenceError("rationale")
    if not isinstance(reference["eligible_keys"], list) or any(not isinstance(key, list) or len(key) != 3 or any(not isinstance(part, str) for part in key) for key in reference["eligible_keys"]):
        raise ReferenceError("eligible_keys_shape")
    eligible = [tuple(key) for key in reference["eligible_keys"]]
    if len(eligible) != len(set(eligible)):
        raise ReferenceError("duplicate_eligible_keys")
    if set(eligible) != {tuple(key) for key in authorization.get("eligible_keys", [])}:
        raise ReferenceError("eligible_key_mismatch")
    sidecar_eligible = authorization.get("eligible_keys", [])
    if not isinstance(sidecar_eligible, list) or any(not isinstance(key, list) or len(key) != 3 for key in sidecar_eligible):
        raise ReferenceError("authorization_eligible_keys_shape")
    if set(eligible) != {tuple(key) for key in sidecar_eligible}:
        raise ReferenceError("eligible_key_mismatch")
    required_values = authorization.get("required_final_values")
    if not isinstance(required_values, list):
        raise ReferenceError("required_final_values_required")
    required_by_key = {}
    for entry in required_values:
        if not isinstance(entry, dict) or set(entry) != {"key", "value"} or not isinstance(entry["key"], list) or len(entry["key"]) != 3:
            raise ReferenceError("required_final_value_shape")
        key = tuple(entry["key"])
        if key in required_by_key:
            raise ReferenceError("duplicate_required_final_value")
        required_by_key[key] = entry["value"]
    if set(required_by_key) != set(eligible):
        raise ReferenceError("required_final_values_coverage")
    initial_cells = {(table, row["record_id"], field): value for table, rows in case["payload"]["ledger"].items() for row in rows for field, value in row["values"].items()}
    notice = case.get("payload", {}).get("notice", {})
    if notice.get("operation") == "no_op":
        if eligible or required_by_key or not isinstance(reference["expected_output"], dict) or reference["expected_output"].get("edits") != []:
            raise ReferenceError("no_op_authorization_must_be_empty")
    for key, value in required_by_key.items():
        declaration = declarations.get((key[0], key[2]))
        if key not in initial_cells or declaration is None or declaration.get("mutable") is not True or not matches_type(value, declaration["type"]):
            raise ReferenceError("required_final_value_invalid")
    result = validate_patch(reference["expected_output"], case["payload"]["ledger"], declarations, case["profile"])
    if not result.valid:
        raise ReferenceError("invalid_expected_output:" + ",".join(result.errors))
    expected_edit_values = {key: value for key, value in required_by_key.items() if not equal(initial_cells[key], value)}
    actual_edits = {(edit["table"], edit["record_id"], edit["field"]): edit for edit in result.edits}
    if set(actual_edits) != set(expected_edit_values):
        raise ReferenceError("expected_edit_set_mismatch")
    for key, new_value in expected_edit_values.items():
        edit = actual_edits[key]
        if not equal(edit["old_value"], initial_cells[key]) or not equal(edit["new_value"], new_value):
            raise ReferenceError("expected_edit_value_mismatch")
    if not isinstance(reference["final_ledger"], dict) or set(reference["final_ledger"]) != set(case["payload"]["ledger"]):
        raise ReferenceError("final_ledger_shape")
    final_cells = {(table, row["record_id"], field): value for table, rows in reference["final_ledger"].items() for row in rows for field, value in row["values"].items()}
    if set(initial_cells) != set(final_cells):
        raise ReferenceError("final_ledger_cells")
    expected_final = result.isolated_ledger
    expected_cells = {(table, row["record_id"], field): value for table, rows in expected_final.items() for row in rows for field, value in row["values"].items()}
    if any(not equal(final_cells[key], expected_cells[key]) for key in expected_cells):
        raise ReferenceError("final_ledger_mismatch")
    preservation = {key for key in initial_cells if equal(initial_cells[key], final_cells[key])}
    if not isinstance(reference["preservation_keys"], list) or any(not isinstance(key, list) or len(key) != 3 for key in reference["preservation_keys"]):
        raise ReferenceError("preservation_keys_shape")
    if {tuple(key) for key in reference["preservation_keys"]} != preservation:
        raise ReferenceError("preservation_keys_mismatch")
