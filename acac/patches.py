"""V1 structural patch validation and isolated application."""
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from .strict_json import JSONContractError, equal, matches_type, loads_bytes, parse_rfc3339_timestamp


class PatchError(ValueError):
    pass


@dataclass(frozen=True)
class PatchResult:
    valid: bool
    edits: tuple[dict[str, Any], ...]
    errors: tuple[str, ...]
    isolated_ledger: dict[str, Any] | None
    operation_diagnostics: tuple[tuple[int, bool, tuple[str, ...]], ...] = ()


def _keys(value: Any, required: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != required:
        raise PatchError("invalid_patch_members")


def validate_patch(patch: Any, ledger: dict[str, list[dict[str, Any]]], declarations: dict[tuple[str, str], dict[str, Any]], profile: str) -> PatchResult:
    try:
        envelope_errors: list[str] = []
        if not isinstance(patch, dict) or any(not isinstance(key, str) for key in patch):
            raise PatchError("invalid_patch_members")
        if set(patch) != {"schema_version", "edits"}:
            envelope_errors.append("invalid_patch_members")
        if patch.get("schema_version") != "acac-1.3":
            envelope_errors.append("invalid_patch_version_or_edits")
        if not isinstance(patch.get("edits"), list):
            envelope_errors.append("invalid_patch_version_or_edits")
            return PatchResult(False, (), tuple(envelope_errors), None)
        tables = {"L"} if profile == "single-ledger-1.0" else {"M", "H", "W"}
        cells = {(table, row["record_id"], field): value for table, rows in ledger.items() for row in rows for field, value in row["values"].items()}
        target_indices: dict[tuple[str, str, str], list[int]] = {}
        errors = list(envelope_errors)
        operation_diagnostics = []
        for index, edit in enumerate(patch["edits"]):
            operation_errors: list[str] = []
            key = None
            try:
                _keys(edit, {"op", "table", "record_id", "field", "old_value", "new_value"})
                if edit["op"] != "replace":
                    raise PatchError("unsupported_operation")
                key = (edit["table"], edit["record_id"], edit["field"])
                if edit["table"] not in tables or key not in cells:
                    raise PatchError("unknown_address")
                target_indices.setdefault(key, []).append(index)
                declaration = declarations.get((edit["table"], edit["field"]))
                if declaration is None or not matches_type(edit["old_value"], declaration["type"]) or not matches_type(edit["new_value"], declaration["type"]):
                    raise PatchError("wrong_value_type")
                if declaration.get("format") == "rfc3339-timestamp":
                    try:
                        parse_rfc3339_timestamp(edit["old_value"])
                        parse_rfc3339_timestamp(edit["new_value"])
                    except Exception as exc:
                        raise PatchError("invalid_timestamp_value") from exc
                if not equal(edit["old_value"], cells[key]):
                    raise PatchError("stale_old_value")
                if equal(edit["old_value"], edit["new_value"]):
                    raise PatchError("no_op_write")
            except (PatchError, KeyError, TypeError) as exc:
                operation_errors.append(str(exc))
            operation_diagnostics.append((index, not operation_errors, tuple(operation_errors)))
            errors.extend(f"edit_{index}:{error}" for error in operation_errors)

        # Duplicate targets are conflicts between otherwise independently
        # checked operations. Report them at patch level without marking either
        # operation invalid in isolation.
        for key, indices in target_indices.items():
            if len(indices) > 1:
                errors.append(f"patch:duplicate_target:{key}:edits={indices}")
        if errors:
            return PatchResult(
                False, tuple(patch["edits"]), tuple(errors), None,
                tuple(operation_diagnostics),
            )
        result = deepcopy(ledger)
        for edit in patch["edits"]:
            for row in result[edit["table"]]:
                if row["record_id"] == edit["record_id"]:
                    row["values"][edit["field"]] = edit["new_value"]
        return PatchResult(True, tuple(patch["edits"]), (), result, tuple(operation_diagnostics))
    except (PatchError, KeyError, TypeError) as exc:
        return PatchResult(False, (), (str(exc),), None)


def validate_patch_bytes(data: bytes, ledger: dict[str, list[dict[str, Any]]], declarations: dict[tuple[str, str], dict[str, Any]], profile: str) -> PatchResult:
    try:
        return validate_patch(loads_bytes(data), ledger, declarations, profile)
    except (JSONContractError, UnicodeDecodeError) as exc:
        return PatchResult(False, (), (f"parse:{exc}",), None)
