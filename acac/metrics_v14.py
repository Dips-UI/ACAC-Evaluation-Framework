"""Exact v1.4 rational metric representation and display helpers."""

from fractions import Fraction
import re
from typing import Any

from .strict_json import equal


class RationalMetricError(ValueError):
    pass


_NUMERATOR = re.compile(r"(?:0|-[1-9][0-9]*|[1-9][0-9]*)\Z")
_DENOMINATOR = re.compile(r"[1-9][0-9]*\Z")


def _parse_integer(token: str) -> int:
    """Parse canonical base-10 integers without Python's digit-count limit."""
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    result = 0
    first = len(digits) % 9 or 9
    result = int(digits[:first])
    for offset in range(first, len(digits), 9):
        chunk = digits[offset:offset + 9]
        result = result * (10 ** len(chunk)) + int(chunk)
    return -result if negative else result


def _integer_token(value: int) -> str:
    """Format arbitrary-precision integer without int-to-string limits."""
    if value == 0:
        return "0"
    negative = value < 0
    remaining = abs(value)
    chunks: list[int] = []
    while remaining:
        remaining, chunk = divmod(remaining, 1_000_000_000)
        chunks.append(chunk)
    token = str(chunks[-1]) + "".join(f"{chunk:09d}" for chunk in reversed(chunks[:-1]))
    return "-" + token if negative else token


def rational(numerator: int, denominator: int) -> dict[str, str]:
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise RationalMetricError("invalid_rational_operands")
    value = Fraction(numerator, denominator)
    return {"numerator": _integer_token(value.numerator), "denominator": _integer_token(value.denominator)}


def validate_rational(value: Any, *, minimum: Fraction | None = None, maximum: Fraction | None = None) -> Fraction:
    if not isinstance(value, dict) or set(value) != {"numerator", "denominator"}:
        raise RationalMetricError("rational_shape")
    numerator, denominator = value["numerator"], value["denominator"]
    if not isinstance(numerator, str) or _NUMERATOR.fullmatch(numerator) is None:
        raise RationalMetricError("rational_numerator_grammar")
    if not isinstance(denominator, str) or _DENOMINATOR.fullmatch(denominator) is None:
        raise RationalMetricError("rational_denominator_grammar")
    n, d = _parse_integer(numerator), _parse_integer(denominator)
    if Fraction(n, d).numerator != n or Fraction(n, d).denominator != d:
        raise RationalMetricError("rational_not_reduced")
    result = Fraction(n, d)
    if minimum is not None and result < minimum or maximum is not None and result > maximum:
        raise RationalMetricError("rational_out_of_range")
    return result


def add(*values: dict[str, str]) -> dict[str, str]:
    total = sum((validate_rational(value) for value in values), Fraction(0, 1))
    return rational(total.numerator, total.denominator)


def divide(value: dict[str, str], divisor: int) -> dict[str, str]:
    if type(divisor) is not int or divisor <= 0:
        raise RationalMetricError("invalid_rational_divisor")
    fraction = validate_rational(value) / divisor
    return rational(fraction.numerator, fraction.denominator)


def display_six_half_even(value: dict[str, str]) -> str:
    """Render a rational for display only; the returned text is not metric data."""
    fraction = validate_rational(value)
    scale = 1_000_000
    scaled_numerator = abs(fraction.numerator) * scale
    quotient, remainder = divmod(scaled_numerator, fraction.denominator)
    twice = 2 * remainder
    if twice > fraction.denominator or (twice == fraction.denominator and quotient % 2 == 1):
        quotient += 1
    whole, fractional = divmod(quotient, scale)
    sign = "-" if fraction.numerator < 0 and quotient else ""
    return f"{sign}{_integer_token(whole)}.{fractional:06d}"


def grade_patch_v14(patch: Any, initial: dict[str, list[dict[str, Any]]], eligible_keys: list[list[str]], required_final_values: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute v1.4 case metrics using exact integer/rational arithmetic.

    Eligibility is intentionally not accepted as a Boolean here. The v1.4
    coordinator must call this only after validating the retained artifact
    chain; this function computes metrics and does not establish that chain.
    """
    from .patches import PatchResult

    if not isinstance(patch, PatchResult):
        raise RationalMetricError("validated_patch_result_required")
    if not isinstance(initial, dict) or not isinstance(eligible_keys, list) or not isinstance(required_final_values, list):
        raise RationalMetricError("grading_inputs_invalid")
    eligible = {tuple(key) for key in eligible_keys}
    required = {tuple(item["key"]): item["value"] for item in required_final_values}
    all_values = {
        (table, row["record_id"], field): value
        for table, rows in initial.items()
        for row in rows
        for field, value in row["values"].items()
    }
    expected = {
        (key[0], key[1], key[2], all_values[key], value)
        for key, value in required.items()
        if key in all_values and not equal(all_values[key], value)
    }
    proposed = {
        (edit["table"], edit["record_id"], edit["field"], edit["old_value"], edit["new_value"])
        for edit in patch.edits
    } if patch.valid else set()
    expected_targets = {(item[0], item[1], item[2]) for item in expected}
    proposed_targets = {(item[0], item[1], item[2]) for item in proposed}
    protected = set(all_values) - expected_targets
    changed_protected: set[tuple[str, str, str]] = set()
    if patch.valid and patch.isolated_ledger is not None:
        after = {
            (table, row["record_id"], field): value
            for table, rows in patch.isolated_ledger.items()
            for row in rows
            for field, value in row["values"].items()
        }
        changed_protected = {key for key in protected if not equal(all_values[key], after[key])}
    if patch.valid:
        preservation: dict[str, Any]
        if protected:
            preservation = rational(len(protected - changed_protected), len(protected))
        else:
            preservation = {"status": "not_applicable", "reason": "empty_preservation_denominator"}
        metrics = {
            "correct_target_count": len(proposed_targets & expected_targets),
            "correct_replacement_count": len(proposed & expected),
            "missed_corrections": len(expected - proposed),
            "unauthorized_edits": len(proposed - expected),
            "scope_violations": len({item[:3] for item in proposed} - eligible),
            "collateral_changes": len(changed_protected),
            "preservation_accuracy": preservation,
        }
    else:
        metrics = {
            name: {"status": "not_applicable", "reason": "structural_invalidity"}
            for name in ("correct_target_count", "correct_replacement_count", "missed_corrections", "unauthorized_edits", "scope_violations", "collateral_changes", "preservation_accuracy")
        }
    aggregate_contribution = {
        "exact_edit_set_valid": bool(patch.valid and proposed == expected),
        "structural_failure": not patch.valid,
        "preservation_numerator": len(protected - changed_protected) if patch.valid and protected else None,
        "preservation_denominator": len(protected) if patch.valid and protected else None,
    }
    operation_diagnostics = [
        f"edit_{index}:isolation_{'valid' if valid else 'invalid'}"
        + (":" + ",".join(errors) if errors else "")
        for index, valid, errors in patch.operation_diagnostics
    ]
    return {
        "metrics": metrics,
        "diagnostics": list(patch.errors) + operation_diagnostics,
        "resulting_ledger": patch.isolated_ledger if patch.valid else None,
        "contract_valid": bool(patch.valid),
        "exact_edit_set_valid": bool(patch.valid and proposed == expected),
        "aggregate_contribution": aggregate_contribution,
    }
