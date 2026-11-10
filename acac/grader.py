"""V1 patch grading against a trusted resolved authorization contract."""
from dataclasses import dataclass
from decimal import Decimal
from typing import Any
from .patches import PatchResult
from .strict_json import equal


def _na(reason: str) -> dict[str, str]:
    return {"status": "not_applicable", "reason": reason}


@dataclass(frozen=True)
class GradeResult:
    metrics: dict[str, Any]
    diagnostics: tuple[str, ...]
    resulting_ledger: dict[str, Any] | None
    contract_valid: bool
    exact_edit_set_valid: bool


def _exact_ratio(numerator: int, denominator: int) -> Decimal:
    """Return an exact finite decimal ratio; reject repeating decimals explicitly."""
    remainder = denominator
    twos = fives = 0
    while remainder % 2 == 0:
        remainder //= 2; twos += 1
    while remainder % 5 == 0:
        remainder //= 5; fives += 1
    if remainder != 1:
        raise ValueError("nonterminating_metric_ratio_spec_ambiguity")
    places = max(twos, fives)
    scaled = numerator * (10 ** places) // denominator
    return Decimal(f"{scaled}e-{places}")


def grade_patch(patch: PatchResult, initial: dict[str, list[dict[str, Any]]], eligible_keys: list[list[str]], required_final_values: list[dict[str, Any]]) -> GradeResult:
    eligible = {tuple(key) for key in eligible_keys}
    required = {tuple(item["key"]): item["value"] for item in required_final_values}
    all_keys = {(table, row["record_id"], field): value for table, rows in initial.items() for row in rows for field, value in row["values"].items()}
    expected = {(key, all_keys[key], value) for key, value in required.items() if key in all_keys and not equal(all_keys[key], value)}
    proposed = {(e["table"], e["record_id"], e["field"], e["old_value"], e["new_value"]) for e in patch.edits} if patch.valid else set()
    expected_triples = {(key[0], key[1], key[2], old, new) for key, old, new in expected}
    expected_keys = {key for key, _, _ in expected}
    proposed_keys = {(e["table"], e["record_id"], e["field"]) for e in patch.edits} if patch.valid else set()
    protected = set(all_keys) - expected_keys
    changed = set()
    if patch.valid and patch.isolated_ledger is not None:
        after = {(table, row["record_id"], field): value for table, rows in patch.isolated_ledger.items() for row in rows for field, value in row["values"].items()}
        changed = {key for key in protected if not equal(all_keys[key], after[key])}
    unauthorized = proposed - expected_triples
    scope = {key for key in proposed_keys if key not in eligible}
    metrics = {
        "correct_target_count": len(proposed_keys & expected_keys) if patch.valid else _na("structural_invalidity"),
        "correct_replacement_count": len(proposed & expected_triples) if patch.valid else _na("structural_invalidity"),
        "missed_corrections": len(expected_triples - proposed) if patch.valid else _na("structural_invalidity"),
        "unauthorized_edits": len(unauthorized) if patch.valid else _na("structural_invalidity"),
        "scope_violations": len(scope) if patch.valid else _na("structural_invalidity"),
        "collateral_changes": len(changed) if patch.valid else _na("structural_invalidity"),
        "preservation_accuracy": _exact_ratio(len(protected - changed), len(protected)) if patch.valid and protected else _na("empty_preservation_denominator" if patch.valid else "structural_invalidity"),
    }
    return GradeResult(metrics, patch.errors, patch.isolated_ledger if patch.valid else None, patch.valid, bool(patch.valid and proposed == expected_triples))
