"""Synthetic tests for exact v1.4 metric arithmetic."""

import unittest

from acac.metrics_v14 import (
    RationalMetricError,
    add,
    display_six_half_even,
    divide,
    grade_patch_v14,
    rational,
    validate_rational,
)
from acac.canonical import semantic_hash
from acac.patches import PatchResult


class RationalMetricTests(unittest.TestCase):
    def test_rational_is_reduced_and_arbitrary_precision(self):
        self.assertEqual(rational(6, 9), {"numerator": "2", "denominator": "3"})
        huge = 10**100 + 1
        self.assertEqual(validate_rational(rational(huge, 3)).numerator, huge)

    def test_rational_tokens_exceed_python_default_decimal_conversion_limit(self):
        token = "1" + ("0" * 5000)
        parsed = validate_rational({"numerator": token, "denominator": "3"})
        self.assertEqual(parsed.denominator, 3)
        self.assertEqual(len(rational(parsed.numerator, parsed.denominator)["numerator"]), 5001)

    def test_rational_rejects_noncanonical_or_unreduced(self):
        for value in (
            {"numerator": "02", "denominator": "3"},
            {"numerator": "2", "denominator": "6"},
            {"numerator": "0", "denominator": "2"},
            {"numerator": "1", "denominator": "0"},
        ):
            with self.subTest(value=value), self.assertRaises(RationalMetricError):
                validate_rational(value)

    def test_add_and_divide_are_exact(self):
        total = add(rational(1, 3), rational(1, 6))
        self.assertEqual(total, {"numerator": "1", "denominator": "2"})
        self.assertEqual(divide(total, 3), {"numerator": "1", "denominator": "6"})

    def test_display_uses_half_even_and_is_separate_from_stored_rational(self):
        self.assertEqual(display_six_half_even(rational(1, 2_000_000)), "0.000000")
        self.assertEqual(display_six_half_even(rational(3, 2_000_000)), "0.000002")
        self.assertEqual(rational(1, 2_000_000), {"numerator": "1", "denominator": "2000000"})

    def test_display_rounding_does_not_mutate_hashed_or_calculated_rational(self):
        metric = rational(1, 3)
        digest_before = semantic_hash(metric)

        self.assertEqual(display_six_half_even(metric), "0.333333")
        self.assertEqual(semantic_hash(metric), digest_before)
        self.assertEqual(add(metric, metric), rational(2, 3))
        self.assertEqual(
            display_six_half_even(rational(1_999_999, 2_000_000)),
            "1.000000",
        )

    def test_patch_metrics_store_repeating_preservation_ratio_exactly(self):
        ledger = {"L": [
            {"record_id": "r1", "values": {"label": "old", "keep": "a"}},
            {"record_id": "r2", "values": {"label": "stay", "keep": "b"}},
            {"record_id": "r3", "values": {"label": "stay", "keep": "c"}},
        ]}
        edit = {"op": "replace", "table": "L", "record_id": "r1", "field": "label", "old_value": "old", "new_value": "new"}
        after = {"L": [
            {"record_id": "r1", "values": {"label": "new", "keep": "a"}},
            {"record_id": "r2", "values": {"label": "changed", "keep": "b"}},
            {"record_id": "r3", "values": {"label": "stay", "keep": "c"}},
        ]}
        patch = PatchResult(True, (edit,), (), after)
        result = grade_patch_v14(
            patch, ledger, [["L", "r1", "label"]],
            [{"key": ["L", "r1", "label"], "value": "new"}],
        )
        self.assertEqual(result["metrics"]["preservation_accuracy"], {"numerator": "4", "denominator": "5"})
        self.assertEqual(result["metrics"]["collateral_changes"], 1)
        self.assertTrue(result["exact_edit_set_valid"])

    def test_structural_failure_has_tagged_na_metrics_and_no_ledger(self):
        patch = PatchResult(False, (), ("invalid_patch",), None)
        result = grade_patch_v14(patch, {"L": []}, [], [])
        self.assertFalse(result["contract_valid"])
        self.assertIsNone(result["resulting_ledger"])
        self.assertEqual(result["metrics"]["preservation_accuracy"], {
            "status": "not_applicable", "reason": "structural_invalidity"
        })


if __name__ == "__main__":
    unittest.main()
