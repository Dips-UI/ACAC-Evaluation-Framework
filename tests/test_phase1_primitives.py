"""Synthetic Phase 1 tests; no benchmark or protected artifacts are read."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from acac.strict_json import (
    INT64_MAX,
    INT64_MIN,
    JSONContractError,
    compare_timestamps,
    hash_file,
    loads,
    loads_bytes,
    matches_type,
    parse_rfc3339_timestamp,
    read_exact_bytes,
    sha256_bytes,
    validate_integer_token,
)


class Phase1PrimitiveTests(unittest.TestCase):
    def test_strict_json_bytes_and_structure(self):
        self.assertEqual(loads_bytes(b'{"x": 1}')["x"].token, "1")
        for raw in (b'{"x": 1, "x": 2}', b'{"x": 1} trailing', b'{"x": null}', b"NaN"):
            with self.assertRaises(JSONContractError):
                loads_bytes(raw)
        with self.assertRaisesRegex(JSONContractError, "invalid_utf8"):
            loads_bytes(b"\xff")

    def test_strings_are_exact(self):
        self.assertTrue(matches_type(" x ", "string"))
        self.assertNotEqual("é", "e\u0301")
        self.assertNotEqual(loads('"é"'), loads('"e\\u0301"'))

    def test_scalar_types_and_integer_tokens(self):
        self.assertTrue(matches_type(True, "boolean"))
        self.assertFalse(matches_type(True, "integer"))
        self.assertFalse(matches_type({}, "string"))
        self.assertEqual(validate_integer_token("0"), 0)
        self.assertEqual(validate_integer_token(str(INT64_MIN)), INT64_MIN)
        self.assertEqual(validate_integer_token(str(INT64_MAX)), INT64_MAX)
        for token in ("-0", "+2", "02", "2.0", "2e0", str(INT64_MAX + 1), str(INT64_MIN - 1)):
            with self.assertRaises(JSONContractError):
                validate_integer_token(token)
        self.assertFalse(matches_type(loads("2.0"), "integer"))

    def test_rfc3339_preserves_spelling_and_compares_utc(self):
        parsed = parse_rfc3339_timestamp("2026-02-03T01:00:00+01:00")
        self.assertEqual(parsed.original, "2026-02-03T01:00:00+01:00")
        self.assertEqual(compare_timestamps(parsed, "2026-02-03T00:00:00Z"), 0)
        parse_rfc3339_timestamp("2026-02-03T00:00:00Z")
        for value in ("2026-02-03T00:00:00", "2026-02-03T00:00:60Z"):
            with self.assertRaises(JSONContractError):
                parse_rfc3339_timestamp(value)

    def test_rfc3339_preserves_submicrosecond_ordering(self):
        first = parse_rfc3339_timestamp("2026-02-03T00:00:00.0000001Z")
        second = parse_rfc3339_timestamp("2026-02-03T00:00:00.0000002Z")
        self.assertEqual(first.original, "2026-02-03T00:00:00.0000001Z")
        self.assertLess(compare_timestamps(first, second), 0)
        self.assertGreater(compare_timestamps(second, first), 0)

    def test_rfc3339_fraction_precision_and_offsets(self):
        short = parse_rfc3339_timestamp("2026-02-03T00:00:00.1Z")
        long = parse_rfc3339_timestamp("2026-02-03T00:00:00.1000000001Z")
        self.assertLess(compare_timestamps(long, "2026-02-03T00:00:00.1000000002Z"), 0)
        self.assertEqual(compare_timestamps(
            "2026-02-03T01:00:00.1000000001+01:00",
            "2026-02-03T00:00:00.1000000001Z",
        ), 0)
        self.assertLess(compare_timestamps(short, long), 0)

    def test_rfc3339_precision_exceeds_default_decimal_context(self):
        first = "2026-02-03T00:00:00." + ("1" * 60) + "1Z"
        second = "2026-02-03T00:00:00." + ("1" * 60) + "2Z"
        self.assertLess(compare_timestamps(first, second), 0)
        self.assertGreater(compare_timestamps(second, first), 0)

    def test_rfc3339_ordering_crosses_second_boundary(self):
        self.assertLess(compare_timestamps(
            "2026-02-03T00:00:00.9999999999Z",
            "2026-02-03T00:00:01Z",
        ), 0)
        self.assertGreater(compare_timestamps(
            "2026-02-03T00:00:01Z",
            "2026-02-03T00:00:00.9999999999Z",
        ), 0)

    def test_rfc3339_comparator_results_for_threshold_values(self):
        event = "2026-02-03T00:00:00.0000002Z"
        threshold = "2026-02-03T00:00:00.0000001Z"
        # The comparator says event is after the threshold. Applying inclusive
        # or exclusive policy is the responsibility of a later temporal layer.
        self.assertGreater(compare_timestamps(event, threshold), 0)
        equal = "2026-02-03T00:00:00.0000001Z"
        self.assertEqual(compare_timestamps(equal, threshold), 0)

    def test_exact_bytes_and_hashes(self):
        variants = [
            b'{"x":1,"y":2}\n',
            b'{"x":1,"y":2}\r\n',
            b'{"x": 1,"y":2}\n',
            b'{"y":2,"x":1}\n',
            b'{"x":1.0,"y":2}\n',
        ]
        self.assertEqual(sha256_bytes(variants[0]), hashlib.sha256(variants[0]).hexdigest())
        self.assertEqual(len({sha256_bytes(item) for item in variants}), len(variants))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            path.write_bytes(variants[0])
            self.assertEqual(read_exact_bytes(path), variants[0])
            self.assertEqual(hash_file(path), sha256_bytes(variants[0]))


if __name__ == "__main__":
    unittest.main()
