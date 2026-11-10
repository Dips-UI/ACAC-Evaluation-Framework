import unittest
from acac.strict_json import JSONContractError, loads, loads_legacy


class LegacyBoundaryTests(unittest.TestCase):
    def test_v1_and_legacy_null_policies_are_explicitly_separate(self):
        with self.assertRaises(JSONContractError): loads('{"diagnostic":null}')
        self.assertIsNone(loads_legacy('{"diagnostic":null}')['diagnostic'])


if __name__ == "__main__": unittest.main()
