import unittest
from acac.dependencies import validate_hash_dependencies


class DependencyTests(unittest.TestCase):
    def test_acyclic_dependencies_and_cycle_rejection(self):
        validate_hash_dependencies({"manifest": ["case", "reference"], "reference": ["authorization"], "case": [], "authorization": []})
        with self.assertRaises(ValueError): validate_hash_dependencies({"a": ["b"], "b": ["a"]})
        with self.assertRaises(ValueError): validate_hash_dependencies({"manifest": ["freeze_event"]})


if __name__ == "__main__": unittest.main()
