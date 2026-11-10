import unittest
from pathlib import Path
from acac.audit import implementation_surface


class AuditTests(unittest.TestCase):
    def test_v1_module_surface(self):
        result = implementation_surface(Path(__file__).parents[1])
        self.assertTrue(result["all_present"])


if __name__ == "__main__": unittest.main()
