import unittest
from acac.consistency import check_versions


class ConsistencyTests(unittest.TestCase):
    def test_v1_versions(self):
        check_versions(case_schema="acac-1.3", manifest="1.3", grader="acac-grader-1.3", auth_non_temporal="acac-auth-1.0", auth_temporal="acac-auth-1.1")
        with self.assertRaises(ValueError): check_versions(case_schema="acac-1.0", manifest="1.3", grader="acac-grader-1.3", auth_non_temporal="acac-auth-1.0", auth_temporal="acac-auth-1.1")


if __name__ == "__main__": unittest.main()
