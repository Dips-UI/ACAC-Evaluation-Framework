import unittest
from types import SimpleNamespace
from acac.reports_v1 import aggregate_report, case_report


class ReportsTests(unittest.TestCase):
    def test_case_and_aggregate_reports(self):
        grade = SimpleNamespace(metrics={}, diagnostics=(), contract_valid=True, exact_edit_set_valid=True)
        governance = SimpleNamespace(status="approved_unfrozen", eligible=True)
        report = case_report("c1", grade, governance)
        self.assertEqual(aggregate_report([report])["aggregate_exact_validity"], 1.0)


if __name__ == "__main__": unittest.main()
