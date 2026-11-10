import unittest
from acac.aggregate import aggregate_cases


class AggregateTests(unittest.TestCase):
    def test_aggregate_requires_resolved_hash_valid_governance(self):
        result = aggregate_cases([{"case_id": "c1", "resolution_status": "resolved", "hash_valid": True, "governance_status": "approved_unfrozen"}, {"case_id": "c2", "resolution_status": "ambiguous", "hash_valid": True, "governance_status": "approved_unfrozen"}])
        self.assertEqual(result["included_case_ids"], ["c1"])
        self.assertEqual(result["excluded_cases"][0]["reason"], "not_eligible")

    def test_aggregate_uses_public_governance_labels(self):
        result = aggregate_cases([
            {"case_id": "c1", "resolution_status": "resolved", "hash_valid": True, "governance_status": "approved_unfrozen"},
            {"case_id": "c2", "resolution_status": "resolved", "hash_valid": True, "governance_status": "frozen"},
            {"case_id": "c3", "resolution_status": "resolved", "hash_valid": True, "governance_status": "approved"},
        ])
        self.assertEqual(result["included_case_ids"], ["c1", "c2"])
        self.assertEqual(result["excluded_cases"][0]["case_id"], "c3")

    def test_ambiguous_and_quarantined_cases_are_both_excluded(self):
        result = aggregate_cases([
            {"case_id": "ambiguous", "resolution_status": "ambiguous", "hash_valid": True, "governance_status": "approved_unfrozen"},
            {"case_id": "quarantined", "resolution_status": "quarantined", "hash_valid": True, "governance_status": "frozen"},
        ])
        self.assertEqual(result["included_case_ids"], [])
        self.assertEqual({item["case_id"] for item in result["excluded_cases"]}, {"ambiguous", "quarantined"})

    def test_temporal_gate_controls_temporal_case_denominator(self):
        result = aggregate_cases([
            {"case_id": "temporal-ok", "resolution_status": "resolved", "hash_valid": True, "governance_status": "approved_unfrozen", "temporal_required": True, "temporal_gate": True},
            {"case_id": "temporal-failed", "resolution_status": "resolved", "hash_valid": True, "governance_status": "frozen", "temporal_required": True, "temporal_gate": False},
            {"case_id": "non-temporal", "resolution_status": "resolved", "hash_valid": True, "governance_status": "approved_unfrozen", "temporal_required": False},
        ])
        self.assertEqual(result["included_case_ids"], ["temporal-ok", "non-temporal"])
        self.assertEqual(result["excluded_cases"], [{"case_id": "temporal-failed", "reason": "temporal_gate_failed"}])


if __name__ == "__main__": unittest.main()
