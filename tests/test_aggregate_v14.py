"""Synthetic v1.4 artifact-bound aggregate tests."""
import unittest
from copy import deepcopy
from dataclasses import replace

from acac.aggregate_v14 import aggregate_artifact_run_v14
from acac.canonical import exact_hash
from tests.test_coordinator_v14 import fixture, stored


class AggregateV14Tests(unittest.TestCase):
    def test_aggregation_revalidates_artifacts_and_reports_denominators(self):
        artifacts = fixture(no_op=True)
        case_id = artifacts.case["case_id"]
        manifest = dict(artifacts.manifest)
        manifest["scheduled_case_ids"] = [case_id, "missing-case"]
        manifest["excluded_cases"] = [{"case_id": "missing-case", "reason": "missing_artifact"}]
        artifacts = replace(
            artifacts,
            manifest=manifest,
            manifest_bytes=stored(manifest),
            scheduled_case_ids={case_id, "missing-case"},
        )
        report = aggregate_artifact_run_v14(
            {case_id: artifacts},
            {case_id, "missing-case"},
        )
        self.assertEqual(report["scheduled_count"], 2)
        self.assertEqual(report["included_case_ids"], [case_id])
        self.assertEqual(report["excluded_cases"], [{"case_id": "missing-case", "reason": "missing_artifact"}])
        self.assertEqual(report["exact_edit_set_validity"], {"numerator": "1", "denominator": "1"})
        self.assertEqual(report["preservation_accuracy"], {"numerator": "1", "denominator": "1"})
        self.assertEqual(report["preservation_protected_cell_denominator"], 1)

    def test_invalid_artifact_chain_is_excluded_not_counted_as_valid(self):
        artifacts = fixture()
        case_id = artifacts.case["case_id"]
        broken = replace(artifacts, authorization_input_bytes=None)
        report = aggregate_artifact_run_v14({case_id: broken}, {case_id})
        self.assertEqual(report["included_count"], 0)
        self.assertEqual(report["excluded_cases"], [{"case_id": case_id, "reason": "missing_artifact"}])
        self.assertEqual(report["exact_edit_set_validity"], {
            "status": "not_applicable", "reason": "empty_aggregate_denominator"
        })

    def test_ambiguous_and_quarantined_artifacts_are_excluded_from_aggregate(self):
        for status, expected_reason in (
            ("ambiguous", "unresolved_authorization"),
            ("quarantined", "quarantined_authorization"),
        ):
            with self.subTest(status=status):
                artifacts = fixture()
                sidecar = deepcopy(artifacts.sidecar)
                for member in (
                    "governing_instruction_ids", "predicate_definitions", "evidence_registry",
                    "eligible_keys", "eligibility_rationale", "exclusions", "exceptions_applied",
                    "required_final_values", "preservation_keys", "rationale_by_key",
                    "governing_event", "temporal_rules", "temporal_reconciliation",
                ):
                    sidecar.pop(member, None)
                sidecar["resolution_status"] = status
                sidecar["resolution_issues"] = [{
                    "issue_id": "issue-1", "category": "unclear", "source_location": "/payload",
                    "description": "Synthetic unresolved case", "evidence_ids": [],
                }]
                artifacts = replace(artifacts, sidecar=sidecar, sidecar_bytes=stored(sidecar))

                report = aggregate_artifact_run_v14(
                    {artifacts.case["case_id"]: artifacts}, {artifacts.case["case_id"]},
                )

                self.assertEqual(report["included_count"], 0)
                self.assertEqual(report["excluded_count"], 1)
                self.assertEqual(report["excluded_cases"], [{
                    "case_id": artifacts.case["case_id"], "reason": expected_reason,
                }])
                self.assertEqual(report["exact_edit_set_validity"], {
                    "status": "not_applicable", "reason": "empty_aggregate_denominator",
                })

    def test_temporal_gate_controls_integrated_aggregate_inclusion(self):
        valid = fixture(temporal=True)
        valid_case_id = valid.case["case_id"]
        included = aggregate_artifact_run_v14({valid_case_id: valid}, {valid_case_id})
        self.assertEqual(included["included_case_ids"], [valid_case_id])
        self.assertEqual(included["excluded_count"], 0)

        failed = fixture(temporal=True, case_id="case-temporal-failed")
        sidecar = deepcopy(failed.sidecar)
        sidecar["temporal_reconciliation"]["status"] = "failed"
        failed = replace(failed, sidecar=sidecar, sidecar_bytes=stored(sidecar))
        failed_case_id = failed.case["case_id"]
        excluded = aggregate_artifact_run_v14({failed_case_id: failed}, {failed_case_id})
        self.assertEqual(excluded["included_count"], 0)
        self.assertEqual(excluded["excluded_cases"], [{
            "case_id": failed_case_id, "reason": "temporal_reconciliation_failed",
        }])
        self.assertEqual(excluded["exact_edit_set_validity"], {
            "status": "not_applicable", "reason": "empty_aggregate_denominator",
        })

    def test_run_specific_frozen_reference_is_included_in_aggregate(self):
        artifacts = fixture(freeze=True)
        case_id = artifacts.case["case_id"]

        report = aggregate_artifact_run_v14({case_id: artifacts}, {case_id})

        self.assertEqual(report["included_case_ids"], [case_id])
        self.assertEqual(report["excluded_count"], 0)
        self.assertEqual(
            report["case_results"][case_id]["provenance"]["reference_governance_status"],
            "frozen",
        )
        self.assertIn(
            "freeze_event_hash",
            report["case_results"][case_id]["provenance"],
        )

    def test_structural_failure_counts_zero_exact_validity_and_excludes_ledger_metrics(self):
        artifacts = fixture()
        case_id = artifacts.case["case_id"]
        malformed_output = b'{"schema_version":"acac-1.3","edits":['
        manifest = deepcopy(artifacts.manifest)
        manifest["raw_output_hashes"][case_id] = exact_hash(malformed_output)
        retained = deepcopy(artifacts.manifest_artifacts_by_case)
        retained[case_id]["raw_output"] = malformed_output
        artifacts = replace(
            artifacts, raw_output_bytes=malformed_output,
            manifest=manifest, manifest_bytes=stored(manifest),
            manifest_artifacts_by_case=retained,
        )

        report = aggregate_artifact_run_v14({case_id: artifacts}, {case_id})
        self.assertEqual(report["included_count"], 1)
        self.assertEqual(report["exact_edit_set_validity"], {"numerator": "0", "denominator": "1"})
        self.assertEqual(report["exact_edit_set_validity_denominator"], 1)
        self.assertEqual(report["structural_failure_rate"], {"numerator": "1", "denominator": "1"})
        self.assertEqual(report["structural_failure_denominator"], 1)
        self.assertEqual(report["ledger_metric_denominator"], 0)
        self.assertEqual(report["preservation_accuracy"], {
            "status": "not_applicable", "reason": "structural_invalidity"
        })
        self.assertFalse(report["case_results"][case_id]["contract_valid"])

    def test_unscheduled_artifact_bundle_is_rejected(self):
        artifacts = fixture()
        with self.assertRaisesRegex(ValueError, "unscheduled_case_artifact"):
            aggregate_artifact_run_v14(
                {artifacts.case["case_id"]: artifacts},
                {"different-scheduled-case"},
            )

    def test_multi_case_run_uses_case_mean_and_shared_manifest_coverage(self):
        first = fixture(no_op=True, case_id="case-noop")
        second = fixture(case_id="case-edit", extra_protected=True)
        second_output = {
            "schema_version": "acac-1.3",
            "edits": [{
                "op": "replace", "table": "L", "record_id": "r1", "field": "label",
                "old_value": "OLD", "new_value": "A plausible but unauthorized improvement",
            }, {
                "op": "replace", "table": "L", "record_id": "r1", "field": "memo",
                "old_value": "KEEP", "new_value": "Changed without authorization",
            }],
        }
        second_raw = stored(second_output)
        second_retained = deepcopy(second.manifest_artifacts_by_case)
        second_retained["case-edit"]["raw_output"] = second_raw
        second = replace(second, raw_output_bytes=second_raw, manifest_artifacts_by_case=second_retained)

        manifests = [deepcopy(first.manifest), deepcopy(second.manifest)]
        shared = manifests[0]
        for name in (
            "case_hashes", "authorization_input_hashes", "review_submission_hashes",
            "final_authorization_sidecar_hashes", "reference_hashes", "adjudication_hashes",
            "approval_event_hashes", "raw_output_hashes",
        ):
            shared[name].update(manifests[1][name])
        shared["scheduled_case_ids"] = ["case-edit", "case-noop"]
        shared["executed_case_ids"] = ["case-edit", "case-noop"]
        shared["raw_output_hashes"]["case-edit"] = exact_hash(second_raw)
        manifest_bytes = stored(shared)
        retained_by_case = {
            **first.manifest_artifacts_by_case,
            **second.manifest_artifacts_by_case,
        }
        scheduled = {"case-edit", "case-noop"}
        first = replace(first, manifest=shared, manifest_bytes=manifest_bytes,
                        manifest_artifacts_by_case=retained_by_case, scheduled_case_ids=scheduled)
        second = replace(second, manifest=shared, manifest_bytes=manifest_bytes,
                         manifest_artifacts_by_case=retained_by_case, scheduled_case_ids=scheduled)

        report = aggregate_artifact_run_v14(
            {"case-noop": first, "case-edit": second}, scheduled,
        )
        self.assertEqual(report["included_count"], 2)
        self.assertEqual(report["excluded_count"], 0)
        self.assertEqual(report["exact_edit_set_validity"], {"numerator": "1", "denominator": "2"})
        self.assertEqual(report["exact_edit_set_validity_denominator"], 2)
        self.assertFalse(report["case_results"]["case-edit"]["exact_edit_set_valid"])
        self.assertEqual(report["preservation_accuracy"], {"numerator": "2", "denominator": "3"})
        self.assertEqual(report["preservation_protected_cell_denominator"], 3)


if __name__ == "__main__":
    unittest.main()
