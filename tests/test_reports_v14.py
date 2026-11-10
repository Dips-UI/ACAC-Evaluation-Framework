"""Synthetic tests for v1.4 public reports."""

from copy import deepcopy
from dataclasses import replace
import json
import unittest

from acac.aggregate_v14 import aggregate_artifact_run_v14
from acac.canonical import exact_hash
from acac.reports_v14 import (
    ReportV14Error,
    aggregate_report_v14,
    case_report_v14,
    edit_decisions_v14,
    render_case_markdown_v14,
)
from tests.test_coordinator_v14 import fixture, stored


class ReportsV14Tests(unittest.TestCase):
    def test_case_report_revalidates_chain_and_discloses_governance_bindings(self):
        artifacts = fixture(no_op=True)
        report = case_report_v14(artifacts)

        self.assertEqual(report["schema_version"], "acac-report-1.4")
        self.assertEqual(report["reference_governance_status"], "approved_unfrozen")
        self.assertEqual(
            report["reference_content_hash"],
            artifacts.manifest["reference_hashes"][artifacts.case["case_id"]],
        )
        self.assertIsNone(report["freeze_event_hash"])
        self.assertEqual(report["freeze_binding"], "not_frozen")
        governance = report["human_review_governance"]
        self.assertEqual(governance["human_review_count"], 1)
        self.assertTrue(governance["adjudication_present"])
        self.assertIn("do not establish independent validation", governance["interpretation"])

    def test_markdown_report_keeps_exact_metric_representation(self):
        report = case_report_v14(fixture(no_op=True))
        markdown = render_case_markdown_v14(report)
        self.assertIn("Reference governance", markdown)
        self.assertIn("approved_unfrozen", markdown)
        self.assertIn('"numerator": "1"', markdown)
        self.assertNotIn("run-locked", markdown)

    def test_ineligible_chain_cannot_be_reported(self):
        artifacts = fixture()
        broken = replace(artifacts, authorization_input_bytes=None)
        with self.assertRaisesRegex(ReportV14Error, "grading_chain_ineligible:missing_artifact"):
            case_report_v14(broken)

    def test_per_edit_report_exposes_resolved_reason_rule_and_bound_evidence(self):
        artifacts = fixture()
        result = edit_decisions_v14(artifacts)
        self.assertEqual(result["status"], "evaluated")
        self.assertEqual(len(result["edits"]), 1)
        edit = result["edits"][0]
        self.assertEqual(edit["target"], ["L", "r1", "label"])
        self.assertEqual(edit["authorization_decision"], "matches_resolved_required_edit")
        self.assertIn("p1", edit["applicable_rules"]["predicate_ids"])
        self.assertEqual(edit["reason"], artifacts.authorization_input["rationale_by_key"][0]["reason"])
        self.assertIn("authorization_input", edit["supporting_evidence"]["artifact_hashes"])
        self.assertFalse(edit["supporting_evidence"]["direct_key_to_evidence_mapping_available"])
        self.assertEqual(edit["supporting_evidence"]["direct_evidence_ids"], [])

    def test_per_edit_report_flags_a_protected_target_without_changing_metrics(self):
        artifacts = fixture(extra_protected=True)
        patch = json.loads(artifacts.raw_output_bytes)
        patch["edits"].append({
            "op": "replace", "table": "L", "record_id": "r1", "field": "memo",
            "old_value": "KEEP", "new_value": "IMPROVED",
        })
        raw = stored(patch)
        manifest = dict(artifacts.manifest)
        manifest["raw_output_hashes"] = {
            artifacts.case["case_id"]: exact_hash(raw),
        }
        retained = deepcopy(artifacts.manifest_artifacts_by_case)
        retained[artifacts.case["case_id"]]["raw_output"] = raw
        artifacts = replace(
            artifacts, raw_output_bytes=raw, manifest=manifest,
            manifest_bytes=stored(manifest), manifest_artifacts_by_case=retained,
        )
        report = edit_decisions_v14(artifacts)
        extra = report["edits"][1]
        self.assertEqual(extra["target"], ["L", "r1", "memo"])
        self.assertEqual(extra["authorization_decision"], "violates_preservation_requirement")
        self.assertIn("preservation", extra["reason"])

    def test_structural_patch_failure_is_not_given_an_authorization_decision(self):
        artifacts = fixture()
        malformed = b'{"schema_version":"acac-1.3","edits":['
        manifest = dict(artifacts.manifest)
        manifest["raw_output_hashes"] = {artifacts.case["case_id"]: exact_hash(malformed)}
        retained = deepcopy(artifacts.manifest_artifacts_by_case)
        retained[artifacts.case["case_id"]]["raw_output"] = malformed
        artifacts = replace(
            artifacts, raw_output_bytes=malformed, manifest=manifest,
            manifest_bytes=stored(manifest), manifest_artifacts_by_case=retained,
        )
        report = edit_decisions_v14(artifacts)
        self.assertEqual(report["status"], "structural_failure")
        self.assertEqual(report["edits"], [])

    def test_aggregate_report_is_json_detached_and_requires_v14(self):
        artifacts = fixture(no_op=True)
        case_id = artifacts.case["case_id"]
        aggregate = aggregate_artifact_run_v14({case_id: artifacts}, {case_id})
        report = aggregate_report_v14(aggregate)
        self.assertEqual(report["included_count"], 1)
        self.assertEqual(report["exact_edit_set_validity_denominator"], 1)
        report["included_count"] = 0
        self.assertEqual(aggregate["included_count"], 1)
        with self.assertRaisesRegex(ReportV14Error, "v1_4_aggregate_required"):
            aggregate_report_v14({"schema_version": "acac-1.3"})


if __name__ == "__main__":
    unittest.main()
