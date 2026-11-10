"""Synthetic end-to-end tests for the offline v1.4 evaluation CLI."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from acac.strict_json import loads_bytes
from acac.canonical import exact_hash
from acac.evaluation_cli_v14 import _render_html
from tests.test_coordinator_v14 import fixture, stored


REPOSITORY = Path(__file__).resolve().parents[1]
DEMO_BUNDLE = REPOSITORY / "examples" / "synthetic_v14_bundle"


def _write_single_bundle(root: Path, artifacts) -> tuple[Path, Path]:
    case_id = artifacts.case["case_id"]
    directory = root / "cases" / case_id
    (directory / "reviews").mkdir(parents=True)
    (directory / "lifecycle").mkdir()
    filenames = {
        "case.json": artifacts.case_bytes,
        "authorization_input.json": artifacts.authorization_input_bytes,
        "final_authorization_sidecar.json": artifacts.sidecar_bytes,
        "reference.json": artifacts.reference_bytes,
        "adjudication.json": artifacts.adjudication_bytes,
        "raw_output.json": artifacts.raw_output_bytes,
    }
    for name, raw in filenames.items():
        (directory / name).write_bytes(raw)
    review_paths = []
    for index, (_, (_, raw)) in enumerate(artifacts.reviews_by_hash.items(), 1):
        name = f"review-{index}.json"
        (directory / "reviews" / name).write_bytes(raw)
        review_paths.append(f"cases/{case_id}/reviews/{name}")
    lifecycle_paths = []
    for index, raw in enumerate(artifacts.lifecycle_event_bytes, 1):
        name = f"event-{index}.json"
        (directory / "lifecycle" / name).write_bytes(raw)
        lifecycle_paths.append(f"cases/{case_id}/lifecycle/{name}")
    manifest_path = root / "manifest.json"
    manifest_path.write_bytes(artifacts.manifest_bytes)
    entry = {
        "case": f"cases/{case_id}/case.json",
        "authorization_input": f"cases/{case_id}/authorization_input.json",
        "review_submissions": review_paths,
        "final_authorization_sidecar": f"cases/{case_id}/final_authorization_sidecar.json",
        "reference": f"cases/{case_id}/reference.json",
        "adjudication": f"cases/{case_id}/adjudication.json",
        "lifecycle_events": lifecycle_paths,
        "raw_output": f"cases/{case_id}/raw_output.json",
    }
    (root / "bundle.json").write_text(json.dumps({
        "schema_version": "acac-evaluation-bundle-1.0",
        "manifest": "manifest.json",
        "cases": {case_id: entry},
    }, indent=2) + "\n", encoding="utf-8")
    controlled = root / "controlled"
    controlled.mkdir()
    config_path = root / "governance.json"
    config_path.write_text(json.dumps({
        "approver_id": "approver-1",
        "approver_role": "approver",
        "controlled_directory": str(controlled),
        "backup_policy": "synthetic test only",
    }), encoding="utf-8")
    return root, config_path


class EvaluationCliV14Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="acac-cli-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def _run(self, *arguments):
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [sys.executable, "-m", "acac", *map(str, arguments)],
            cwd=REPOSITORY, env=env, text=True, capture_output=True, check=False,
        )

    def _success_bundle(self):
        return _write_single_bundle(self.root / "bundle", fixture(case_id="cli-valid"))

    def test_help_lists_evaluate_and_demo_commands(self):
        help_result = self._run("--help")
        evaluate_help = self._run("evaluate", "--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("evaluate", help_result.stdout)
        self.assertIn("verify-bundle", help_result.stdout)
        self.assertIn("demo", help_result.stdout)
        self.assertEqual(evaluate_help.returncode, 0, evaluate_help.stderr)
        self.assertIn("--bundle", evaluate_help.stdout)
        self.assertIn("--config", evaluate_help.stdout)

    def test_valid_bundle_runs_coordinator_and_writes_three_reports(self):
        bundle, config = self._success_bundle()
        output = self.root / "output"
        result = self._run("evaluate", "--bundle", bundle, "--config", config, "--output-dir", output)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = loads_bytes(result.stdout.encode("utf-8"))
        self.assertEqual(summary["status"], "completed")
        report_path = Path(summary["json_report"])
        markdown_path = Path(summary["markdown_report"])
        html_path = Path(summary["html_report"])
        report = loads_bytes(report_path.read_bytes())
        self.assertEqual(report["aggregate"]["included_count"], 1)
        edit = report["edit_decisions_by_case"]["cli-valid"]["edits"][0]
        self.assertEqual(edit["authorization_decision"], "matches_resolved_required_edit")
        self.assertIn("Exact edit-set validity", markdown_path.read_text(encoding="utf-8"))
        html = html_path.read_text(encoding="utf-8")
        self.assertIn("Per-edit decisions", html)
        self.assertIn("matches_resolved_required_edit", html)
        self.assertIn("Artifact hash bindings", html)

    def test_missing_or_invalid_artifacts_fail_closed(self):
        bundle, config = self._success_bundle()
        (bundle / "cases" / "cli-valid" / "case.json").unlink()
        result = self._run("evaluate", "--bundle", bundle, "--config", config,
                           "--output-dir", self.root / "out")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(loads_bytes(result.stdout.encode())["status"], "failed")

    def test_malformed_artifact_fails_closed(self):
        bundle, config = self._success_bundle()
        (bundle / "cases" / "cli-valid" / "case.json").write_bytes(b'{"case_id":"x","case_id":"y"}')
        result = self._run("evaluate", "--bundle", bundle, "--config", config,
                           "--output-dir", self.root / "out")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(loads_bytes(result.stdout.encode())["status"], "failed")

    def test_hash_binding_mismatch_is_reported_ineligible_with_nonzero_exit(self):
        bundle, config = self._success_bundle()
        manifest_path = bundle / "manifest.json"
        manifest = loads_bytes(manifest_path.read_bytes())
        manifest["case_hashes"]["cli-valid"]["exact"] = "sha256:" + "0" * 64
        manifest_path.write_bytes(stored(manifest))
        output = self.root / "out"
        result = self._run("evaluate", "--bundle", bundle, "--config", config, "--output-dir", output)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        summary = loads_bytes(result.stdout.encode())
        self.assertEqual(summary["status"], "ineligible")
        report = loads_bytes(Path(summary["json_report"]).read_bytes())
        self.assertEqual(report["aggregate"]["included_count"], 0)
        self.assertTrue(report["aggregate"]["excluded_cases"])

    def test_verify_bundle_reports_exact_and_semantic_hash_bindings_without_writing(self):
        bundle, config = self._success_bundle()
        before = sorted(path.name for path in bundle.iterdir())
        result = self._run("verify-bundle", "--bundle", bundle, "--config", config)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = loads_bytes(result.stdout.encode("utf-8"))
        self.assertEqual(value["verification_status"], "verified")
        self.assertEqual(value["executed_count"], 1)
        case = value["cases"][0]
        self.assertEqual(case["status"], "verified")
        self.assertTrue(case["hash_bindings"]["case"]["matches"])
        self.assertTrue(case["hash_bindings"]["authorization_input"]["matches"])
        self.assertTrue(case["model_output_contract_valid"])
        self.assertEqual(sorted(path.name for path in bundle.iterdir()), before)

    def test_verify_bundle_identifies_manifest_hash_discrepancy(self):
        bundle, config = self._success_bundle()
        manifest_path = bundle / "manifest.json"
        manifest = loads_bytes(manifest_path.read_bytes())
        manifest["case_hashes"]["cli-valid"]["exact"] = "sha256:" + "0" * 64
        manifest_path.write_bytes(stored(manifest))
        result = self._run("verify-bundle", "--bundle", bundle, "--config", config)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        value = loads_bytes(result.stdout.encode("utf-8"))
        self.assertEqual(value["verification_status"], "failed")
        self.assertIn("case", value["cases"][0]["mismatched_bindings"])
        self.assertTrue(value["cases"][0]["coordinator_refusal_code"])

    def test_verify_bundle_separates_integrity_from_model_patch_validity(self):
        bundle, config = self._success_bundle()
        index = loads_bytes((bundle / "bundle.json").read_bytes())
        raw_path = bundle / index["cases"]["cli-valid"]["raw_output"]
        malformed = b'{"schema_version":"acac-1.3","edits":['
        raw_path.write_bytes(malformed)
        manifest_path = bundle / "manifest.json"
        manifest = loads_bytes(manifest_path.read_bytes())
        manifest["raw_output_hashes"]["cli-valid"] = exact_hash(malformed)
        manifest_path.write_bytes(stored(manifest))
        result = self._run("verify-bundle", "--bundle", bundle, "--config", config)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        value = loads_bytes(result.stdout.encode("utf-8"))
        self.assertEqual(value["verification_status"], "verified")
        self.assertFalse(value["cases"][0]["model_output_contract_valid"])

    def test_self_contained_html_escapes_report_values(self):
        report = {
            "run_id": "<img src=x onerror=alert(1)>",
            "status": "completed", "evidence_type": "synthetic",
            "aggregate": {
                "scheduled_count": 1, "included_count": 1, "excluded_count": 0,
                "structural_failure_count": 0, "excluded_cases": [],
                "case_results": {"case-1": {
                    "contract_valid": True, "exact_edit_set_valid": True,
                    "diagnostics": [], "provenance": {},
                }},
                "exact_edit_set_validity": {"numerator": "1", "denominator": "1"},
                "preservation_accuracy": {"numerator": "1", "denominator": "1"},
                "structural_failure_rate": {"numerator": "0", "denominator": "1"},
                "count_metrics": {},
            },
            "edit_decisions_by_case": {"case-1": {
                "status": "evaluated", "edits": [{
                    "target": ["W", "r1", "label"], "from": "OLD", "to": "<script>alert(1)</script>",
                    "authorization_decision": "outside_eligible_scope",
                    "reason": "<script>untrusted rationale</script>",
                    "applicable_rules": {}, "supporting_evidence": {"artifact_hashes": {}},
                }],
            }},
        }
        rendered = _render_html(report)
        self.assertIn("Content-Security-Policy", rendered)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", rendered)
        self.assertIn("&lt;script&gt;untrusted rationale&lt;/script&gt;", rendered)
        self.assertNotIn("<script>", rendered)

    def test_path_traversal_in_bundle_is_rejected(self):
        bundle, config = self._success_bundle()
        index_path = bundle / "bundle.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["cases"]["cli-valid"]["case"] = "../../outside.json"
        index_path.write_text(json.dumps(index), encoding="utf-8")
        result = self._run("evaluate", "--bundle", bundle, "--config", config,
                           "--output-dir", self.root / "out")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(loads_bytes(result.stdout.encode())["status"], "failed")

    def test_ineligible_and_unauthorized_examples_are_explicit_in_demo_report(self):
        first_output = self.root / "demo-one"
        result = self._run("demo", "--output-dir", first_output)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        summary = loads_bytes(result.stdout.encode())
        self.assertEqual(summary["status"], "ineligible")
        report = loads_bytes(Path(summary["json_report"]).read_bytes())
        aggregate = report["aggregate"]
        self.assertEqual(report["evidence_type"], "synthetic demonstration")
        self.assertIn("demo-authorized", aggregate["included_case_ids"])
        self.assertTrue(aggregate["case_results"]["demo-authorized"]["exact_edit_set_valid"])
        unauthorized = aggregate["case_results"]["demo-unauthorized"]
        self.assertFalse(unauthorized["exact_edit_set_valid"])
        self.assertGreater(unauthorized["metrics"]["unauthorized_edits"], 0)
        self.assertGreater(unauthorized["metrics"]["collateral_changes"], 0)
        preservation = unauthorized["metrics"]["preservation_accuracy"]
        self.assertNotEqual(preservation["numerator"], preservation["denominator"])
        self.assertTrue(any(item["case_id"] == "demo-refused" for item in aggregate["excluded_cases"]))
        markdown = Path(summary["markdown_report"]).read_text(encoding="utf-8")
        self.assertIn("not a model benchmark", markdown)

    def test_quarantined_authorization_is_excluded_from_aggregate(self):
        bundle = self.root / "quarantined-bundle"
        import shutil
        shutil.copytree(DEMO_BUNDLE, bundle)
        index = loads_bytes((bundle / "bundle.json").read_bytes())
        sidecar_path = bundle / index["cases"]["demo-refused"]["final_authorization_sidecar"]
        sidecar = loads_bytes(sidecar_path.read_bytes())
        sidecar["resolution_status"] = "quarantined"
        sidecar_raw = stored(sidecar)
        sidecar_path.write_bytes(sidecar_raw)
        manifest_path = bundle / "manifest.json"
        manifest = loads_bytes(manifest_path.read_bytes())
        manifest["final_authorization_sidecar_hashes"]["demo-refused"] = exact_hash(sidecar_raw)
        manifest_path.write_bytes(stored(manifest))
        controlled = self.root / "quarantine-controlled"
        controlled.mkdir()
        config = self.root / "quarantine-governance.json"
        config.write_text(json.dumps({
            "approver_id": "approver-1", "approver_role": "approver",
            "controlled_directory": str(controlled), "backup_policy": "synthetic test only",
        }), encoding="utf-8")
        result = self._run("evaluate", "--bundle", bundle,
                           "--config", config,
                           "--output-dir", self.root / "out")
        self.assertEqual(result.returncode, 2)
        summary = loads_bytes(result.stdout.encode())
        report = loads_bytes(Path(summary["json_report"]).read_bytes())
        self.assertEqual(report["aggregate"]["included_count"], 2)
        self.assertTrue(any(
            item["case_id"] == "demo-refused" and item["reason"] == "quarantined_authorization"
            for item in report["aggregate"]["excluded_cases"]
        ))

    def test_structural_failure_is_reported_and_returns_nonzero(self):
        artifacts = fixture(case_id="structural")
        malformed = b'{"schema_version":"acac-1.3","edits":['
        manifest = dict(artifacts.manifest)
        manifest["raw_output_hashes"] = {"structural": exact_hash(malformed)}
        retained = dict(artifacts.manifest_artifacts_by_case)
        retained["structural"] = dict(retained["structural"])
        retained["structural"]["raw_output"] = malformed
        artifacts = replace(
            artifacts, raw_output_bytes=malformed, manifest=manifest,
            manifest_bytes=stored(manifest), manifest_artifacts_by_case=retained,
        )
        bundle, _ = _write_single_bundle(self.root / "bundle", artifacts)
        controlled = self.root / "controlled"
        controlled.mkdir()
        config = self.root / "governance.json"
        config.write_text(json.dumps({
            "approver_id": "approver-1", "approver_role": "approver",
            "controlled_directory": str(controlled), "backup_policy": "synthetic test only",
        }), encoding="utf-8")
        actual = self._run("evaluate", "--bundle", bundle, "--config", config,
                           "--output-dir", self.root / "structural-eval")
        self.assertEqual(actual.returncode, 2, actual.stdout + actual.stderr)
        summary = loads_bytes(actual.stdout.encode())
        self.assertEqual(summary["status"], "completed_with_structural_failures")
        report = loads_bytes(Path(summary["json_report"]).read_bytes())
        self.assertGreater(report["aggregate"]["structural_failure_count"], 0)

    def test_synthetic_demo_is_reproducible_and_reports_do_not_overwrite(self):
        one = self._run("demo", "--output-dir", self.root / "one")
        two = self._run("demo", "--output-dir", self.root / "two")
        first = loads_bytes(one.stdout.encode())
        second = loads_bytes(two.stdout.encode())
        first_report = loads_bytes(Path(first["json_report"]).read_bytes())
        second_report = loads_bytes(Path(second["json_report"]).read_bytes())
        self.assertEqual(first_report, second_report)
        collision = self._run("demo", "--output-dir", self.root / "one")
        self.assertEqual(collision.returncode, 2)
        self.assertIn("report_already_exists", collision.stdout)

    def test_malformed_owner_configuration_refuses_evaluation(self):
        bundle, config = self._success_bundle()
        config.write_text("{}", encoding="utf-8")
        result = self._run("evaluate", "--bundle", bundle, "--config", config,
                           "--output-dir", self.root / "out")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(loads_bytes(result.stdout.encode())["status"], "failed")

    def test_demo_bundle_contains_only_synthetic_case_ids(self):
        index = loads_bytes((DEMO_BUNDLE / "bundle.json").read_bytes())
        self.assertEqual(set(index["cases"]), {
            "demo-authorized", "demo-unauthorized", "demo-refused",
        })
        self.assertTrue(all(case_id.startswith("demo-") for case_id in index["cases"]))


if __name__ == "__main__":
    unittest.main()
