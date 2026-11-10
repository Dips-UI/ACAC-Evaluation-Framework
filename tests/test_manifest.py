import unittest
import hashlib
from decimal import Decimal
from acac.manifest import validate_manifest, verify_artifact_maps


class ManifestTests(unittest.TestCase):
    def test_manifest_coverage_and_versions(self):
        manifest = {"manifest_version": "1.3", "run_id": "run-1", "mode": "instruction_resolution", "scheduled_case_ids": ["c1"], "executed_case_ids": ["c1"], "excluded_cases": [], "case_hashes": {"c1": {"exact": "sha256:" + "0" * 64, "semantic": "sha256:" + "1" * 64}}, "authorization_spec_hashes": {}, "reference_hashes": {}, "approval_event_hashes": {}, "raw_output_hashes": {"c1": "sha256:" + "2" * 64}, "prompt_hash": "sha256:" + "3" * 64, "configuration_hash": "sha256:" + "4" * 64, "grader_version": "acac-grader-1.3", "created_at": "2026-01-01T00:00:00Z", "model": {"provider": "local", "family": "test", "model_id": "m", "version": "v", "runtime_version": "unavailable", "settings": {}}}
        validate_manifest(manifest, {"c1"})
        with self.assertRaises(ValueError): validate_manifest({**manifest, "executed_case_ids": ["c2"]}, {"c1"})
        raw = b"authorization"
        verify_artifact_maps({"executed_case_ids": ["c1"], "authorization_spec_hashes": {"c1": "sha256:" + hashlib.sha256(raw).hexdigest()}, "reference_hashes": {}, "approval_event_hashes": {}}, {"c1": {"authorization": raw}})

    def test_conditional_artifact_maps_reject_out_of_set_and_mismatched_hash(self):
        raw = b"synthetic retained reference"
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        base = {"executed_case_ids": ["c1"], "authorization_spec_hashes": {},
                "reference_hashes": {"c1": digest}, "approval_event_hashes": {}}
        artifacts = {"c1": {"reference": raw}}
        verify_artifact_maps(base, artifacts)
        with self.assertRaisesRegex(ValueError, "conditional_hash_outside_executed"):
            verify_artifact_maps({**base, "reference_hashes": {"c2": digest}}, artifacts)
        with self.assertRaisesRegex(ValueError, "artifact_hash_mismatch"):
            verify_artifact_maps({**base, "reference_hashes": {"c1": "sha256:" + "0" * 64}}, artifacts)

    def test_executed_case_may_also_be_excluded(self):
        manifest = {"manifest_version": "1.3", "run_id": "run-1", "mode": "instruction_resolution", "scheduled_case_ids": ["c1"], "executed_case_ids": ["c1"], "excluded_cases": [{"case_id": "c1", "reason": "missing_reference"}], "case_hashes": {"c1": {"exact": "sha256:" + "0" * 64, "semantic": "sha256:" + "1" * 64}}, "authorization_spec_hashes": {}, "reference_hashes": {}, "approval_event_hashes": {}, "raw_output_hashes": {"c1": "sha256:" + "2" * 64}, "prompt_hash": "sha256:" + "3" * 64, "configuration_hash": "sha256:" + "4" * 64, "grader_version": "acac-grader-1.3", "created_at": "2026-01-01T00:00:00Z", "model": {"provider": "local", "family": "test", "model_id": "m", "version": "v", "runtime_version": "unavailable", "settings": {}}}
        validate_manifest(manifest, {"c1"})

    def test_manifest_rejects_partial_model_and_bad_hash(self):
        manifest = {"manifest_version": "1.3", "run_id": "run-1", "mode": "instruction_resolution", "scheduled_case_ids": ["c1"], "executed_case_ids": ["c1"], "excluded_cases": [], "case_hashes": {"c1": {"exact": "sha256:" + "0" * 64, "semantic": "sha256:" + "1" * 64}}, "authorization_spec_hashes": {}, "reference_hashes": {}, "approval_event_hashes": {}, "raw_output_hashes": {"c1": "sha256:" + "2" * 64}, "prompt_hash": "sha256:" + "3" * 64, "configuration_hash": "sha256:" + "4" * 64, "grader_version": "acac-grader-1.3", "created_at": "2026-01-01T00:00:00Z", "model": {"provider": "local"}}
        with self.assertRaisesRegex(ValueError, "model_metadata"):
            validate_manifest(manifest, {"c1"})
        manifest["model"] = {"provider": "local", "family": "test", "model_id": "m", "version": "v", "runtime_version": "unavailable", "settings": {}}
        manifest["raw_output_hashes"]["c1"] = "sha256:not-a-hash"
        with self.assertRaisesRegex(ValueError, "raw_output_hashes"):
            validate_manifest(manifest, {"c1"})

    def test_missing_artifact_codes_are_controlled_and_sorted(self):
        manifest = {"manifest_version": "1.3", "run_id": "run-1", "mode": "instruction_resolution", "scheduled_case_ids": ["c1"], "executed_case_ids": ["c1"], "excluded_cases": [{"case_id": "c1", "reason": "missing_reference;missing_authorization_spec"}], "case_hashes": {"c1": {"exact": "sha256:" + "0" * 64, "semantic": "sha256:" + "1" * 64}}, "authorization_spec_hashes": {}, "reference_hashes": {}, "approval_event_hashes": {}, "raw_output_hashes": {"c1": "sha256:" + "2" * 64}, "prompt_hash": "sha256:" + "3" * 64, "configuration_hash": "sha256:" + "4" * 64, "grader_version": "acac-grader-1.3", "created_at": "2026-01-01T00:00:00Z", "model": {"provider": "local", "family": "test", "model_id": "m", "version": "v", "runtime_version": "unavailable", "settings": {}}}
        with self.assertRaisesRegex(ValueError, "missing_artifact_reason_order"):
            validate_manifest(manifest, {"c1"})
        manifest["excluded_cases"][0]["reason"] = "missing_authorization_spec;missing_reference"
        validate_manifest(manifest, {"c1"})
        manifest["excluded_cases"][0]["reason"] = "missing_unknown"
        with self.assertRaisesRegex(ValueError, "unknown_missing_artifact_code"):
            validate_manifest(manifest, {"c1"})

    def test_model_settings_allow_exact_decimal_but_reject_null_and_float(self):
        manifest = {"manifest_version": "1.3", "run_id": "run-1", "mode": "instruction_resolution", "scheduled_case_ids": ["c1"], "executed_case_ids": ["c1"], "excluded_cases": [], "case_hashes": {"c1": {"exact": "sha256:" + "0" * 64, "semantic": "sha256:" + "1" * 64}}, "authorization_spec_hashes": {}, "reference_hashes": {}, "approval_event_hashes": {}, "raw_output_hashes": {"c1": "sha256:" + "2" * 64}, "prompt_hash": "sha256:" + "3" * 64, "configuration_hash": "sha256:" + "4" * 64, "grader_version": "acac-grader-1.3", "created_at": "2026-01-01T00:00:00Z", "model": {"provider": "local", "family": "test", "model_id": "m", "version": "v", "runtime_version": "unavailable", "settings": {"sampling": {"temperature": Decimal("0.1250"), "enabled": False}}}}
        validate_manifest(manifest, {"c1"})
        for bad in (None, 1.25):
            manifest["model"]["settings"]["sampling"]["temperature"] = bad
            with self.assertRaisesRegex(ValueError, "invalid_model_setting_value"):
                validate_manifest(manifest, {"c1"})

    def test_manifest_requires_utc_time_and_fails_safely_on_malformed_lists(self):
        manifest = {"manifest_version": "1.3", "run_id": "run-1", "mode": "instruction_resolution", "scheduled_case_ids": ["c1"], "executed_case_ids": [], "excluded_cases": [{"case_id": "c1", "reason": "missing_reference"}], "case_hashes": {}, "authorization_spec_hashes": {}, "reference_hashes": {}, "approval_event_hashes": {}, "raw_output_hashes": {}, "prompt_hash": "sha256:" + "3" * 64, "configuration_hash": "sha256:" + "4" * 64, "grader_version": "acac-grader-1.3", "created_at": "2026-01-01T01:00:00+01:00"}
        with self.assertRaisesRegex(ValueError, "created_at_must_be_utc"):
            validate_manifest(manifest, {"c1"})
        manifest["created_at"] = "2026-01-01T00:00:00Z"
        manifest["excluded_cases"] = [None]
        with self.assertRaisesRegex(ValueError, "excluded_case_shape"):
            validate_manifest(manifest, {"c1"})


if __name__ == "__main__": unittest.main()
