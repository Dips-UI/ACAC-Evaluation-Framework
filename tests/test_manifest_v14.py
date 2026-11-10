"""Synthetic v1.4 manifest coverage and hash-binding tests."""

import unittest

from acac.canonical import exact_hash, semantic_hash
from acac.strict_json import loads_bytes
from acac.manifest_v14 import ManifestV14Error, validate_manifest_v14


def _hash(raw):
    return exact_hash(raw)


class ManifestV14Tests(unittest.TestCase):
    def fixture(self):
        artifacts = {
            "c1": {
                "case": b'{"case":"c1"}',
                "raw_output": b'{"edits":[]}',
                "authorization_input": b'{"schema_version":"acac-auth-input-1.0"}',
                "review_submission_bytes": [b'{"review_id":"r1"}'],
                "final_authorization_sidecar": b'{"spec_version":"acac-auth-1.2"}',
                "reference": b'{"reference_id":"ref1"}',
                "adjudication": b'{"review_id":"adj1"}',
                "approval_event": b'{"event_type":"approved"}',
            }
        }
        manifest = {
            "manifest_version": "1.4",
            "run_id": "run-1",
            "mode": "resolved_contract",
            "scheduled_case_ids": ["c1", "c2"],
            "executed_case_ids": ["c1"],
            "excluded_cases": [{"case_id": "c2", "reason": "missing_artifact"}],
            "case_hashes": {"c1": {"exact": _hash(artifacts["c1"]["case"]), "semantic": semantic_hash(loads_bytes(artifacts["c1"]["case"]))}},
            "authorization_input_hashes": {"c1": _hash(artifacts["c1"]["authorization_input"])},
            "review_submission_hashes": {"c1": [_hash(artifacts["c1"]["review_submission_bytes"][0])]},
            "final_authorization_sidecar_hashes": {"c1": _hash(artifacts["c1"]["final_authorization_sidecar"])},
            "reference_hashes": {"c1": _hash(artifacts["c1"]["reference"])},
            "adjudication_hashes": {"c1": _hash(artifacts["c1"]["adjudication"])},
            "approval_event_hashes": {"c1": _hash(artifacts["c1"]["approval_event"])},
            "raw_output_hashes": {"c1": _hash(artifacts["c1"]["raw_output"])},
            "prompt_hash": "sha256:" + "b" * 64,
            "configuration_hash": "sha256:" + "c" * 64,
            "grader_version": "acac-grader-1.4",
            "created_at": "2026-11-01T00:00:00Z",
            "model": {"provider": "synthetic", "family": "test", "model_id": "fixture", "version": "1", "runtime_version": "1", "settings": {}},
        }
        return manifest, artifacts

    def _two_case_fixture(self):
        manifest, artifacts = self.fixture()
        manifest["scheduled_case_ids"] = ["c1", "c2"]
        manifest["executed_case_ids"] = ["c1", "c2"]
        manifest["excluded_cases"] = []
        artifacts["c2"] = {
            "case": b'{"case":"c2"}', "raw_output": b'{"edits":[2]}',
            "authorization_input": b'{"schema_version":"acac-auth-input-1.0","case":"c2"}',
            "review_submission_bytes": [b'{"review_id":"r2"}'],
            "final_authorization_sidecar": b'{"spec_version":"acac-auth-1.2","case":"c2"}',
            "reference": b'{"reference_id":"ref2"}',
            "adjudication": b'{"review_id":"adj2"}',
            "approval_event": b'{"event_type":"approved","case":"c2"}',
        }
        c2 = artifacts["c2"]
        manifest["case_hashes"]["c2"] = {
            "exact": _hash(c2["case"]),
            "semantic": semantic_hash(loads_bytes(c2["case"])),
        }
        manifest["authorization_input_hashes"]["c2"] = _hash(c2["authorization_input"])
        manifest["review_submission_hashes"]["c2"] = [_hash(c2["review_submission_bytes"][0])]
        for map_name, artifact_name in (
            ("final_authorization_sidecar_hashes", "final_authorization_sidecar"),
            ("reference_hashes", "reference"), ("adjudication_hashes", "adjudication"),
            ("approval_event_hashes", "approval_event"), ("raw_output_hashes", "raw_output"),
        ):
            manifest[map_name]["c2"] = _hash(c2[artifact_name])
        return manifest, artifacts

    def test_complete_manifest_maps_bind_to_retained_bytes(self):
        manifest, artifacts = self.fixture()
        validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

    def test_freeze_event_hash_is_not_a_manifest_member(self):
        manifest, artifacts = self.fixture()
        manifest["freeze_event_hash"] = "sha256:" + "d" * 64
        with self.assertRaisesRegex(ManifestV14Error, "manifest_members"):
            validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

    def test_missing_or_extra_conditional_artifact_map_is_rejected(self):
        manifest, artifacts = self.fixture()
        del manifest["reference_hashes"]["c1"]
        with self.assertRaisesRegex(ManifestV14Error, "reference_hashes_coverage_mismatch"):
            validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

    def test_mismatched_present_artifact_hash_is_rejected(self):
        manifest, artifacts = self.fixture()
        manifest["authorization_input_hashes"]["c1"] = "sha256:" + "d" * 64
        with self.assertRaisesRegex(ManifestV14Error, "authorization_input_hashes_hash_mismatch"):
            validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

    def test_review_hash_hashes_match_artifacts_independent_of_source_order(self):
        manifest, artifacts = self.fixture()
        raw1, raw2 = b"a", b"z"
        artifacts["c1"]["review_submission_bytes"] = [raw1, raw2]
        manifest["review_submission_hashes"]["c1"] = [_hash(raw2), _hash(raw1)]
        validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)
        manifest["review_submission_hashes"]["c1"][0] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(ManifestV14Error, "review_submission_hashes_mismatch"):
            validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

    def test_excluded_case_cannot_be_executed_without_coverage_consistency(self):
        manifest, artifacts = self.fixture()
        manifest["executed_case_ids"].append("c2")
        with self.assertRaises(ManifestV14Error):
            validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

    def test_two_executed_cases_require_exact_case_and_output_map_coverage(self):
        manifest, artifacts = self._two_case_fixture()
        validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

        del manifest["raw_output_hashes"]["c2"]
        with self.assertRaisesRegex(ManifestV14Error, "raw_output_hashes_coverage"):
            validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

    def test_two_case_conditional_maps_reject_out_of_set_missing_and_mismatched_entries(self):
        cases = (
            ("case_hashes", "case_hashes_coverage", "case_hashes_coverage", "case_hash_mismatch"),
            ("raw_output_hashes", "raw_output_hashes_coverage", "raw_output_hashes_coverage", "raw_output_hash_mismatch"),
            ("authorization_input_hashes", "authorization_input_hashes_coverage_mismatch"),
            ("review_submission_hashes", "review_submission_hashes_coverage_mismatch"),
            ("final_authorization_sidecar_hashes", "final_authorization_sidecar_hashes_coverage_mismatch"),
            ("reference_hashes", "reference_hashes_coverage_mismatch"),
            ("adjudication_hashes", "adjudication_hashes_coverage_mismatch"),
            ("approval_event_hashes", "approval_event_hashes_coverage_mismatch"),
        )
        for case in cases:
            map_name, missing_error = case[0], case[1]
            out_of_set_error = case[2] if len(case) > 2 else f"invalid_{map_name}"
            mismatch_error = case[3] if len(case) > 3 else (
                "review_submission_hashes_mismatch" if map_name == "review_submission_hashes"
                else f"{map_name}_hash_mismatch"
            )
            with self.subTest(map=map_name, failure="out_of_set"):
                manifest, artifacts = self._two_case_fixture()
                if map_name == "case_hashes":
                    manifest[map_name]["c3"] = {"exact": _hash(b"unexpected"), "semantic": _hash(b"unexpected")}
                else:
                    manifest[map_name]["c3"] = [_hash(b"unexpected")] if map_name == "review_submission_hashes" else _hash(b"unexpected")
                with self.assertRaisesRegex(ManifestV14Error, out_of_set_error):
                    validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

            with self.subTest(map=map_name, failure="missing"):
                manifest, artifacts = self._two_case_fixture()
                del manifest[map_name]["c2"]
                with self.assertRaisesRegex(ManifestV14Error, missing_error):
                    validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)

            with self.subTest(map=map_name, failure="mismatched_hash"):
                manifest, artifacts = self._two_case_fixture()
                if map_name == "case_hashes":
                    manifest[map_name]["c2"] = {"exact": _hash(b"wrong"), "semantic": _hash(b"wrong")}
                else:
                    manifest[map_name]["c2"] = [_hash(b"wrong")] if map_name == "review_submission_hashes" else _hash(b"wrong")
                with self.assertRaisesRegex(ManifestV14Error, mismatch_error):
                    validate_manifest_v14(manifest, {"c1", "c2"}, artifacts)


if __name__ == "__main__":
    unittest.main()
