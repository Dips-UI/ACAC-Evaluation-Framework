"""Synthetic Phase 0 policy tests; no benchmark or review artifacts are read."""

from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from acac.phase0 import (
    INT64_MAX,
    INT64_MIN,
    PACKAGE_LICENSE,
    PREDICATE_MAX_DEPTH,
    PREDICATE_MAX_NODES,
    GovernanceConfig,
    Phase0ConfigurationError,
    deferred_capabilities,
    require_distinct_approver,
    validate_approval_actor,
    verify_controlled_artifact,
    write_production,
)
from acac.runner import DisabledAdapter, Request


class Phase0Tests(unittest.TestCase):
    def config(self, directory: Path) -> GovernanceConfig:
        return GovernanceConfig.from_mapping({
            "approver_id": "owner-approver",
            "approver_role": "approver",
            "controlled_directory": str(directory),
            "backup_policy": "daily immutable local backup",
        })

    def test_accepted_constants(self):
        self.assertEqual((INT64_MIN, INT64_MAX), (-(2**63), 2**63 - 1))
        self.assertEqual((PREDICATE_MAX_DEPTH, PREDICATE_MAX_NODES), (8, 64))
        self.assertEqual(PACKAGE_LICENSE, "Apache-2.0")

    def test_project_metadata_declares_apache_license(self):
        project = Path(__file__).resolve().parents[1] / "pyproject.toml"
        with project.open("rb") as handle:
            metadata = tomllib.load(handle)["project"]
        self.assertEqual(metadata["license"]["text"], "Apache-2.0")

    def test_governance_config_requires_owner_values_and_license(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            self.assertEqual(config.license, PACKAGE_LICENSE)
            with self.assertRaisesRegex(Phase0ConfigurationError, "approver_id"):
                GovernanceConfig.from_mapping({
                    "approver_id": "",
                    "approver_role": "approver",
                    "controlled_directory": directory,
                    "backup_policy": "daily",
                })
            with self.assertRaisesRegex(Phase0ConfigurationError, "license"):
                GovernanceConfig.from_mapping({
                    "approver_id": "owner-approver",
                    "approver_role": "approver",
                    "controlled_directory": directory,
                    "backup_policy": "daily",
                    "license": "MIT",
                })

    def test_governance_config_requires_real_directory_and_rejects_symlink_root(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(Phase0ConfigurationError, "missing_or_not_directory"):
                GovernanceConfig.from_mapping({
                    "approver_id": "owner-approver",
                    "approver_role": "approver",
                    "controlled_directory": str(Path(directory) / "missing"),
                    "backup_policy": "daily",
                })
            target = Path(directory) / "target"
            target.mkdir()
            link = Path(directory) / "root-link"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlinks unavailable")
            with self.assertRaisesRegex(Phase0ConfigurationError, "symlink"):
                GovernanceConfig.from_mapping({
                    "approver_id": "owner-approver",
                    "approver_role": "approver",
                    "controlled_directory": str(link),
                    "backup_policy": "daily",
                })

    def test_approver_must_differ_from_author(self):
        require_distinct_approver("author-1", "owner-approver")
        with self.assertRaisesRegex(Phase0ConfigurationError, "differ"):
            require_distinct_approver("same", "same")

    def test_future_approval_actor_must_match_configured_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory))
            validate_approval_actor(config, "author-1", "owner-approver")
            with self.assertRaisesRegex(Phase0ConfigurationError, "configured_owner"):
                validate_approval_actor(config, "author-1", "other-approver")
            with self.assertRaisesRegex(Phase0ConfigurationError, "differ"):
                validate_approval_actor(config, "owner-approver", "owner-approver")

    def test_controlled_artifact_hash_and_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.config(root)
            artifact = root / "trusted.json"
            artifact.write_bytes(b'{"version":1}\n')
            import hashlib
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            verify_controlled_artifact(artifact, root, digest)
            self.assertFalse((root / "trusted.json.bak").exists())
            with self.assertRaisesRegex(Phase0ConfigurationError, "mismatch"):
                verify_controlled_artifact(artifact, root, "0" * 64)
            with self.assertRaisesRegex(Phase0ConfigurationError, "artifact_hash"):
                verify_controlled_artifact(artifact, root, "not-a-hash")
            with self.assertRaisesRegex(Phase0ConfigurationError, "artifact_missing"):
                verify_controlled_artifact(root / "missing.json", root, digest)
            directory_artifact = root / "directory-artifact"
            directory_artifact.mkdir()
            with self.assertRaisesRegex(Phase0ConfigurationError, "not_file"):
                verify_controlled_artifact(directory_artifact, root, digest)
            outside = root.parent / "outside.json"
            outside.write_bytes(artifact.read_bytes())
            with self.assertRaisesRegex(Phase0ConfigurationError, "outside"):
                verify_controlled_artifact(outside, root, digest)
            internal_target = root / "internal-target.json"
            internal_target.write_bytes(artifact.read_bytes())
            internal_link = root / "internal-link.json"
            try:
                internal_link.symlink_to(internal_target)
            except (OSError, NotImplementedError):
                self.skipTest("file symlinks unavailable")
            with self.assertRaisesRegex(Phase0ConfigurationError, "symlink"):
                verify_controlled_artifact(internal_link, root, digest)

    def test_symlink_escape_guards_are_exercised_without_platform_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "trusted.json"
            artifact.write_bytes(b"trusted")
            import hashlib
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()

            def fake_is_symlink(path):
                return path == artifact

            with patch.object(Path, "is_symlink", autospec=True, side_effect=fake_is_symlink):
                with self.assertRaisesRegex(Phase0ConfigurationError, "artifact_symlink"):
                    verify_controlled_artifact(artifact, root, digest)

    def test_production_write_is_unavailable(self):
        with self.assertRaisesRegex(RuntimeError, "production_writes_disabled"):
            write_production("anything")

    def test_provider_execution_is_disabled(self):
        with self.assertRaisesRegex(RuntimeError, "disabled"):
            DisabledAdapter().generate(Request("synthetic", "{}"))

    def test_deferred_capabilities_are_explicit(self):
        deferred = deferred_capabilities()
        for capability in ("EvalScope", "annotation-platform-integrations", "model-provider-clients", "production-writes"):
            self.assertIn(capability, deferred)


if __name__ == "__main__":
    unittest.main()
