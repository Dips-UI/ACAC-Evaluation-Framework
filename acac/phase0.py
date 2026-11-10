"""Phase 0 policy and trust-boundary primitives for ACAC V1.

This module deliberately contains no case parsing, grading, model execution, or
production-write capability. Its write guard is local policy protection, not a
proof of system-wide prevention. It validates the project-level decisions that
must be fixed before later implementation phases begin.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import re
from typing import Any, Mapping


INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
PREDICATE_MAX_DEPTH = 8
PREDICATE_MAX_NODES = 64
PACKAGE_LICENSE = "Apache-2.0"


class Phase0ConfigurationError(ValueError):
    """Raised when accepted project-governance configuration is incomplete."""


@dataclass(frozen=True)
class GovernanceConfig:
    """Explicit local governance and custody configuration.

    The approver identity and custody policy are deployment values. They are
    intentionally supplied by configuration rather than invented by code.
    """

    approver_id: str
    approver_role: str
    controlled_directory: Path
    backup_policy: str
    license: str = PACKAGE_LICENSE

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "GovernanceConfig":
        required = {"approver_id", "approver_role", "controlled_directory", "backup_policy"}
        if not isinstance(value, Mapping) or set(value) - required - {"license"} or not required <= set(value):
            raise Phase0ConfigurationError("governance_config_fields")
        result = cls(
            approver_id=value["approver_id"],
            approver_role=value["approver_role"],
            controlled_directory=Path(value["controlled_directory"]),
            backup_policy=value["backup_policy"],
            license=value.get("license", PACKAGE_LICENSE),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if type(self.approver_id) is not str or not self.approver_id.strip():
            raise Phase0ConfigurationError("approver_id")
        if self.approver_role != "approver":
            raise Phase0ConfigurationError("approver_role")
        if type(self.backup_policy) is not str or not self.backup_policy.strip():
            raise Phase0ConfigurationError("backup_policy")
        if self.license != PACKAGE_LICENSE:
            raise Phase0ConfigurationError("license")
        if not isinstance(self.controlled_directory, Path):
            raise Phase0ConfigurationError("controlled_directory")
        if not self.controlled_directory.exists() or not self.controlled_directory.is_dir():
            raise Phase0ConfigurationError("controlled_directory_missing_or_not_directory")
        if self.controlled_directory.is_symlink():
            raise Phase0ConfigurationError("controlled_directory_symlink")


def require_distinct_approver(author_id: str, approver_id: str) -> None:
    """Require the owner-designated approver to differ from the author."""

    if type(author_id) is not str or type(approver_id) is not str or not author_id or not approver_id:
        raise Phase0ConfigurationError("actor_identity")
    if author_id == approver_id:
        raise Phase0ConfigurationError("approver_must_differ_from_author")


def validate_approval_actor(config: GovernanceConfig, author_id: str, approver_id: str) -> None:
    """Validate the actor that a future approval path intends to use."""

    if approver_id != config.approver_id:
        raise Phase0ConfigurationError("approver_not_configured_owner")
    require_distinct_approver(author_id, approver_id)


def verify_controlled_artifact(path: Path, controlled_directory: Path, expected_sha256: str) -> None:
    """Verify custody and bytes; this function does not create or verify backups."""

    if not isinstance(controlled_directory, Path) or not controlled_directory.exists():
        raise Phase0ConfigurationError("controlled_directory_missing_or_not_directory")
    if not controlled_directory.is_dir() or controlled_directory.is_symlink():
        raise Phase0ConfigurationError("controlled_directory")
    if type(expected_sha256) is not str or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise Phase0ConfigurationError("artifact_hash")
    if not isinstance(path, Path) or path.is_symlink():
        raise Phase0ConfigurationError("artifact_symlink")
    root = controlled_directory.resolve(strict=True)
    if not path.exists():
        raise Phase0ConfigurationError("artifact_missing")
    if not path.is_file():
        raise Phase0ConfigurationError("artifact_not_file")
    target = path.resolve(strict=True)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise Phase0ConfigurationError("artifact_outside_controlled_directory") from exc
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    if actual != expected_sha256.lower():
        raise Phase0ConfigurationError("artifact_hash_mismatch")


def deferred_capabilities() -> frozenset[str]:
    """Return capabilities explicitly deferred from V1."""

    return frozenset({
        "EvalScope",
        "annotation-platform-integrations",
        "csv-import",
        "dashboards",
        "direct-execution",
        "rollback",
        "multi-reference-scoring",
        "nested-values",
        "model-provider-clients",
        "production-writes",
    })


def write_production(*_args: Any, **_kwargs: Any) -> None:
    """Explicit Phase 0 guard: ACAC has no production-write path."""

    raise RuntimeError("production_writes_disabled")


def load_governance_json(path: Path) -> GovernanceConfig:
    """Load a local governance file without creating or modifying artifacts."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Phase0ConfigurationError("governance_file") from exc
    return GovernanceConfig.from_mapping(value)
