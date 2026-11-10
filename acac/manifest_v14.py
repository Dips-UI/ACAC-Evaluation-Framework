"""ACAC v1.4 run-manifest validation and retained-artifact map binding."""

from typing import Any

from .canonical import exact_hash, semantic_hash
from .manifest import _id, _model_setting
from .strict_json import loads_bytes, parse_rfc3339_timestamp


class ManifestV14Error(ValueError):
    pass


_BASE = {
    "manifest_version", "run_id", "mode", "scheduled_case_ids", "executed_case_ids",
    "excluded_cases", "case_hashes", "authorization_input_hashes",
    "review_submission_hashes", "final_authorization_sidecar_hashes",
    "reference_hashes", "adjudication_hashes", "approval_event_hashes",
    "raw_output_hashes", "prompt_hash", "configuration_hash", "grader_version", "created_at",
}
_MAP_TO_ARTIFACT = {
    "authorization_input_hashes": "authorization_input",
    "final_authorization_sidecar_hashes": "final_authorization_sidecar",
    "reference_hashes": "reference",
    "adjudication_hashes": "adjudication",
    "approval_event_hashes": "approval_event",
}
_REFUSAL_ORDER = (
    "missing_artifact", "unsupported_version", "malformed_artifact", "hash_mismatch",
    "binding_mismatch", "unresolved_authorization", "quarantined_authorization",
    "review_missing", "review_invalid", "sidecar_invalid",
    "temporal_reconciliation_failed", "reference_invalid", "adjudication_invalid",
    "lifecycle_invalid", "approval_missing", "approver_not_distinct", "manifest_invalid",
)


def _hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise ManifestV14Error(f"invalid_{label}")


def _hash_map(value: Any, label: str, executed: set[str]) -> None:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value) or not set(value) <= executed:
        raise ManifestV14Error(f"invalid_{label}")
    for digest in value.values():
        _hash(digest, label)


def validate_manifest_v14(manifest: Any, scheduled: set[str], retained_artifacts: dict[str, dict[str, Any]]) -> None:
    """Validate v1.4 coverage and prove every present artifact map entry.

    ``retained_artifacts`` maps each executed case ID to raw artifact bytes:
    case, raw_output, authorization_input, review_submission_bytes (a list),
    final_authorization_sidecar, reference, adjudication, approval_event.
    ``case`` and ``raw_output`` are mandatory for each executed case. Optional
    artifact maps exactly follow the retained artifacts supplied for that case.
    """
    try:
        if not isinstance(manifest, dict) or any(not isinstance(key, str) for key in manifest):
            raise ManifestV14Error("manifest_object_required")
        if set(manifest) not in (_BASE, _BASE | {"model"}):
            raise ManifestV14Error("manifest_members")
        if manifest["manifest_version"] != "1.4" or manifest["mode"] not in {"instruction_resolution", "resolved_contract"}:
            raise ManifestV14Error("manifest_version_or_mode")
        if not isinstance(scheduled, set) or any(not isinstance(item, str) for item in scheduled):
            raise ManifestV14Error("scheduled_argument")
        if not isinstance(retained_artifacts, dict):
            raise ManifestV14Error("retained_artifact_map_required")
        _id(manifest["run_id"], "run_id")
        scheduled_ids = manifest["scheduled_case_ids"]
        if not isinstance(scheduled_ids, list) or any(not isinstance(item, str) for item in scheduled_ids):
            raise ManifestV14Error("scheduled_case_ids")
        for item in scheduled_ids:
            _id(item, "scheduled_case_id")
        if len(scheduled_ids) != len(set(scheduled_ids)) or set(scheduled_ids) != scheduled:
            raise ManifestV14Error("scheduled_coverage")
        executed_ids = manifest["executed_case_ids"]
        if not isinstance(executed_ids, list) or any(not isinstance(item, str) for item in executed_ids):
            raise ManifestV14Error("executed_case_ids")
        for item in executed_ids:
            _id(item, "executed_case_id")
        executed = set(executed_ids)
        if len(executed_ids) != len(executed) or not executed <= scheduled:
            raise ManifestV14Error("executed_coverage")
        excluded = manifest["excluded_cases"]
        if not isinstance(excluded, list):
            raise ManifestV14Error("excluded_cases")
        excluded_ids: list[str] = []
        for item in excluded:
            if not isinstance(item, dict) or set(item) != {"case_id", "reason"}:
                raise ManifestV14Error("excluded_case_shape")
            _id(item["case_id"], "excluded_case_id")
            if item["case_id"] not in scheduled or not isinstance(item["reason"], str) or not item["reason"] or item["reason"].strip() != item["reason"]:
                raise ManifestV14Error("excluded_case_shape")
            codes = item["reason"].split(";")
            if len(codes) != len(set(codes)) or any(code not in _REFUSAL_ORDER for code in codes):
                raise ManifestV14Error("excluded_case_reason_code")
            if codes != sorted(codes, key=_REFUSAL_ORDER.index):
                raise ManifestV14Error("excluded_case_reason_order")
            excluded_ids.append(item["case_id"])
        if len(excluded_ids) != len(set(excluded_ids)) or set(scheduled) != executed | set(excluded_ids):
            raise ManifestV14Error("schedule_exclusion_coverage")
        if manifest["grader_version"] != "acac-grader-1.4":
            raise ManifestV14Error("grader_version")
        for name in ("prompt_hash", "configuration_hash"):
            _hash(manifest[name], name)
        timestamp = parse_rfc3339_timestamp(manifest["created_at"])
        if not (timestamp.original.endswith("Z") or timestamp.original.endswith("+00:00")):
            raise ManifestV14Error("created_at_must_be_utc")

        for name in ("case_hashes", "raw_output_hashes"):
            values = manifest[name]
            if not isinstance(values, dict) or set(values) != executed:
                raise ManifestV14Error(f"{name}_coverage")
        for case_id, hashes in manifest["case_hashes"].items():
            if not isinstance(hashes, dict) or set(hashes) != {"exact", "semantic"}:
                raise ManifestV14Error("case_hash_shape")
            _hash(hashes["exact"], "case_exact_hash")
            _hash(hashes["semantic"], "case_semantic_hash")
            raw_case = retained_artifacts.get(case_id, {}).get("case") if isinstance(retained_artifacts.get(case_id), dict) else None
            if not isinstance(raw_case, bytes):
                raise ManifestV14Error("retained_case_bytes_required")
            try:
                parsed_case = loads_bytes(raw_case)
            except Exception as exc:
                raise ManifestV14Error("retained_case_json_invalid") from exc
            if hashes["exact"] != exact_hash(raw_case) or hashes["semantic"] != semantic_hash(parsed_case):
                raise ManifestV14Error("case_hash_mismatch")
        _hash_map(manifest["raw_output_hashes"], "raw_output_hash", executed)
        for case_id, digest in manifest["raw_output_hashes"].items():
            raw_output = retained_artifacts.get(case_id, {}).get("raw_output") if isinstance(retained_artifacts.get(case_id), dict) else None
            if not isinstance(raw_output, bytes) or digest != exact_hash(raw_output):
                raise ManifestV14Error("raw_output_hash_mismatch")

        for map_name, artifact_name in _MAP_TO_ARTIFACT.items():
            values = manifest[map_name]
            if not isinstance(values, dict) or any(not isinstance(key, str) for key in values) or not set(values) <= executed:
                raise ManifestV14Error(f"invalid_{map_name}")
            expected_cases = {
                case_id for case_id in executed
                if isinstance(retained_artifacts.get(case_id), dict) and isinstance(retained_artifacts[case_id].get(artifact_name), bytes)
            }
            if set(values) != expected_cases:
                raise ManifestV14Error(f"{map_name}_coverage_mismatch")
            for case_id, digest in values.items():
                _hash(digest, map_name)
                if digest != exact_hash(retained_artifacts[case_id][artifact_name]):
                    raise ManifestV14Error(f"{map_name}_hash_mismatch")

        review_map = manifest["review_submission_hashes"]
        if not isinstance(review_map, dict) or any(not isinstance(case_id, str) for case_id in review_map) or not set(review_map) <= executed:
            raise ManifestV14Error("invalid_review_submission_hashes")
        expected_review_cases = {
            case_id for case_id in executed
            if isinstance(retained_artifacts.get(case_id), dict) and "review_submission_bytes" in retained_artifacts[case_id]
        }
        if set(review_map) != expected_review_cases:
            raise ManifestV14Error("review_submission_hashes_coverage_mismatch")
        for case_id, hashes in review_map.items():
            raw_reviews = retained_artifacts[case_id].get("review_submission_bytes")
            if not isinstance(raw_reviews, list) or any(not isinstance(raw, bytes) for raw in raw_reviews):
                raise ManifestV14Error("review_submission_bytes_required")
            if not isinstance(hashes, list) or any(not isinstance(item, str) for item in hashes):
                raise ManifestV14Error("review_submission_hash_array")
            if len(hashes) != len(set(hashes)):
                raise ManifestV14Error("duplicate_review_submission_hash")
            for digest in hashes:
                _hash(digest, "review_submission_hash")
            expected_hashes = [exact_hash(raw) for raw in raw_reviews]
            if len(hashes) != len(expected_hashes) or set(hashes) != set(expected_hashes):
                raise ManifestV14Error("review_submission_hashes_mismatch")

        has_output = bool(manifest["raw_output_hashes"])
        if has_output != ("model" in manifest):
            raise ManifestV14Error("model_metadata_conditional")
        if "model" in manifest:
            model = manifest["model"]
            if not isinstance(model, dict) or set(model) != {"provider", "family", "model_id", "version", "runtime_version", "settings"}:
                raise ManifestV14Error("model_metadata_shape")
            if any(not isinstance(model[key], str) or not model[key] for key in ("provider", "family", "model_id", "version", "runtime_version")) or not isinstance(model["settings"], dict):
                raise ManifestV14Error("model_metadata_shape")
            for key in ("provider", "family", "model_id", "version", "runtime_version"):
                _id(model[key], "model_" + key)
            _model_setting(model["settings"])
    except ManifestV14Error:
        raise
    except Exception as exc:
        raise ManifestV14Error(str(exc)) from exc
