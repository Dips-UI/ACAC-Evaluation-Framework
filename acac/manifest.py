"""Structural V1 run-manifest validation."""
from datetime import datetime, timezone
import hashlib
from decimal import Decimal
from .strict_json import parse_rfc3339_timestamp


class ManifestError(ValueError):
    pass


def _hash(value: object, label: str) -> None:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(ch not in "0123456789abcdef" for ch in value[7:]):
        raise ManifestError(label)


def _id(value: object, label: str) -> None:
    if not isinstance(value, str) or not value or value.strip() != value or not value.isprintable():
        raise ManifestError(label)


def _model_setting(value: object) -> None:
    if value is None or isinstance(value, float):
        raise ManifestError("invalid_model_setting_value")
    if isinstance(value, bool) or isinstance(value, str):
        return
    if isinstance(value, int):
        if value < -(2**63) or value > 2**63 - 1:
            raise ManifestError("model_setting_integer_out_of_range")
        return
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ManifestError("invalid_model_setting_decimal")
        return
    if isinstance(value, list):
        for item in value:
            _model_setting(item)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ManifestError("model_setting_keys_must_be_strings")
        for item in value.values():
            _model_setting(item)
        return
    raise ManifestError("invalid_model_setting_value")


def verify_artifact_maps(manifest: dict, artifacts: dict[str, dict[str, bytes]]) -> None:
    """Verify conditional artifact maps against retained exact bytes."""
    executed = set(manifest.get("executed_case_ids", []))
    for map_name, artifact_name in (("authorization_spec_hashes", "authorization"), ("reference_hashes", "reference"), ("approval_event_hashes", "approval")):
        values = manifest.get(map_name, {})
        if not set(values) <= executed:
            raise ManifestError("conditional_hash_outside_executed")
        for case_id, expected in values.items():
            raw = artifacts.get(case_id, {}).get(artifact_name)
            if raw is None or expected != "sha256:" + hashlib.sha256(raw).hexdigest():
                raise ManifestError("artifact_hash_mismatch")


def validate_manifest(manifest: dict, scheduled: set[str]) -> None:
    required = {"manifest_version", "run_id", "mode", "scheduled_case_ids", "executed_case_ids", "excluded_cases", "case_hashes", "authorization_spec_hashes", "reference_hashes", "approval_event_hashes", "raw_output_hashes", "prompt_hash", "configuration_hash", "grader_version", "created_at"}
    if not isinstance(manifest, dict) or any(not isinstance(key, str) for key in manifest) or set(manifest) not in (required, required | {"model"}):
        raise ManifestError("manifest_members")
    if manifest["manifest_version"] != "1.3" or manifest["mode"] not in {"instruction_resolution", "resolved_contract"}:
        raise ManifestError("manifest_identity")
    _id(manifest["run_id"], "run_id")
    if not isinstance(scheduled, set) or any(not isinstance(item, str) for item in scheduled):
        raise ManifestError("scheduled_argument")
    scheduled_ids = manifest["scheduled_case_ids"]
    if not isinstance(scheduled_ids, list) or any(not isinstance(item, str) for item in scheduled_ids):
        raise ManifestError("scheduled_coverage")
    for item in scheduled_ids: _id(item, "scheduled_case_id")
    if set(scheduled_ids) != scheduled or len(scheduled_ids) != len(set(scheduled_ids)):
        raise ManifestError("scheduled_coverage")
    if not isinstance(manifest["executed_case_ids"], list) or any(not isinstance(item, str) for item in manifest["executed_case_ids"]):
        raise ManifestError("executed_case_ids")
    for item in manifest["executed_case_ids"]: _id(item, "executed_case_id")
    executed = set(manifest["executed_case_ids"])
    if not executed <= scheduled:
        raise ManifestError("executed_unscheduled")
    if len(manifest["executed_case_ids"]) != len(executed):
        raise ManifestError("duplicate_executed_ids")
    excluded = manifest["excluded_cases"]
    if not isinstance(excluded, list):
        raise ManifestError("excluded_cases")
    if not isinstance(manifest["case_hashes"], dict) or not isinstance(manifest["raw_output_hashes"], dict) or set(manifest["case_hashes"]) != executed or set(manifest["raw_output_hashes"]) != executed:
        raise ManifestError("hash_coverage")
    if manifest["grader_version"] != "acac-grader-1.3":
        raise ManifestError("grader_version")
    if not isinstance(manifest["created_at"], str):
        raise ManifestError("created_at")
    try:
        timestamp = parse_rfc3339_timestamp(manifest["created_at"])
        if not (timestamp.original.endswith("Z") or timestamp.original.endswith("+00:00")):
            raise ManifestError("created_at_must_be_utc")
    except ManifestError:
        raise
    except Exception as exc:
        raise ManifestError("created_at") from exc
    for field in ("prompt_hash", "configuration_hash"):
        _hash(manifest[field], field)
    for case_id, hashes in manifest["case_hashes"].items():
        if not isinstance(hashes, dict) or set(hashes) != {"exact", "semantic"}:
            raise ManifestError("case_hashes")
        _hash(hashes["exact"], "case_hashes"); _hash(hashes["semantic"], "case_hashes")
    for name in ("authorization_spec_hashes", "reference_hashes", "approval_event_hashes"):
        if not isinstance(manifest[name], dict) or any(not isinstance(key, str) for key in manifest[name]) or not set(manifest[name]) <= executed:
            raise ManifestError(name)
        for value in manifest[name].values(): _hash(value, name)
    if not isinstance(manifest["raw_output_hashes"], dict):
        raise ManifestError("raw_output_hashes")
    for value in manifest["raw_output_hashes"].values(): _hash(value, "raw_output_hashes")
    excluded_ids = []
    for entry in excluded:
        if not isinstance(entry, dict) or any(not isinstance(key, str) for key in entry) or set(entry) != {"case_id", "reason"}:
            raise ManifestError("excluded_case_shape")
        _id(entry["case_id"], "excluded_case_id")
        if entry["case_id"] not in scheduled or not isinstance(entry["reason"], str) or not entry["reason"] or entry["reason"].strip() != entry["reason"]:
            raise ManifestError("excluded_case_shape")
        excluded_ids.append(entry["case_id"])
    if len(excluded_ids) != len(set(excluded_ids)):
        raise ManifestError("duplicate_excluded_ids")
    for entry in excluded:
        missing = [code for code in entry["reason"].split(";") if code.startswith("missing_")]
        allowed_missing = {"missing_authorization_spec", "missing_reference", "missing_approval_event"}
        if any(code not in allowed_missing for code in missing):
            raise ManifestError("unknown_missing_artifact_code")
        if missing and missing != sorted(missing):
            raise ManifestError("missing_artifact_reason_order")
    if set(scheduled) != executed | set(excluded_ids):
        raise ManifestError("incomplete_schedule_coverage")
    if manifest["raw_output_hashes"] and "model" not in manifest:
        raise ManifestError("model_metadata_required")
    if not manifest["raw_output_hashes"] and "model" in manifest:
        raise ManifestError("model_must_be_omitted_without_output")
    if "model" in manifest:
        model = manifest["model"]
        if not isinstance(model, dict) or set(model) != {"provider", "family", "model_id", "version", "runtime_version", "settings"}:
            raise ManifestError("model_metadata")
        if any(not isinstance(model[name], str) or not model[name] for name in ("provider", "family", "model_id", "version", "runtime_version")) or not isinstance(model["settings"], dict):
            raise ManifestError("model_metadata")
        for name in ("provider", "family", "model_id", "version", "runtime_version"):
            _id(model[name], "model_" + name)
        _model_setting(model["settings"])
