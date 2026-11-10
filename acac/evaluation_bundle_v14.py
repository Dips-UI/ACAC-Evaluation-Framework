"""Strict loader for exact-byte v1.4 evaluation run bundles.

Bundle layout is indexed by ``bundle.json`` and every referenced artifact must
resolve inside the selected bundle directory. This module performs loading only;
eligibility remains the coordinator's responsibility.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import exact_hash
from .coordinator_v14 import V14Artifacts
from .strict_json import loads_bytes


class EvaluationBundleError(ValueError):
    """An evaluation bundle is incomplete, malformed, or unsafe to load."""


_BUNDLE_FIELDS = {"schema_version", "manifest", "cases"}
_CASE_FIELDS = {
    "case", "authorization_input", "review_submissions",
    "final_authorization_sidecar", "reference", "adjudication",
    "lifecycle_events", "raw_output",
}


def _read_path(root: Path, relative: Any, label: str) -> bytes:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise EvaluationBundleError(f"{label}_path_invalid")
    candidate = Path(relative)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise EvaluationBundleError(f"{label}_path_invalid")
    base = root.resolve(strict=True)
    try:
        resolved = (base / candidate).resolve(strict=True)
        resolved.relative_to(base)
    except (OSError, ValueError) as exc:
        raise EvaluationBundleError(f"{label}_path_outside_or_missing") from exc
    if not resolved.is_file():
        raise EvaluationBundleError(f"{label}_not_a_file")
    try:
        return resolved.read_bytes()
    except OSError as exc:
        raise EvaluationBundleError(f"{label}_unreadable") from exc


def _parse(raw: bytes, label: str) -> Any:
    try:
        return loads_bytes(raw)
    except Exception as exc:
        raise EvaluationBundleError(f"{label}_json_invalid") from exc


def load_evaluation_bundle_v14(
    bundle_root: Path,
    configured_approver_id: str,
) -> tuple[dict[str, V14Artifacts], set[str]]:
    """Load exact artifact bytes into coordinator inputs.

    The bundle index is intentionally small. Artifact validity, hash binding,
    lifecycle and grading eligibility are checked downstream by the existing
    coordinator and aggregate functions.
    """
    root = Path(bundle_root)
    try:
        if not root.is_dir():
            raise EvaluationBundleError("bundle_directory_required")
        bundle_bytes = _read_path(root, "bundle.json", "bundle_index")
        bundle = _parse(bundle_bytes, "bundle_index")
        if not isinstance(bundle, dict) or set(bundle) != _BUNDLE_FIELDS:
            raise EvaluationBundleError("bundle_index_shape")
        if bundle["schema_version"] != "acac-evaluation-bundle-1.0":
            raise EvaluationBundleError("unsupported_bundle_version")
        manifest_bytes = _read_path(root, bundle["manifest"], "manifest")
        manifest = _parse(manifest_bytes, "manifest")
        if not isinstance(manifest, dict):
            raise EvaluationBundleError("manifest_object_required")
        scheduled_list = manifest.get("scheduled_case_ids")
        executed_list = manifest.get("executed_case_ids")
        if not isinstance(scheduled_list, list) or not isinstance(executed_list, list):
            raise EvaluationBundleError("manifest_case_inventory_required")
        if any(type(value) is not str for value in scheduled_list + executed_list):
            raise EvaluationBundleError("manifest_case_inventory_invalid")
        if len(scheduled_list) != len(set(scheduled_list)) or len(executed_list) != len(set(executed_list)):
            raise EvaluationBundleError("manifest_case_inventory_duplicate")
        scheduled = set(scheduled_list)
        executed = set(executed_list)
        entries = bundle["cases"]
        if not isinstance(entries, dict) or any(type(key) is not str for key in entries):
            raise EvaluationBundleError("bundle_cases_object_required")
        if set(entries) != executed:
            raise EvaluationBundleError("bundle_executed_case_coverage_mismatch")
        retained_by_case: dict[str, dict[str, Any]] = {}
        loaded: dict[str, dict[str, Any]] = {}

        for case_id in sorted(executed):
            entry = entries[case_id]
            if not isinstance(entry, dict) or set(entry) != _CASE_FIELDS:
                raise EvaluationBundleError("case_entry_shape")
            raw: dict[str, bytes] = {}
            for name in (
                "case", "authorization_input", "final_authorization_sidecar",
                "reference", "adjudication", "raw_output",
            ):
                raw[name] = _read_path(root, entry[name], f"{case_id}_{name}")
            parsed = {
                name: _parse(raw[name], f"{case_id}_{name}")
                for name in (
                    "case", "authorization_input", "final_authorization_sidecar",
                    "reference", "adjudication",
                )
            }
            reviews_value = entry["review_submissions"]
            if not isinstance(reviews_value, list) or not reviews_value:
                raise EvaluationBundleError("review_submissions_required")
            reviews: dict[str, tuple[dict, bytes]] = {}
            review_bytes: list[bytes] = []
            for review_index, rel_path in enumerate(reviews_value):
                review_raw = _read_path(root, rel_path, f"{case_id}_review_{review_index}")
                review = _parse(review_raw, f"{case_id}_review_{review_index}")
                if not isinstance(review, dict):
                    raise EvaluationBundleError("review_object_required")
                digest = exact_hash(review_raw)
                if digest in reviews:
                    raise EvaluationBundleError("duplicate_review_submission_hash")
                reviews[digest] = (review, review_raw)
                review_bytes.append(review_raw)

            event_paths = entry["lifecycle_events"]
            if not isinstance(event_paths, list) or not event_paths:
                raise EvaluationBundleError("lifecycle_events_required")
            event_values, event_bytes, event_hashes = [], [], []
            for event_index, rel_path in enumerate(event_paths):
                event_raw = _read_path(root, rel_path, f"{case_id}_lifecycle_{event_index}")
                event = _parse(event_raw, f"{case_id}_lifecycle_{event_index}")
                if not isinstance(event, dict):
                    raise EvaluationBundleError("lifecycle_event_object_required")
                event_values.append(event)
                event_bytes.append(event_raw)
                event_hashes.append(exact_hash(event_raw))
            approval_index = next(
                (index for index, event in enumerate(event_values)
                 if event.get("event_type") == "approved"),
                None,
            )
            if approval_index is None:
                raise EvaluationBundleError("approval_event_missing")
            retained_by_case[case_id] = {
                "case": raw["case"],
                "raw_output": raw["raw_output"],
                "authorization_input": raw["authorization_input"],
                "review_submission_bytes": review_bytes,
                "final_authorization_sidecar": raw["final_authorization_sidecar"],
                "reference": raw["reference"],
                "adjudication": raw["adjudication"],
                "approval_event": event_bytes[approval_index],
            }
            loaded[case_id] = {
                **parsed,
                "reviews": reviews,
                "raw": raw,
                "lifecycle_events": event_values,
                "lifecycle_event_bytes": event_bytes,
                "lifecycle_event_hashes": event_hashes,
            }

        artifacts_by_case: dict[str, V14Artifacts] = {}
        for case_id, item in loaded.items():
            case = item["case"]
            reference = item["reference"]
            if not isinstance(case, dict) or case.get("case_id") != case_id:
                raise EvaluationBundleError("case_id_binding_mismatch")
            author = reference.get("author") if isinstance(reference, dict) else None
            if not isinstance(author, dict) or type(author.get("author_id")) is not str:
                raise EvaluationBundleError("reference_author_id_missing")
            artifacts_by_case[case_id] = V14Artifacts(
                case, item["raw"]["case"],
                item["authorization_input"], item["raw"]["authorization_input"],
                item["reviews"],
                item["final_authorization_sidecar"], item["raw"]["final_authorization_sidecar"],
                reference, item["raw"]["reference"],
                item["adjudication"], item["raw"]["adjudication"],
                item["lifecycle_events"], item["lifecycle_event_bytes"],
                item["lifecycle_event_hashes"], item["raw"]["raw_output"],
                manifest, manifest_bytes, scheduled, retained_by_case,
                author["author_id"], configured_approver_id,
            )
        return artifacts_by_case, scheduled
    except EvaluationBundleError:
        raise
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise EvaluationBundleError("evaluation_bundle_invalid") from exc
