"""Command helpers for fail-closed, offline v1.4 artifact evaluation."""

from __future__ import annotations

import hashlib
import html
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from .aggregate_v14 import aggregate_artifact_run_v14
from .evaluation_bundle_v14 import EvaluationBundleError, load_evaluation_bundle_v14
from .canonical import exact_hash, semantic_hash
from .coordinator_v14 import grade_with_artifact_eligibility
from .manifest_v14 import validate_manifest_v14
from .phase0 import GovernanceConfig, load_governance_json
from .reports_v14 import aggregate_report_v14, edit_decisions_v14
from .strict_json import dumps, loads_bytes


class EvaluationCLIError(ValueError):
    pass


def _atomic_create(path: Path, content: bytes) -> None:
    """Publish one report atomically without replacing an existing file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".acac-report-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # Same-directory hard-link publication is atomic and create-if-absent.
        os.link(temporary, path)
    except FileExistsError as exc:
        raise EvaluationCLIError(f"report_already_exists:{path.name}") from exc
    except OSError as exc:
        raise EvaluationCLIError("report_publication_failed") from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _render_markdown(report: dict[str, Any]) -> str:
    aggregate = report["aggregate"]
    results = aggregate.get("case_results", {})
    excluded = {item["case_id"]: item["reason"] for item in aggregate["excluded_cases"]}
    lines = [
        "# ACAC evaluation report",
        "",
        f"- Run: `{report['run_id']}`",
        f"- Status: **{report['status']}**",
        f"- Evidence type: **{report['evidence_type']}**",
        f"- Scheduled cases: {aggregate['scheduled_count']}",
        f"- Coordinator-eligible cases: {aggregate['included_count']}",
        f"- Excluded cases: {aggregate['excluded_count']}",
        f"- Structural failures: {aggregate['structural_failure_count']}",
        "",
        "## Per-case results",
        "",
        "| Case | Outcome | Exact edit set | Diagnostics |",
        "|---|---|---:|---|",
    ]
    for case_id in sorted(set(results) | set(excluded)):
        if case_id in excluded:
            lines.append(f"| `{case_id}` | Ineligible: `{excluded[case_id]}` | — | — |")
            continue
        result = results[case_id]
        diagnostics = ", ".join(f"`{item}`" for item in result["diagnostics"]) or "—"
        exact = "yes" if result["exact_edit_set_valid"] else "no"
        outcome = "Structural failure" if not result["contract_valid"] else "Evaluated"
        lines.append(f"| `{case_id}` | {outcome} | {exact} | {diagnostics} |")
    lines.extend((
        "",
        "## Aggregate metrics",
        "",
        "| Metric | Value | Denominator |",
        "|---|---:|---:|",
        f"| Exact edit-set validity | `{json.dumps(aggregate['exact_edit_set_validity'])}` | {aggregate['exact_edit_set_validity_denominator']} |",
        f"| Preservation accuracy | `{json.dumps(aggregate['preservation_accuracy'])}` | {aggregate['preservation_protected_cell_denominator']} |",
        f"| Structural failure rate | `{json.dumps(aggregate['structural_failure_rate'])}` | {aggregate['structural_failure_denominator']} |",
    ))
    if aggregate["count_metrics"]:
        for name, value in sorted(aggregate["count_metrics"].items()):
            lines.append(f"| `{name}` | {value} | {aggregate['ledger_metric_denominator']} |")
    if report["evidence_type"] == "synthetic demonstration":
        lines.extend((
            "",
            "> This is synthetic software demonstration evidence. It is not a model benchmark, gold data, or evidence of real model performance.",
        ))
    lines.append("")
    return "\n".join(lines)


def _render_html(report: dict[str, Any]) -> str:
    """Render a self-contained, script-free HTML view of an existing report."""
    aggregate = report["aggregate"]
    results = aggregate.get("case_results", {})
    excluded = {item["case_id"]: item["reason"] for item in aggregate["excluded_cases"]}
    edits_by_case = report.get("edit_decisions_by_case", {})
    esc = lambda value: html.escape(str(value), quote=True)
    rows = []
    for case_id in sorted(set(results) | set(excluded)):
        if case_id in excluded:
            rows.append(
                f"<tr><th scope=\"row\">{esc(case_id)}</th><td>Not grading-eligible</td>"
                f"<td colspan=\"2\">{esc(excluded[case_id])}</td></tr>"
            )
            continue
        result = results[case_id]
        outcome = "Structural failure" if not result["contract_valid"] else (
            "Exact edit set" if result["exact_edit_set_valid"] else "Differs from expected edit set"
        )
        diagnostics = "; ".join(result["diagnostics"]) or "None"
        rows.append(
            f"<tr><th scope=\"row\">{esc(case_id)}</th><td>{esc(outcome)}</td>"
            f"<td>{'yes' if result['exact_edit_set_valid'] else 'no'}</td>"
            f"<td>{esc(diagnostics)}</td></tr>"
        )

    edit_sections = []
    for case_id in sorted(edits_by_case):
        case_decisions = edits_by_case[case_id]
        edit_rows = []
        for item in case_decisions.get("edits", []):
            target = ".".join(map(str, item.get("target", [])))
            applicable = item.get("applicable_rules", {})
            evidence = item.get("supporting_evidence", {}).get("artifact_hashes", {})
            fields = [
                f"<td>{esc(target)}</td>",
                f"<td><code>{esc(json.dumps(item.get('from'), ensure_ascii=False))}</code> &rarr; "
                f"<code>{esc(json.dumps(item.get('to'), ensure_ascii=False))}</code></td>",
                f"<td>{esc(item.get('authorization_decision', 'not_evaluated'))}</td>",
                f"<td>{esc(item.get('reason', ''))}</td>",
            ]
            rules_text = json.dumps(applicable, ensure_ascii=False, sort_keys=True)
            evidence_text = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
            fields.extend((f"<td><code>{esc(rules_text)}</code></td>", f"<td><code>{esc(evidence_text)}</code></td>"))
            edit_rows.append("<tr>" + "".join(fields) + "</tr>")
        diagnostics = "; ".join(case_decisions.get("diagnostics", []))
        summary = case_decisions.get("refusal_code") or case_decisions.get("status", "unknown")
        if diagnostics:
            summary += ": " + diagnostics
        edit_sections.append(
            f"<section><h3>{esc(case_id)} - {esc(summary)}</h3>"
            "<div class=\"table-wrap\"><table><thead><tr><th>Target</th><th>Proposed transition</th>"
            "<th>Decision</th><th>Reason</th><th>Applicable rules and instructions</th>"
            "<th>Bound evidence hashes</th></tr></thead><tbody>"
            + ("".join(edit_rows) if edit_rows else "<tr><td colspan=\"6\">No edit-level decision was made.</td></tr>")
            + "</tbody></table></div></section>"
        )

    metrics = "".join(
        f"<tr><th scope=\"row\">{esc(name)}</th><td><code>{esc(json.dumps(value, ensure_ascii=False, sort_keys=True))}</code></td></tr>"
        for name, value in sorted(aggregate.items())
        if name.endswith("validity") or name in {"preservation_accuracy", "structural_failure_rate", "count_metrics"}
    )
    limitations = (
        "Per-edit decisions report comparison with the validated resolved authorization. "
        "They do not interpret natural-language instructions. The current schema does not bind direct evidence IDs to each key; artifact hashes below are provenance bindings."
    )
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>ACAC evaluation report</title><style>
body{font:16px/1.5 system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#17202a;background:#fff}
h1,h2,h3{line-height:1.2} .summary{display:flex;flex-wrap:wrap;gap:.6rem}.badge{padding:.35rem .65rem;border:1px solid #9aa7b2;border-radius:1rem;background:#f3f6f8}
.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;margin:.8rem 0 1.5rem}th,td{border:1px solid #c7d0d8;padding:.55rem;text-align:left;vertical-align:top}thead{background:#edf2f5}
code,pre{overflow-wrap:anywhere;white-space:pre-wrap} .note{padding:.8rem 1rem;background:#f4f7f9;border-left:4px solid #54758e}section{margin:1.5rem 0}
</style></head><body>
""" + (
        f"<h1>ACAC evaluation report</h1><div class=\"summary\">"
        f"<span class=\"badge\">Run: {esc(report['run_id'])}</span>"
        f"<span class=\"badge\">Status: {esc(report['status'])}</span>"
        f"<span class=\"badge\">Evidence: {esc(report['evidence_type'])}</span>"
        f"<span class=\"badge\">Scheduled: {aggregate['scheduled_count']}</span>"
        f"<span class=\"badge\">Included: {aggregate['included_count']}</span>"
        f"<span class=\"badge\">Excluded: {aggregate['excluded_count']}</span>"
        f"<span class=\"badge\">Structural failures: {aggregate['structural_failure_count']}</span></div>"
        f"<h2>Case results</h2><div class=\"table-wrap\"><table><thead><tr><th>Case</th><th>Outcome</th>"
        f"<th>Exact edit set</th><th>Diagnostics or exclusion reason</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
        f"<h2>Aggregate metrics</h2><table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>{metrics}</tbody></table>"
        f"<h2>Per-edit decisions</h2><p class=\"note\">{esc(limitations)}</p>{''.join(edit_sections)}"
        f"<h2>Provenance</h2><div class=\"table-wrap\"><table><thead><tr><th>Case</th><th>Artifact hash bindings</th></tr></thead><tbody>"
        + "".join(
            f"<tr><th scope=\"row\">{esc(case_id)}</th><td><code>{esc(json.dumps(result.get('provenance', {}), ensure_ascii=False, sort_keys=True))}</code></td></tr>"
            for case_id, result in sorted(results.items())
        )
        + "</tbody></table></div></body></html>\n"
    )


def _hash_bindings(artifacts: Any) -> dict[str, Any]:
    """Return computed and manifest-recorded hashes for one loaded case."""
    case_id = artifacts.case["case_id"]
    manifest = artifacts.manifest
    recorded_case = manifest["case_hashes"][case_id]
    computed_case = {
        "exact": exact_hash(artifacts.case_bytes),
        "semantic": semantic_hash(artifacts.case),
    }
    recorded = {
        "case": recorded_case,
        "authorization_input": manifest["authorization_input_hashes"][case_id],
        "review_submissions": sorted(manifest["review_submission_hashes"][case_id]),
        "final_authorization_sidecar": manifest["final_authorization_sidecar_hashes"][case_id],
        "reference": manifest["reference_hashes"][case_id],
        "adjudication": manifest["adjudication_hashes"][case_id],
        "raw_output": manifest["raw_output_hashes"][case_id],
    }
    approval = next((digest for event, digest in zip(artifacts.lifecycle_events, artifacts.lifecycle_event_hashes)
                     if event.get("event_type") == "approved"), None)
    computed = {
        "case": computed_case,
        "authorization_input": exact_hash(artifacts.authorization_input_bytes),
        "review_submissions": sorted(exact_hash(raw) for _, raw in artifacts.reviews_by_hash.values()),
        "final_authorization_sidecar": exact_hash(artifacts.sidecar_bytes),
        "reference": exact_hash(artifacts.reference_bytes),
        "adjudication": exact_hash(artifacts.adjudication_bytes),
        "approval_event": approval,
        "raw_output": exact_hash(artifacts.raw_output_bytes),
    }
    recorded["approval_event"] = manifest["approval_event_hashes"][case_id]
    return {
        name: {"recorded": recorded[name], "computed": computed[name], "matches": recorded[name] == computed[name]}
        for name in recorded
    }


def verify_bundle(bundle: Path, *, config_path: Path) -> dict[str, Any]:
    """Read-only hash and artifact-binding verification using the grading gate."""
    try:
        config: GovernanceConfig = load_governance_json(config_path)
        artifacts_by_case, scheduled = load_evaluation_bundle_v14(bundle, config.approver_id)
    except Exception as exc:
        raise EvaluationCLIError("verification_input_invalid:" + (str(exc) or "unknown")) from exc
    bundle_root = Path(bundle)
    bundle_index_bytes = (bundle_root / "bundle.json").read_bytes()
    bundle_index = loads_bytes(bundle_index_bytes)
    manifest_relative = Path(bundle_index["manifest"])
    manifest_path = (bundle_root / manifest_relative).resolve(strict=True)
    manifest_path.relative_to(bundle_root.resolve(strict=True))
    manifest_bytes = manifest_path.read_bytes()
    manifest_value = loads_bytes(manifest_bytes)
    bundle_hash = exact_hash(bundle_index_bytes)
    manifest_hash = exact_hash(manifest_bytes)
    manifest_exclusions = {
        item["case_id"]: item["reason"]
        for item in manifest_value.get("excluded_cases", [])
        if isinstance(item, dict) and isinstance(item.get("case_id"), str)
    }
    manifest_errors: list[str] = []
    retained_artifacts = (
        next(iter(artifacts_by_case.values())).manifest_artifacts_by_case
        if artifacts_by_case else {}
    )
    try:
        validate_manifest_v14(manifest_value, scheduled, retained_artifacts)
    except Exception as exc:
        manifest_errors.append(str(exc) or "manifest_validation_failed")
    case_checks: list[dict[str, Any]] = []
    all_verified = not manifest_errors
    for case_id in sorted(scheduled):
        artifacts = artifacts_by_case.get(case_id)
        if artifacts is None:
            case_checks.append({
                "case_id": case_id, "status": "not_executed",
                "reason": manifest_exclusions.get(case_id, "case_has_no_executed_artifact_entry"),
            })
            continue
        checked = grade_with_artifact_eligibility(artifacts)
        try:
            bindings = _hash_bindings(artifacts)
            mismatches = [name for name, item in bindings.items() if not item["matches"]]
        except Exception:
            bindings, mismatches = {}, ["hash_binding_computation_failed"]
        chain_valid = checked.result is not None
        if mismatches or not chain_valid:
            all_verified = False
        case_checks.append({
            "case_id": case_id,
            "status": "verified" if not mismatches and chain_valid else "failed",
            "hash_bindings": bindings,
            "mismatched_bindings": mismatches,
            "coordinator_refusal_code": checked.refusal_code or "",
            "coordinator_diagnostics": list(checked.diagnostics),
            "model_output_contract_valid": checked.result["contract_valid"] if checked.result else "not_evaluated",
            "model_output_exact_edit_set_valid": checked.result["exact_edit_set_valid"] if checked.result else "not_evaluated",
        })
    return {
        "schema_version": "acac-integrity-verification-1.0",
        "verification_status": "verified" if all_verified else "failed",
        "claim": "Recorded exact/semantic hashes and the existing artifact eligibility/binding chain were checked. This does not authenticate human identities or establish correctness beyond the supplied approved artifacts.",
        "bundle_index_sha256": bundle_hash,
        "manifest_sha256": manifest_hash,
        "manifest_validation_errors": manifest_errors,
        "scheduled_count": len(scheduled),
        "executed_count": len(artifacts_by_case),
        "cases": case_checks,
    }


def evaluate_bundle(
    bundle: Path,
    output_dir: Path,
    *,
    config_path: Path | None = None,
    synthetic_demo: bool = False,
    configured_approver_id: str | None = None,
) -> dict[str, Any]:
    """Run the existing artifact-bound coordinator and aggregate path."""
    if synthetic_demo:
        if configured_approver_id != "approver-1" or config_path is not None:
            raise EvaluationCLIError("synthetic_demo_configuration_invalid")
    else:
        if config_path is None:
            raise EvaluationCLIError("governance_config_required")
        try:
            config: GovernanceConfig = load_governance_json(config_path)
        except Exception as exc:
            raise EvaluationCLIError("governance_configuration_invalid") from exc
        configured_approver_id = config.approver_id
    try:
        artifacts, scheduled = load_evaluation_bundle_v14(bundle, configured_approver_id or "")
    except EvaluationBundleError as exc:
        raise EvaluationCLIError(str(exc)) from exc
    if not scheduled:
        raise EvaluationCLIError("empty_scheduled_run")
    try:
        aggregate = aggregate_report_v14(aggregate_artifact_run_v14(artifacts, scheduled))
    except Exception as exc:
        raise EvaluationCLIError("evaluation_aggregation_failed") from exc

    if aggregate["excluded_count"]:
        status = "ineligible"
    elif aggregate["structural_failure_count"]:
        status = "completed_with_structural_failures"
    else:
        status = "completed"
    run_id = artifacts[next(iter(artifacts))].manifest.get("run_id", "run") if artifacts else "run"
    edit_decisions = {}
    for case_id in sorted(scheduled):
        case_artifacts = artifacts.get(case_id)
        if case_artifacts is None:
            edit_decisions[case_id] = {
                "status": "not_evaluated_case_not_executed", "edits": [],
            }
        else:
            edit_decisions[case_id] = edit_decisions_v14(case_artifacts)
    report = {
        "schema_version": "acac-evaluation-report-1.0",
        "run_id": run_id,
        "status": status,
        "evidence_type": "synthetic demonstration" if synthetic_demo else "supplied artifact bundle",
        "aggregate": aggregate,
        "edit_decisions_by_case": edit_decisions,
    }
    output_root = Path(output_dir)
    name_suffix = hashlib.sha256(str(run_id).encode("utf-8")).hexdigest()[:12]
    json_path = output_root / f"evaluation-{name_suffix}.json"
    markdown_path = output_root / f"evaluation-{name_suffix}.md"
    html_path = output_root / f"evaluation-{name_suffix}.html"
    output_paths = (json_path, markdown_path, html_path)
    if len({path.resolve(strict=False) for path in output_paths}) != len(output_paths):
        raise EvaluationCLIError("report_paths_collide")
    json_bytes = (dumps(report)).encode("utf-8")
    markdown_bytes = _render_markdown(report).encode("utf-8")
    html_bytes = _render_html(report).encode("utf-8")
    if any(path.exists() for path in output_paths):
        raise EvaluationCLIError("report_already_exists")
    published: list[tuple[Path, bytes]] = []
    try:
        for path, content in zip(output_paths, (json_bytes, markdown_bytes, html_bytes)):
            _atomic_create(path, content)
            published.append((path, content))
    except Exception:
        # Do not leave a partial report set after a publication failure.
        for path, content in reversed(published):
            try:
                if path.is_file() and path.read_bytes() == content:
                    path.unlink()
            except OSError:
                pass
        raise
    return {
        "status": status,
        "run_id": run_id,
        "scheduled_count": aggregate["scheduled_count"],
        "included_count": aggregate["included_count"],
        "excluded_count": aggregate["excluded_count"],
        "structural_failure_count": aggregate["structural_failure_count"],
        "json_report": str(json_path),
        "markdown_report": str(markdown_path),
        "html_report": str(html_path),
    }
