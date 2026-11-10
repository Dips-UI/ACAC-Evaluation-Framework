"""Synthetic end-to-end tests for the v1.4 grading gate."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest

from acac.canonical import exact_hash, semantic_hash
from acac.coordinator_v14 import V14Artifacts, grade_with_artifact_eligibility
from tests.test_references_v14 import build_chain


def stored(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def event(event_type, ref, ref_hash, seq, previous, actor_id, role, evidence, extra=None):
    value = {
        "event_schema_version": "acac-lifecycle-1.1", "event_id": f"event-{seq}",
        "reference_id": ref["reference_id"], "reference_revision": ref["revision"],
        "reference_content_hash": ref_hash, "sequence": seq, "event_type": event_type,
        "actor": {"actor_id": actor_id, "role": role},
        "occurred_at": f"2026-11-01T00:00:{seq:02d}Z", "evidence_hashes": evidence,
        "reason": f"Synthetic {event_type}", "previous_event_hash": previous,
    }
    if extra:
        value.update(extra)
    raw = stored(value)
    return value, raw, exact_hash(raw)


def fixture(no_op=False, temporal=False, case_id="case-001", extra_protected=False,
            reference_id="ref-1", revision=1, input_revision_note=None, freeze=False,
            exception=False,
            exception_decision="authorized",
            multiple_original_conditions=False):
    case, case_bytes, auth, auth_bytes, ref, ref_bytes, sidecar, sidecar_bytes, reviews = build_chain(
        no_op=no_op, temporal=temporal, case_id=case_id, extra_protected=extra_protected,
        reference_id=reference_id, revision=revision, input_revision_note=input_revision_note,
        multiple_original_conditions=multiple_original_conditions, exception=exception,
    )
    review_hash, (review, review_bytes) = next(iter(reviews.items()))
    case_hash, input_hash = exact_hash(case_bytes), exact_hash(auth_bytes)
    sidecar_hash, ref_hash = exact_hash(sidecar_bytes), exact_hash(ref_bytes)
    adjudication = {
        "review_id": "adjudication-1", "case_id": case["case_id"],
        "reviewer_role": "adjudicator", "source_case_hash": case_hash,
        "authorization_input_hash": input_hash, "reference_id": ref["reference_id"],
        "reference_revision": ref["revision"], "reference_content_hash": ref_hash,
        "considered_review_hashes": [review_hash],
        "disagreement_disposition": [{"review_id": review["review_id"], "decision": "accepted"}],
        "decision_rationale": "Synthetic adjudication", "exception_decisions": ([{
            "exception_id": "e1", "exclusion_id": "x1", "key": ["L", "r1", "label"],
            "decision": exception_decision, "instruction_ids": ["notice-1"],
            "source_locations": ["/payload/notice/authority_text"], "evidence_ids": [],
            "rationale": "Synthetic adjudicator authority decision",
        }] if exception else []), "adjudicator_id": "adjudicator-1",
        "independence_declaration": True, "independence_basis": "Synthetic separate role",
        "completed_at": "2026-10-31T13:00:00Z",
    }
    adjudication_bytes = stored(adjudication)
    adjudication_hash = exact_hash(adjudication_bytes)
    event_values, event_bytes, event_hashes = [], [], []
    previous = ""
    definitions = [
        ("created", "author-1", "reference_author", [], None),
        ("reviewed", "reviewer-1", "human_reviewer", [review_hash], None),
        ("adjudicated", "adjudicator-1", "adjudicator", [review_hash, adjudication_hash], None),
        ("approved", "approver-1", "approver",
         [input_hash, sidecar_hash, review_hash, adjudication_hash, ref_hash],
         {"authorization_input_hash": input_hash,
          "final_authorization_sidecar_hash": sidecar_hash,
          "review_submission_hashes": [review_hash],
          "adjudication_hash": adjudication_hash,
          "approved_reference_hash": ref_hash}),
    ]
    for seq, (kind, actor, role, evidence, extra) in enumerate(definitions, 1):
        item, raw, digest = event(kind, ref, ref_hash, seq, previous, actor, role, evidence, extra)
        event_values.append(item)
        event_bytes.append(raw)
        event_hashes.append(digest)
        previous = digest
    output_bytes = stored(ref["expected_output"])
    retained = {
        "case": case_bytes, "raw_output": output_bytes, "authorization_input": auth_bytes,
        "review_submission_bytes": [review_bytes], "final_authorization_sidecar": sidecar_bytes,
        "reference": ref_bytes, "adjudication": adjudication_bytes, "approval_event": event_bytes[-1],
    }
    manifest = {
        "manifest_version": "1.4", "run_id": "run-1", "mode": "resolved_contract",
        "scheduled_case_ids": [case["case_id"]], "executed_case_ids": [case["case_id"]],
        "excluded_cases": [],
        "case_hashes": {case["case_id"]: {"exact": case_hash, "semantic": semantic_hash(case)}},
        "authorization_input_hashes": {case["case_id"]: input_hash},
        "review_submission_hashes": {case["case_id"]: [review_hash]},
        "final_authorization_sidecar_hashes": {case["case_id"]: sidecar_hash},
        "reference_hashes": {case["case_id"]: ref_hash},
        "adjudication_hashes": {case["case_id"]: adjudication_hash},
        "approval_event_hashes": {case["case_id"]: event_hashes[-1]},
        "raw_output_hashes": {case["case_id"]: exact_hash(output_bytes)},
        "prompt_hash": "sha256:" + "a" * 64, "configuration_hash": "sha256:" + "b" * 64,
        "grader_version": "acac-grader-1.4", "created_at": "2026-11-01T00:00:00Z",
        "model": {"provider": "synthetic", "family": "fixture", "model_id": "fixture",
                  "version": "1", "runtime_version": "1", "settings": {}},
    }
    artifacts = V14Artifacts(
        case, case_bytes, auth, auth_bytes, reviews, sidecar, sidecar_bytes,
        ref, ref_bytes, adjudication, adjudication_bytes, event_values, event_bytes,
        event_hashes, output_bytes, manifest, stored(manifest), {case["case_id"]},
        {case["case_id"]: retained}, "author-1", "approver-1",
    )
    if freeze:
        manifest_hash = exact_hash(artifacts.manifest_bytes)
        frozen, frozen_bytes, frozen_hash = event(
            "frozen", ref, ref_hash, len(event_values) + 1, event_hashes[-1],
            "approver-1", "approver", [manifest_hash],
            {"run_id": manifest["run_id"], "manifest_hash": manifest_hash},
        )
        artifacts = replace(
            artifacts,
            lifecycle_events=[*event_values, frozen],
            lifecycle_event_bytes=[*event_bytes, frozen_bytes],
            lifecycle_event_hashes=[*event_hashes, frozen_hash],
        )
    return artifacts


class CoordinatorV14Tests(unittest.TestCase):
    def test_coordinator_refuses_eligibility_omission_before_grading(self):
        artifacts = fixture()
        bad_input = deepcopy(artifacts.authorization_input)
        resolution = bad_input
        resolution["eligible_keys"] = []
        resolution["eligibility_rationale"] = []
        resolution["required_final_values"] = []
        resolution["preservation_keys"] = [["L", "r1", "label"]]
        resolution["rationale_by_key"] = []
        bad_artifacts = replace(
            artifacts, authorization_input=bad_input,
            authorization_input_bytes=stored(bad_input),
        )

        result = grade_with_artifact_eligibility(bad_artifacts)

        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "malformed_artifact")
        self.assertIn("eligible_key_missing_from_scope", result.diagnostics)

    def test_coordinator_refuses_missing_rationale_coverage_before_grading(self):
        artifacts = fixture()
        bad_input = deepcopy(artifacts.authorization_input)
        bad_input["rationale_by_key"] = []
        bad_artifacts = replace(
            artifacts, authorization_input=bad_input,
            authorization_input_bytes=stored(bad_input),
        )
        result = grade_with_artifact_eligibility(bad_artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "malformed_artifact")
        self.assertIn("rationale_by_key_coverage", result.diagnostics)

    def test_resolved_approved_chain_produces_bound_grade(self):
        result = grade_with_artifact_eligibility(fixture())
        self.assertTrue(result.eligible, result.diagnostics)
        self.assertTrue(result.result["contract_valid"])
        self.assertTrue(result.result["exact_edit_set_valid"])
        self.assertEqual(result.result["schema_version"], "acac-1.4")
        self.assertIn("edit_0:isolation_valid", result.result["diagnostics"])

    def test_semantic_hash_is_sensitive_to_linked_artifact_values_and_empty_members(self):
        chains = (fixture(exception=True, temporal=True, freeze=True), fixture(no_op=True))
        bundles = []
        for artifacts in chains:
            grade = grade_with_artifact_eligibility(artifacts)
            self.assertTrue(grade.eligible, grade.diagnostics)
            bundles.append({
                "grading_result": grade.result,
                "case": artifacts.case,
                "authorization_input": artifacts.authorization_input,
                "reviews": [review for review, _ in artifacts.reviews_by_hash.values()],
                "sidecar": artifacts.sidecar,
                "reference": artifacts.reference,
                "adjudication": artifacts.adjudication,
                "lifecycle_events": artifacts.lifecycle_events,
                "raw_output": json.loads(artifacts.raw_output_bytes),
                "manifest": artifacts.manifest,
            })
        baseline = semantic_hash(bundles)
        sorted_array_items = {
            "evidence_registry": {"evidence_id": "synthetic"},
            "predicate_definitions": {"predicate_id": "synthetic"},
            "exclusions": {"exclusion_id": "synthetic"},
            "exceptions_applied": {"exception_id": "synthetic"},
            "resolution_issues": {"issue_id": "synthetic"},
            "excluded_cases": {"case_id": "synthetic"},
            "exception_decisions": {
                "exception_id": "synthetic", "exclusion_id": "synthetic",
                "key": ["L", "record", "field"],
            },
            "temporal_rules": {
                "source_location": "/payload/temporal_conditions/0",
                "occurrence_index": 0, "rule_id": "synthetic",
            },
            "edits": {"table": "L", "record_id": "record", "field": "field"},
            "field_declarations": {"table": "L", "field": "field"},
        }

        def mutations(value, path=()):
            if isinstance(value, dict):
                if not value:
                    yield path, {"synthetic_member": "changed"}
                for key, child in value.items():
                    for child_path, changed in mutations(child, path + (key,)):
                        variant = deepcopy(value)
                        variant[key] = changed
                        yield child_path, variant
            elif isinstance(value, list):
                if not value:
                    name = path[-1] if path else None
                    if name in {"eligible_keys", "preservation_keys"}:
                        item = [["L", "record", "field"]]
                    elif name in {"scheduled_case_ids", "executed_case_ids", "review_submission_hashes"}:
                        item = ["sha256:" + "0" * 64 if name == "review_submission_hashes" else "synthetic"]
                    elif name in {"L", "M", "H", "W"}:
                        item = [{"record_id": "synthetic"}]
                    elif name in sorted_array_items:
                        item = [sorted_array_items[name]]
                    else:
                        item = ["synthetic"]
                    yield path, item
                for index, child in enumerate(value):
                    for child_path, changed in mutations(child, path + (index,)):
                        variant = deepcopy(value)
                        variant[index] = changed
                        yield child_path, variant
            elif isinstance(value, str):
                yield path, value + "#changed"
            elif isinstance(value, bool):
                yield path, not value
            elif isinstance(value, int):
                yield path, value + 1

        changed_members = 0
        for path, changed_bundle in mutations(bundles):
            with self.subTest(field_path=path):
                self.assertNotEqual(baseline, semantic_hash(changed_bundle))
            changed_members += 1
        self.assertGreater(changed_members, 0)

    def test_no_op_chain_remains_fully_validated_and_has_empty_authorization(self):
        artifacts = fixture(no_op=True)
        self.assertEqual(artifacts.authorization_input["eligible_keys"], [])
        self.assertEqual(artifacts.authorization_input["required_final_values"], [])
        self.assertEqual(artifacts.reference["expected_output"]["edits"], [])
        result = grade_with_artifact_eligibility(artifacts)
        self.assertTrue(result.eligible, result.diagnostics)

    def test_each_generated_result_provenance_member_is_hash_sensitive(self):
        result = grade_with_artifact_eligibility(fixture(freeze=True))
        self.assertTrue(result.eligible, result.diagnostics)
        baseline = result.result
        provenance = baseline["provenance"]
        baseline_hash = semantic_hash(baseline)

        for member, value in provenance.items():
            with self.subTest(member=member):
                changed = deepcopy(baseline)
                current = changed["provenance"][member]
                if isinstance(current, list):
                    self.assertTrue(current)
                    current[0] = current[0] + "#changed"
                else:
                    self.assertIsInstance(current, str)
                    changed["provenance"][member] = current + "#changed"
                self.assertNotEqual(baseline_hash, semantic_hash(changed))

    def test_exception_override_requires_hash_bound_adjudication_decision(self):
        artifacts = fixture(exception=True)
        result = grade_with_artifact_eligibility(artifacts)
        self.assertTrue(result.eligible, result.diagnostics)

        missing = deepcopy(artifacts.adjudication)
        missing["exception_decisions"] = []
        refused = grade_with_artifact_eligibility(replace(
            artifacts, adjudication=missing, adjudication_bytes=stored(missing),
        ))
        self.assertFalse(refused.eligible)
        self.assertEqual(refused.refusal_code, "adjudication_invalid")
        self.assertIn("exception_decision_coverage_mismatch", refused.diagnostics)

        refusal_by_decision = {
            "not_authorized": "exception_not_authorized",
            "unresolved": "exception_authority_unresolved",
        }
        for decision, expected_code in refusal_by_decision.items():
            with self.subTest(decision=decision):
                negative = fixture(exception=True, exception_decision=decision)
                adjudication_hash = exact_hash(negative.adjudication_bytes)
                adjudication_event = next(
                    item for item in negative.lifecycle_events if item["event_type"] == "adjudicated"
                )
                self.assertIn(adjudication_hash, adjudication_event["evidence_hashes"])
                refused_negative = grade_with_artifact_eligibility(negative)
                self.assertFalse(refused_negative.eligible)
                self.assertIsNone(refused_negative.result)
                self.assertEqual(refused_negative.refusal_code, expected_code)
                self.assertIn(expected_code, refused_negative.diagnostics)

        malformed = deepcopy(artifacts.adjudication)
        malformed["exception_decisions"][0]["decision"] = "invalid_decision"
        malformed_result = grade_with_artifact_eligibility(replace(
            artifacts, adjudication=malformed, adjudication_bytes=stored(malformed),
        ))
        self.assertFalse(malformed_result.eligible)
        self.assertIsNone(malformed_result.result)
        self.assertEqual(malformed_result.refusal_code, "adjudication_invalid")
        self.assertIn("exception_decision_value_invalid", malformed_result.diagnostics)

        self.assertTrue(result.result["contract_valid"])
        self.assertTrue(result.result["exact_edit_set_valid"])

    def test_new_input_revision_requires_fresh_reference_and_review_bindings(self):
        previous = fixture()
        revised = fixture(
            case_id=previous.case["case_id"], reference_id="ref-2", revision=2,
            input_revision_note="Fresh authorization input revision",
        )
        self.assertNotEqual(exact_hash(previous.authorization_input_bytes), exact_hash(revised.authorization_input_bytes))
        accepted = grade_with_artifact_eligibility(revised)
        self.assertTrue(accepted.eligible, accepted.diagnostics)

        stale_review_chain = replace(revised, reviews_by_hash=previous.reviews_by_hash)
        rejected = grade_with_artifact_eligibility(stale_review_chain)
        self.assertFalse(rejected.eligible)
        self.assertIsNone(rejected.result)
        self.assertEqual(rejected.refusal_code, "review_invalid")

    def test_new_input_revision_rejects_each_stale_downstream_artifact(self):
        previous = fixture()
        revised = fixture(
            case_id=previous.case["case_id"], reference_id="ref-2", revision=2,
            input_revision_note="Fresh authorization input revision",
        )
        stale_variants = (
            ("review", replace(revised, reviews_by_hash=previous.reviews_by_hash), "review_invalid"),
            ("sidecar", replace(revised, sidecar=previous.sidecar, sidecar_bytes=previous.sidecar_bytes), "sidecar_invalid"),
            ("adjudication", replace(revised, adjudication=previous.adjudication,
                                      adjudication_bytes=previous.adjudication_bytes), "adjudication_invalid"),
            ("lifecycle", replace(revised, lifecycle_events=previous.lifecycle_events,
                                   lifecycle_event_bytes=previous.lifecycle_event_bytes,
                                   lifecycle_event_hashes=previous.lifecycle_event_hashes), "manifest_invalid"),
            ("manifest", replace(revised, manifest=previous.manifest,
                                  manifest_bytes=previous.manifest_bytes,
                                  manifest_artifacts_by_case=previous.manifest_artifacts_by_case), "manifest_invalid"),
        )
        for name, artifacts, expected in stale_variants:
            with self.subTest(artifact=name):
                result = grade_with_artifact_eligibility(artifacts)
                self.assertFalse(result.eligible)
                self.assertIsNone(result.result)
                self.assertEqual(result.refusal_code, expected)

    def test_superseded_frozen_reference_remains_bound_only_to_prior_run(self):
        previous = fixture(freeze=True)
        replacement = fixture(
            case_id=previous.case["case_id"], reference_id="ref-2", revision=2,
            input_revision_note="Fresh replacement input",
        )
        replacement_hash = exact_hash(replacement.reference_bytes)
        previous_hash = previous.lifecycle_event_hashes[-1]
        superseded, superseded_bytes, superseded_hash = event(
            "superseded", previous.reference, exact_hash(previous.reference_bytes),
            len(previous.lifecycle_events) + 1, previous_hash,
            "approver-1", "approver", [replacement_hash],
            {"replacement_reference_id": replacement.reference["reference_id"],
             "replacement_reference_hash": replacement_hash},
        )
        previous = replace(
            previous,
            lifecycle_events=[*previous.lifecycle_events, superseded],
            lifecycle_event_bytes=[*previous.lifecycle_event_bytes, superseded_bytes],
            lifecycle_event_hashes=[*previous.lifecycle_event_hashes, superseded_hash],
            additional_retained_artifacts={replacement_hash: replacement.reference_bytes},
        )
        lifecycle_semantic_hash = semantic_hash(previous.lifecycle_events)
        changed_replacement_id = deepcopy(previous.lifecycle_events)
        changed_replacement_id[-1]["replacement_reference_id"] += "-changed"
        self.assertNotEqual(lifecycle_semantic_hash, semantic_hash(changed_replacement_id))
        changed_replacement_hash = deepcopy(previous.lifecycle_events)
        changed_replacement_hash[-1]["replacement_reference_hash"] = "sha256:" + "0" * 64
        self.assertNotEqual(lifecycle_semantic_hash, semantic_hash(changed_replacement_hash))

        prior_run = grade_with_artifact_eligibility(previous)
        self.assertTrue(prior_run.eligible, prior_run.diagnostics)
        self.assertEqual(prior_run.result["provenance"]["reference_governance_status"], "frozen")

        original_manifest_hash = exact_hash(previous.manifest_bytes)
        original_manifest_bytes = previous.manifest_bytes
        changed_manifest = deepcopy(previous.manifest)
        changed_manifest["run_id"] = "run-2"
        retained = dict(previous.additional_retained_artifacts)
        retained[original_manifest_hash] = original_manifest_bytes
        other_run = replace(
            previous, manifest=changed_manifest, manifest_bytes=stored(changed_manifest),
            additional_retained_artifacts=retained,
        )
        rejected = grade_with_artifact_eligibility(other_run)
        self.assertFalse(rejected.eligible)
        self.assertEqual(rejected.refusal_code, "lifecycle_invalid")
        self.assertIn("run_specific_freeze_binding_missing", rejected.diagnostics)

    def test_temporal_chain_requires_and_accepts_complete_reconciliation(self):
        temporal_fixture = fixture(temporal=True, multiple_original_conditions=True)
        self.assertEqual(
            [item["instruction_id"] for item in temporal_fixture.case["payload"]["temporal_conditions"]],
            ["notice-1", "original", "original"],
        )
        self.assertEqual(
            [rule["source_condition_id"] for rule in temporal_fixture.authorization_input["temporal_rules"]],
            ["condition-1", "original-condition-1", "original-condition-2"],
        )
        result = grade_with_artifact_eligibility(temporal_fixture)
        self.assertTrue(result.eligible, result.diagnostics)
        self.assertTrue(result.result["exact_edit_set_valid"])

        broken_sidecar = deepcopy(temporal_fixture.sidecar)
        broken_sidecar["temporal_reconciliation"]["status"] = "failed"
        object.__setattr__(temporal_fixture, "sidecar", broken_sidecar)
        object.__setattr__(temporal_fixture, "sidecar_bytes", stored(broken_sidecar))
        result = grade_with_artifact_eligibility(temporal_fixture)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "temporal_reconciliation_failed")

        malformed_time_fixture = fixture(temporal=True)
        malformed_time = deepcopy(malformed_time_fixture.sidecar)
        malformed_time["temporal_reconciliation"]["checked_at"] = "not-a-timestamp"
        object.__setattr__(malformed_time_fixture, "sidecar", malformed_time)
        object.__setattr__(malformed_time_fixture, "sidecar_bytes", stored(malformed_time))
        result = grade_with_artifact_eligibility(malformed_time_fixture)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "temporal_reconciliation_failed")

    def test_status_bearing_pre_review_input_is_rejected(self):
        artifacts = fixture()
        auth = deepcopy(artifacts.authorization_input)
        auth["resolution_status"] = "resolved"
        object.__setattr__(artifacts, "authorization_input", auth)
        object.__setattr__(artifacts, "authorization_input_bytes", stored(auth))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "malformed_artifact")
        self.assertIn("invalid_members", result.diagnostics)

    def test_unresolved_and_quarantined_final_sidecars_are_refused(self):
        for status, expected in (("ambiguous", "unresolved_authorization"), ("quarantined", "quarantined_authorization")):
            with self.subTest(status=status):
                artifacts = fixture()
                sidecar = deepcopy(artifacts.sidecar)
                for member in (
                    "governing_instruction_ids", "predicate_definitions", "evidence_registry",
                    "eligible_keys", "eligibility_rationale", "exclusions", "exceptions_applied",
                    "required_final_values", "preservation_keys", "rationale_by_key",
                    "governing_event", "temporal_rules", "temporal_reconciliation",
                ):
                    sidecar.pop(member, None)
                sidecar["resolution_status"] = status
                sidecar["resolution_issues"] = [{
                    "issue_id": "issue-1", "category": "unclear", "source_location": "/payload",
                    "description": "Synthetic unresolved review issue", "evidence_ids": [],
                }]
                object.__setattr__(artifacts, "sidecar", sidecar)
                object.__setattr__(artifacts, "sidecar_bytes", stored(sidecar))
                result = grade_with_artifact_eligibility(artifacts)
                self.assertFalse(result.eligible)
                self.assertEqual(result.refusal_code, expected)

    def test_missing_authorization_evidence_is_refused(self):
        artifacts = fixture()
        object.__setattr__(artifacts, "authorization_input_bytes", None)
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "missing_artifact")

    def test_retained_object_and_manifest_bindings_are_refused(self):
        artifacts = fixture()
        case = deepcopy(artifacts.case)
        case["case_id"] = "different-case"
        object.__setattr__(artifacts, "case", case)
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "malformed_artifact")
        self.assertIn("retained_value_mismatch", result.diagnostics)

        artifacts = fixture()
        object.__setattr__(artifacts, "manifest_artifacts_by_case", {})
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "manifest_invalid")
        self.assertIn("current_case_artifact_bytes_missing", result.diagnostics)

        artifacts = fixture()
        retained = deepcopy(artifacts.manifest_artifacts_by_case)
        retained[artifacts.case["case_id"]]["raw_output"] = b'{"edits":[]}'
        object.__setattr__(artifacts, "manifest_artifacts_by_case", retained)
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "manifest_invalid")
        self.assertIn("current_case_raw_output_binding_mismatch", result.diagnostics)

        artifacts = fixture()
        manifest = deepcopy(artifacts.manifest)
        manifest["executed_case_ids"] = []
        object.__setattr__(artifacts, "manifest", manifest)
        object.__setattr__(artifacts, "manifest_bytes", stored(manifest))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "manifest_invalid")
        self.assertIn("case_not_executed", result.diagnostics)

    def test_missing_and_invalid_human_reviews_have_distinct_refusals(self):
        artifacts = fixture()
        object.__setattr__(artifacts, "reviews_by_hash", {})
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "review_missing")

        artifacts = fixture()
        digest, (review, raw) = next(iter(artifacts.reviews_by_hash.items()))
        invalid_review = deepcopy(review)
        invalid_review["reviewer_role"] = "ai_auditor"
        object.__setattr__(artifacts, "reviews_by_hash", {digest: (invalid_review, raw)})
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "review_invalid")

        artifacts = fixture()
        original = next(iter(artifacts.reviews_by_hash.values()))[0]
        extra = deepcopy(original)
        extra["review_id"] = "review-extra"
        extra_bytes = stored(extra)
        extra_hash = exact_hash(extra_bytes)
        reviews = dict(artifacts.reviews_by_hash)
        reviews[extra_hash] = (extra, extra_bytes)
        object.__setattr__(artifacts, "reviews_by_hash", reviews)
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "review_invalid")
        self.assertIn("review_artifact_set_mismatch", result.diagnostics)

    def test_unsupported_version_and_malformed_retained_json_are_refused(self):
        artifacts = fixture()
        auth = deepcopy(artifacts.authorization_input)
        auth["schema_version"] = "acac-auth-input-unsupported"
        object.__setattr__(artifacts, "authorization_input", auth)
        object.__setattr__(artifacts, "authorization_input_bytes", stored(auth))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "unsupported_version")

        artifacts = fixture()
        object.__setattr__(artifacts, "case_bytes", b'{"case":')
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "malformed_artifact")

        artifacts = fixture()
        object.__setattr__(artifacts, "manifest", [])
        object.__setattr__(artifacts, "manifest_bytes", b"[]")
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "manifest_invalid")

        artifacts = fixture()
        object.__setattr__(
            artifacts, "manifest_bytes",
            b'{"manifest_version":"1.4","manifest_version":"1.4"}',
        )
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "malformed_artifact")

    def test_artifact_hash_and_binding_mismatches_use_distinct_refusals(self):
        artifacts = fixture()
        auth = deepcopy(artifacts.authorization_input)
        auth["source_case_hash"] = "sha256:" + "0" * 64
        object.__setattr__(artifacts, "authorization_input", auth)
        object.__setattr__(artifacts, "authorization_input_bytes", stored(auth))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "binding_mismatch")

        artifacts = fixture()
        review_hash, review_pair = next(iter(artifacts.reviews_by_hash.items()))
        object.__setattr__(artifacts, "reviews_by_hash", {"sha256:" + "0" * 64: review_pair})
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "hash_mismatch")

        artifacts = fixture()
        manifest = deepcopy(artifacts.manifest)
        manifest["raw_output_hashes"][artifacts.case["case_id"]] = "sha256:" + "0" * 64
        object.__setattr__(artifacts, "manifest", manifest)
        object.__setattr__(artifacts, "manifest_bytes", stored(manifest))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "hash_mismatch")

    def test_invalid_adjudication_and_missing_approval_have_distinct_refusals(self):
        artifacts = fixture()
        adjudication = deepcopy(artifacts.adjudication)
        adjudication["independence_declaration"] = "true"
        object.__setattr__(artifacts, "adjudication", adjudication)
        object.__setattr__(artifacts, "adjudication_bytes", stored(adjudication))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "adjudication_invalid")

        artifacts = fixture()
        object.__setattr__(artifacts, "lifecycle_events", artifacts.lifecycle_events[:-1])
        object.__setattr__(artifacts, "lifecycle_event_bytes", artifacts.lifecycle_event_bytes[:-1])
        object.__setattr__(artifacts, "lifecycle_event_hashes", artifacts.lifecycle_event_hashes[:-1])
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "approval_missing")

    def test_reference_author_cannot_be_configured_approver(self):
        artifacts = fixture()
        events = deepcopy(artifacts.lifecycle_events)
        approval = events[-1]
        approval["actor"]["actor_id"] = "author-1"
        approval_raw = stored(approval)
        approval_hash = exact_hash(approval_raw)
        raw_events = list(artifacts.lifecycle_event_bytes)
        event_hashes = list(artifacts.lifecycle_event_hashes)
        raw_events[-1], event_hashes[-1] = approval_raw, approval_hash
        retained = deepcopy(artifacts.manifest_artifacts_by_case)
        retained[artifacts.case["case_id"]]["approval_event"] = approval_raw
        manifest = deepcopy(artifacts.manifest)
        manifest["approval_event_hashes"][artifacts.case["case_id"]] = approval_hash
        object.__setattr__(artifacts, "lifecycle_events", events)
        object.__setattr__(artifacts, "lifecycle_event_bytes", raw_events)
        object.__setattr__(artifacts, "lifecycle_event_hashes", event_hashes)
        object.__setattr__(artifacts, "manifest_artifacts_by_case", retained)
        object.__setattr__(artifacts, "manifest", manifest)
        object.__setattr__(artifacts, "manifest_bytes", stored(manifest))
        object.__setattr__(artifacts, "configured_approver_id", "author-1")
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "approver_not_distinct")

    def test_reference_input_mismatch_is_refused(self):
        artifacts = fixture()
        reference = deepcopy(artifacts.reference)
        reference["authorization_input_hash"] = "sha256:" + "0" * 64
        object.__setattr__(artifacts, "reference", reference)
        object.__setattr__(artifacts, "reference_bytes", stored(reference))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "binding_mismatch")

    def test_invalid_reference_is_refused_after_rebinding_review_evidence(self):
        artifacts = fixture()
        reference = deepcopy(artifacts.reference)
        reference["rationale"] = 7
        reference_bytes = stored(reference)
        reference_hash = exact_hash(reference_bytes)

        reviews = {}
        review_hashes = []
        for _, (review_value, _) in artifacts.reviews_by_hash.items():
            review = deepcopy(review_value)
            review["reference_content_hash"] = reference_hash
            review_bytes = stored(review)
            digest = exact_hash(review_bytes)
            review_hashes.append(digest)
            reviews[digest] = (review, review_bytes)

        sidecar = deepcopy(artifacts.sidecar)
        sidecar["review_submission_hashes"] = review_hashes
        for provenance in sidecar["resolved_by"]:
            provenance["review_submission_hash"] = review_hashes[0]
        sidecar_bytes = stored(sidecar)

        object.__setattr__(artifacts, "reference", reference)
        object.__setattr__(artifacts, "reference_bytes", reference_bytes)
        object.__setattr__(artifacts, "reviews_by_hash", reviews)
        object.__setattr__(artifacts, "sidecar", sidecar)
        object.__setattr__(artifacts, "sidecar_bytes", sidecar_bytes)
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "reference_invalid")

    def test_sidecar_reference_chain_mismatch_is_refused(self):
        artifacts = fixture()
        sidecar = deepcopy(artifacts.sidecar)
        sidecar["authorization_input_hash"] = "sha256:" + "0" * 64
        object.__setattr__(artifacts, "sidecar", sidecar)
        object.__setattr__(artifacts, "sidecar_bytes", stored(sidecar))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "sidecar_invalid")

    def test_approval_event_must_bind_validated_artifact_hashes(self):
        artifacts = fixture()
        approval = deepcopy(artifacts.lifecycle_events[-1])
        approval["authorization_input_hash"] = "sha256:" + "0" * 64
        raw = stored(approval)
        digest = exact_hash(raw)
        events = list(artifacts.lifecycle_events)
        raws = list(artifacts.lifecycle_event_bytes)
        hashes = list(artifacts.lifecycle_event_hashes)
        events[-1], raws[-1], hashes[-1] = approval, raw, digest
        object.__setattr__(artifacts, "lifecycle_events", events)
        object.__setattr__(artifacts, "lifecycle_event_bytes", raws)
        object.__setattr__(artifacts, "lifecycle_event_hashes", hashes)
        retained = deepcopy(artifacts.manifest_artifacts_by_case)
        retained[artifacts.case["case_id"]]["approval_event"] = raw
        object.__setattr__(artifacts, "manifest_artifacts_by_case", retained)
        manifest = deepcopy(artifacts.manifest)
        manifest["approval_event_hashes"][artifacts.case["case_id"]] = digest
        object.__setattr__(artifacts, "manifest", manifest)
        object.__setattr__(artifacts, "manifest_bytes", stored(manifest))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "lifecycle_invalid")

    def test_approval_must_bind_every_review_listed_by_sidecar(self):
        artifacts = fixture()
        original_hash, (original, _) = next(iter(artifacts.reviews_by_hash.items()))
        extra_review = deepcopy(original)
        extra_review["review_id"] = "review-2"
        extra_bytes = stored(extra_review)
        extra_hash = exact_hash(extra_bytes)
        reviews = dict(artifacts.reviews_by_hash)
        reviews[extra_hash] = (extra_review, extra_bytes)

        sidecar = deepcopy(artifacts.sidecar)
        sidecar["review_submission_hashes"] = [original_hash, extra_hash]
        original_provenance = deepcopy(sidecar["resolved_by"][0])
        extra_provenance = deepcopy(original_provenance)
        extra_provenance["review_submission_hash"] = extra_hash
        sidecar["resolved_by"].append(extra_provenance)
        sidecar_bytes = stored(sidecar)
        sidecar_hash = exact_hash(sidecar_bytes)

        adjudication = deepcopy(artifacts.adjudication)
        adjudication["considered_review_hashes"] = [original_hash, extra_hash]
        adjudication["disagreement_disposition"].append({"review_id": "review-2", "decision": "accepted"})
        adjudication_bytes = stored(adjudication)
        adjudication_hash = exact_hash(adjudication_bytes)

        events, raw_events, event_hashes = [], [], []
        previous = ""
        for sequence, source in enumerate(artifacts.lifecycle_events, 1):
            item = deepcopy(source)
            if item["event_type"] == "reviewed":
                item["evidence_hashes"] = [original_hash, extra_hash]
            elif item["event_type"] == "adjudicated":
                item["evidence_hashes"] = [original_hash, extra_hash, adjudication_hash]
            elif item["event_type"] == "approved":
                # Deliberately omit extra_hash while keeping the approval event
                # internally valid; the coordinator must catch the sidecar mismatch.
                item["authorization_input_hash"] = exact_hash(artifacts.authorization_input_bytes)
                item["final_authorization_sidecar_hash"] = sidecar_hash
                item["review_submission_hashes"] = [original_hash]
                item["adjudication_hash"] = adjudication_hash
                item["approved_reference_hash"] = exact_hash(artifacts.reference_bytes)
                item["evidence_hashes"] = [
                    item["authorization_input_hash"], sidecar_hash, original_hash,
                    adjudication_hash, item["approved_reference_hash"],
                ]
            item["previous_event_hash"] = previous
            raw = stored(item)
            digest = exact_hash(raw)
            events.append(item)
            raw_events.append(raw)
            event_hashes.append(digest)
            previous = digest

        retained = deepcopy(artifacts.manifest_artifacts_by_case)
        retained_case = retained[artifacts.case["case_id"]]
        retained_case["review_submission_bytes"] = [
            raw for _, raw in reviews.values()
        ]
        retained_case["final_authorization_sidecar"] = sidecar_bytes
        retained_case["adjudication"] = adjudication_bytes
        retained_case["approval_event"] = raw_events[-1]
        object.__setattr__(artifacts, "reviews_by_hash", reviews)
        object.__setattr__(artifacts, "sidecar", sidecar)
        object.__setattr__(artifacts, "sidecar_bytes", sidecar_bytes)
        object.__setattr__(artifacts, "adjudication", adjudication)
        object.__setattr__(artifacts, "adjudication_bytes", adjudication_bytes)
        object.__setattr__(artifacts, "lifecycle_events", events)
        object.__setattr__(artifacts, "lifecycle_event_bytes", raw_events)
        object.__setattr__(artifacts, "lifecycle_event_hashes", event_hashes)
        object.__setattr__(artifacts, "manifest_artifacts_by_case", retained)

        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "binding_mismatch")
        self.assertIn("approval_artifact_binding_mismatch", result.diagnostics)

    def test_wrong_configured_approver_is_refused(self):
        artifacts = fixture()
        object.__setattr__(artifacts, "configured_approver_id", "different-approver")
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "lifecycle_invalid")

    def test_frozen_reference_requires_matching_run_and_manifest_binding(self):
        artifacts = fixture()
        manifest_hash = exact_hash(artifacts.manifest_bytes)
        freeze, raw, digest = event(
            "frozen", artifacts.reference, exact_hash(artifacts.reference_bytes), 5,
            artifacts.lifecycle_event_hashes[-1], "approver-1", "approver", [manifest_hash],
            {"run_id": "different-run", "manifest_hash": manifest_hash},
        )
        object.__setattr__(artifacts, "lifecycle_events", [*artifacts.lifecycle_events, freeze])
        object.__setattr__(artifacts, "lifecycle_event_bytes", [*artifacts.lifecycle_event_bytes, raw])
        object.__setattr__(artifacts, "lifecycle_event_hashes", [*artifacts.lifecycle_event_hashes, digest])
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertIsNone(result.result)
        self.assertEqual(result.refusal_code, "lifecycle_invalid")
        self.assertIn("freeze_manifest_run_mismatch", result.diagnostics)

    def test_excluded_case_cannot_produce_grade(self):
        artifacts = fixture()
        manifest = deepcopy(artifacts.manifest)
        manifest["excluded_cases"] = [{"case_id": artifacts.case["case_id"], "reason": "missing_artifact"}]
        object.__setattr__(artifacts, "manifest", manifest)
        object.__setattr__(artifacts, "manifest_bytes", stored(manifest))
        result = grade_with_artifact_eligibility(artifacts)
        self.assertFalse(result.eligible)
        self.assertEqual(result.refusal_code, "manifest_invalid")

    def test_structurally_invalid_model_output_gets_tagged_invalid_result(self):
        artifacts = fixture()
        invalid_patch = deepcopy(artifacts.reference["expected_output"])
        invalid_patch["edits"][0]["old_value"] = "stale synthetic value"
        raw = stored(invalid_patch)
        object.__setattr__(artifacts, "raw_output_bytes", raw)
        manifest = deepcopy(artifacts.manifest)
        manifest["raw_output_hashes"][artifacts.case["case_id"]] = exact_hash(raw)
        object.__setattr__(artifacts, "manifest", manifest)
        object.__setattr__(artifacts, "manifest_bytes", stored(manifest))
        retained = deepcopy(artifacts.manifest_artifacts_by_case)
        retained[artifacts.case["case_id"]]["raw_output"] = raw
        object.__setattr__(artifacts, "manifest_artifacts_by_case", retained)
        result = grade_with_artifact_eligibility(artifacts)
        self.assertTrue(result.eligible, result.diagnostics)
        self.assertFalse(result.result["contract_valid"])
        self.assertFalse(result.result["exact_edit_set_valid"])
        self.assertIn("edit_0:isolation_invalid:stale_old_value", result.result["diagnostics"])
        self.assertEqual(
            result.result["metrics"]["preservation_accuracy"],
            {"status": "not_applicable", "reason": "structural_invalidity"},
        )


if __name__ == "__main__":
    unittest.main()
