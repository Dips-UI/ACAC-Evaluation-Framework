# ACAC v1 Implementation Checklist

This checklist converts the mandatory requirements in `docs/product_requirements_v1.3.8.md` into verifiable implementation work. The specification remains authoritative. The five owner decisions listed in Sections 11 and 15 are treated as accepted and resolved for implementation planning.

Each checkbox is complete only when its stated artifact, behavior, and automated test evidence exist. No checklist item authorizes benchmark execution, production writes, model calls, or access to private review/gold data.

## Phase 0 — resolved decisions, boundaries, and repository controls

- [ ] Record the accepted human approver identity/role in the local governance configuration; test that approval is rejected when the approver is absent or is the reference author.
- [ ] Record Apache-2.0 as the package license; test that package metadata and distribution files use the accepted license.
- [ ] Configure signed 64-bit annotation integers (`[-9223372036854775808, 9223372036854775807]`); test both bounds and one-value overflows.
- [ ] Configure predicate limits of 8 levels and 64 nodes per definition; test boundary acceptance, overflow rejection, and independent per-definition counting.
- [ ] Record the accepted controlled-directory access and backup policy; test that trusted artifacts are read from the controlled location and that hash verification detects replacement.
- [ ] Enforce the product boundary: local CLI/Python API, pure in-memory application, deterministic grading, hashing, manifests, JSON/Markdown reports, and offline tests only; test that no production-write or provider-client path exists.
- [ ] Mark EvalScope, annotation-platform integrations, CSV import, dashboards, direct execution, rollback, multi-reference scoring, nested values, and model-provider clients as deferred; test that no deferred feature is required by V1 imports or commands.

## Phase 1 — strict parsing and primitive validation

- [ ] Implement strict UTF-8 JSON parsing with no trailing content, duplicate object-member rejection, non-finite-number rejection, and JSON null rejection; test each failure.
- [ ] Implement exact string comparison without trimming or Unicode normalization; test leading/trailing whitespace and canonically equivalent Unicode strings.
- [ ] Implement scalar type validation for `string`, `integer`, and `boolean`; test Boolean/integer distinction and rejection of objects, arrays, and nulls.
- [ ] Implement canonical integer lexical validation: `0` or `-?[1-9][0-9]*`; reject `-0`, `+2`, leading zeros, decimal points, and exponents; test signed 64-bit bounds.
- [ ] Implement RFC 3339 timestamp parsing with explicit offsets, `Z` support, leap-second rejection, naive-timestamp rejection, UTC instant comparison, and source-spelling preservation; test valid and invalid forms.
- [ ] Implement exact SHA-256 over stored bytes and expose the original bytes for audit; test whitespace, line-ending, key-order, and token-spelling changes.

## Phase 2 — case bundle and profile schemas (Sections 1.1–1.5)

- [ ] Validate case top-level fields exactly: `schema_version`, `profile`, `case_id`, `task`, and `payload`; accept only `schema_version: "acac-1.3"` and `task: "correct_ledger"`.
- [ ] Validate profiles `single-ledger-1.0` and `historical-ledger-1.0`; enforce public table `L` for single-ledger and `M`, `H`, `W` for historical-ledger.
- [ ] Validate `field_declarations` uniqueness by `(table, field)`, required members, allowed types, Boolean `mutable`, optional `description`, and string-only `format: "rfc3339-timestamp"`.
- [ ] Enforce historical mutability: every `M`/`H` declaration is immutable and only `W` declarations may be mutable; test rejection of mutable `M`/`H`.
- [ ] Validate ledger tables as arrays of `{record_id, values}`, exact declared fields, unique record IDs, correct primitive types, and profile-specific table sets; require identical record-ID sets across historical tables.
- [ ] Preserve row order in exact-byte artifacts while treating row order as non-semantic for grading and semantic hashing; test both behaviors.
- [ ] Validate `metadata_declarations` uniqueness, types, optional timestamp format, and `record_metadata` coverage for every record; reject undeclared or missing metadata values.
- [ ] Validate `updates`: required/optional fields, positive strictly increasing `sequence`, allowed `kind`, conditional `effective_boundary`, predicate references, and forbidden executable expressions.
- [ ] Validate notices: required `notice_id`, `operation`, `authority_text`, `scope`; allowed operations; target-field rules; historical targets restricted to `W`; and exact no-op scope `{"fields": []}` with no predicate.
- [ ] Enforce notice temporal-field conditionals: require `governing_event` when temporal authorization is used and omit `governing_event` entirely for non-temporal authorization; test both branches.
- [ ] Validate no-op authorization: require `eligible_keys: []`, empty required-value and eligibility-rationale sets, and an empty expected patch for a `no_op` notice.
- [ ] Enforce conditional `temporal_conditions`: required when any temporal applicability assertion exists and forbidden otherwise; validate its exact six fields, IDs, timestamp, boundary, and predicate reference.
- [ ] Enforce one case-level governing-event locator and require every structured condition, notice, update, and sidecar locator to match it; quarantine multi-field cases.
- [ ] Represent original-guideline temporal assertions with `instruction_id: "original"`; quarantine prose-only, missing, contradictory, or unrepresented assertions without free-text extraction.

## Phase 3 — bounded predicates and authorization resolution

- [ ] Implement the V1 predicate grammar: `record_ids`, `batch_ids`, `field`, `all`, and `any`; reject unsupported keys, empty sets, duplicate keys, and extra members.
- [ ] Implement `eq`, `neq`, `in`, and `not_in` only for non-timestamp authorization fields; reject `lt`, `lte`, `gt`, and `gte` everywhere in V1 predicates.
- [ ] Reject every authorization operator (`eq`, `neq`, `in`, `not_in`, `lt`, `lte`, `gt`, `gte`) on fields or metadata with `format: "rfc3339-timestamp"`; continue allowing timestamp parsing and validation.
- [ ] Enforce predicate depth and node limits, root depth 1, and independent per-definition counting; test exact 8/64 boundaries.
- [ ] Validate predicate definitions as exactly `{predicate_id, expression}` with unique IDs and no recursion; validate explicit instruction, exclusion, exception, and evidence namespaces.
- [ ] Implement deterministic predicate evaluation against the initial ledger and record metadata; implement explicit all-record scope using `record_ids` listing every applicable record.
- [ ] Implement status-dependent authorization-sidecar validation for `spec_version`, `case_id`, `source_case_hash`, `resolution_status`, `profile`, `resolution_issues`, `resolved_by`, and `resolution_note`.
- [ ] Require `spec_version: "acac-auth-1.0"` for resolved non-temporal sidecars and reject temporal members in that form; retain `acac-auth-1.1` for resolved temporal sidecars.
- [ ] Implement the complete `resolved` sidecar schema, including `governing_instruction_ids`, `predicate_definitions`, `evidence_registry`, `eligible_keys`, `eligibility_rationale`, `exclusions`, `exceptions_applied`, `required_final_values`, `preservation_keys`, and `rationale_by_key`.
- [ ] Enforce resolved coverage: every eligible key is mutable, keys are unique, required final values exactly cover eligible keys, unchanged eligible values are recorded, and preservation keys are exactly unchanged cells.
- [ ] Implement `ambiguous`/`quarantined` sidecars with required issues/provenance and prohibition of resolved-only fields, including `governing_event`, `temporal_rules`, and `temporal_reconciliation`.
- [ ] Implement evidence-registry validation for unique `{evidence_id, content_hash, description}` entries, retained-artifact hashes, case-level references, unresolved minimal registries, and quarantine on missing/malformed/mismatched evidence.

## Phase 4 — temporal reconciliation and timestamp authorization

- [ ] Implement the authoritative eight-field `temporal_rules` schema exactly: `rule_id`, `source_condition_id`, `source_location`, `occurrence_index`, `instruction_id`, `predicate_id`, `effective_at`, `effective_boundary`; reject any governing-event member in a rule.
- [ ] Validate RFC 6901 `source_location`, zero `occurrence_index`, unique `(source_location, occurrence_index)`, unique `source_condition_id`, and immutable source-condition identity.
- [ ] Require every temporal rule to reference a valid explicit predicate definition; reject omitted or unresolved `predicate_id` values.
- [ ] Require exact agreement among case `temporal_conditions`, notice/update temporal fields, the sidecar case-level `governing_event`, and temporal rules; quarantine missing, extra, conflicting, duplicate, unsupported, or ambiguous mappings.
- [ ] Implement the temporal one-to-one reconciliation gate and require `spec_version: "acac-auth-1.1"` for resolved temporal sidecars.
- [ ] Require resolved temporal `temporal_reconciliation` with exactly `status`, `review_submission_hash`, and `checked_at`; require `status: "succeeded"` and explicit-offset timestamp; omit it for resolved non-temporal and unresolved sidecars.
- [ ] Evaluate effective time exclusively as `event >= effective_at` for `inclusive` and `event > effective_at` for `exclusive`; do not inherit thresholds or boundaries across updates.
- [ ] Quarantine absent/malformed/ambiguous governing events, missing in-scope timestamp values, missing boundaries, unclear event meaning, conflicting predicates, timezone guesses, and missing exception evidence.
- [ ] Test repeated temporal conditions, repeated source locations, multiple rules on one event field, original-instruction conditions, and independent update thresholds.

## Phase 5 — model projections and evaluation modes

- [ ] Implement the exact instruction-resolution projection: top-level identity plus declarations, needed metadata, ledger, original guideline, redacted update fields (`update_id`, `sequence`, `kind`, `text`), and redacted notice fields (`notice_id`, `operation`, `issued_at`, `authority_text`).
- [ ] Exclude `temporal_conditions`, predicates, effective-time/boundary fields, scope predicates/fields, governing events, exclusions, exceptions, evidence, sidecars, references, reviews, lifecycle artifacts, manifests, and target counts from instruction-resolution prompts.
- [ ] Implement the exact resolved-contract `scope_contract` fields: `contract_version`, `profile`, `target_fields`, `predicate_definitions`, `governing_event`, `temporal_conditions`, `exclusions`, and `exceptions_applied`; reject extra fields.
- [ ] Ensure resolved-contract prompts do not contain required final values, expected edits, final ledgers, references, reviews, lifecycle events, or unintended evidence.
- [ ] Test that trusted reconciliation and grading retain the complete case bundle while instruction-resolution prompts do not leak authorization answers.

## Phase 6 — patch schema, application, and grading

- [ ] Validate patch top-level keys exactly as `schema_version` and `edits`; accept only `schema_version: "acac-1.3"` and `op: "replace"`.
- [ ] Validate edit addresses, unique target keys, declared types, exact `old_value`, non-no-op writes, and profile-specific target tables; reject add/delete/move/copy and row mutation.
- [ ] Apply structurally valid patches all-or-nothing; apply semantic/authorization failures only to an isolated ledger copy; never normalize to an authorized subset or write externally.
- [ ] Retain raw responses and per-operation diagnostics, including hypothetical isolated validity, while reporting no resulting ledger for structural failure.
- [ ] Implement exact metrics from Section 5.3: correct target selection, correct replacement value, missed corrections, unauthorized edits, scope violations, collateral changes, preservation accuracy, contract validity, and exact edit-set validity.
- [ ] Implement structural-failure metric behavior, tagged N/A values, overlap rules, and no-op denominator behavior; test the four worked examples in Section 5.4.

## Phase 7 — immutable references and lifecycle governance

- [ ] Validate immutable reference content fields, author provenance, source/spec hashes, expected output, final ledger, eligible keys, preservation keys, and rationale.
- [ ] Recompute reference integrity: eligible-key equality, required-value coverage, exact expected edits, old/new values, simultaneous application, final ledger equality, preservation-key equality, and source hashes.
- [ ] Implement immutable ordinary human review submissions with the Section 8.2 fields, including reviewer identity/role, source hashes, review scope, proposed edits, ambiguity notes, decision reason, completion time, independence declaration, independence basis, and optional `supersedes_review_id`.
- [ ] Implement separate adjudication artifacts with `reviewer_role: "adjudicator"`, source case/authorization/reference hashes, every considered review hash or ID, case-by-case disagreement disposition, decision rationale, adjudicator identity, independence declaration and basis, and RFC 3339 completion timestamp.
- [ ] Implement AI-audit artifacts with `reviewer_role: "ai_auditor"` and complete model metadata; reject role/artifact mismatches and prevent AI audits from satisfying human-review or adjudication requirements.
- [ ] Enforce human-review provenance, independence declarations, adjudication evidence, distinct approver identity, and AI non-approval.
- [ ] Implement append-only lifecycle events with sequence numbers, previous-event hashes, exact-byte event hashes, actor-role checks, event-specific evidence requirements, and conditional fields.
- [ ] Implement exactly these lifecycle transitions and reject every other edge: `created -> reviewed | ambiguous | quarantined`; `reviewed -> adjudicated | ambiguous | quarantined`; `adjudicated -> approved | ambiguous | quarantined`; `approved -> frozen | superseded | quarantined`; and `frozen -> frozen | superseded | quarantined`.
- [ ] Derive status by replaying valid events; reject absent, reordered, hash-invalid, or illegal chains; keep `ambiguous` and `quarantined` terminal for a content revision.
- [ ] Implement approval gates for resolved/hash-valid sidecars and temporal reconciliation; prevent approval from overriding failed authorization.
- [ ] Implement post-approval/freeze quarantine without rewriting historical content, reports, or completed runs; exclude quarantined references from new and not-yet-graded runs.
- [ ] Implement pre-run and post-execution freeze timing, run-specific binding, manifest-hash binding, and prohibition of retroactive pre-grading claims.

## Phase 8 — hashing, canonicalization, and reproducibility

- [ ] Implement semantic canonicalization: Unicode-code-point key sorting, exact strings, canonical booleans/integers, sorted ledger rows, sorted declarations, preserved update sequence, and sorted address/registry arrays as specified.
- [ ] Sort `evidence_registry`, `predicate_definitions`, `exclusions`, `exceptions_applied`, `temporal_rules`, `resolution_issues`, `excluded_cases`, `scheduled_case_ids`, and `executed_case_ids` in their specified semantic-hash order; preserve source order for `temporal_conditions` and meaningful sequences.
- [ ] Canonically sort `field_declarations` by `(table, field)`, ledger rows by `record_id`, `eligible_keys` and preservation keys lexicographically by address tuple, and patch `edits` by `(table, record_id, field)` for semantic hashing while retaining raw patch order.
- [ ] Implement exact decimal normalization only for permitted model settings and metric ratios; reject floats elsewhere and reject decimals that cannot be preserved exactly.
- [ ] Test semantic-hash invariance and sensitivity requirements from Section 7, including row/order/set changes and value/ID/timestamp changes.
- [ ] Enforce acyclic hash dependencies among content, reviews, lifecycle events, manifests, and freeze events; ensure manifests never contain freeze-event hashes.

## Phase 9 — manifests, results, and reporting

- [ ] Validate `manifest_version: "1.3"`, run identity, mode, scheduled/executed/excluded coverage, all required hash maps, prompt/configuration hashes, grader version, and UTC creation time.
- [ ] Ensure `executed_case_ids` contains every case with model output; allow overlap with `excluded_cases`; require every scheduled case in at least one set and reject unscheduled IDs/duplicates.
- [ ] Require exact `case_hashes` and `raw_output_hashes` coverage for executed cases; conditionally include authorization-spec, reference, and approval-event hashes only when artifacts exist.
- [ ] Restrict every conditional artifact-hash map to executed-case IDs, require every present hash to validate against the retained artifact, and test an out-of-set key and a mismatched present hash.
- [ ] Represent missing artifacts with controlled exclusion codes (`missing_authorization_spec`, `missing_reference`, `missing_approval_event`) and reject null, empty, fabricated, or silently omitted status.
- [ ] Require complete model metadata whenever raw outputs exist and omit the model object when no model output exists.
- [ ] Validate grading-result schemas, provenance, governance status, freeze-event requirements, metric N/A tags, and structural-invalidity reporting.
- [ ] Implement per-case reports and aggregate denominators: include only resolved, hash-valid, lifecycle-approved/frozen cases meeting temporal gates; report scheduled/included/excluded counts and exclusion reasons.
- [ ] Distinguish `approved_unfrozen` from `frozen`; require valid run-specific freeze binding for frozen aggregate inclusion.

## Phase 10 — acceptance-criteria test suite

- [ ] Implement tests for A–G: ambiguous/quarantined/missing-status rejection, source/hash integrity, coverage, resolved readiness, and approval override prevention.
- [ ] Implement tests for H–M: later-defect quarantine, valid unresolved schemas, resolved-only leakage, unresolved evidence IDs, and empty unresolved registries.
- [ ] Implement tests for N–T: missing/extra temporal mappings, threshold/boundary and instruction/predicate mismatches, structured source identity, and reconciliation success gates.
- [ ] Implement tests for U–Y: non-temporal omission rules, approval-hash non-waiver, manifest eligibility, aggregate eligibility, and governance labels.
- [ ] Implement tests for Z–AD: conditional artifact coverage, single governing-event identity, timestamp predicate prohibition, artifact-role exclusivity, and canonical ordering.
- [ ] Implement tests for AE–AG: exact model visibility, original-guideline temporal sourcing, and governing-event agreement.
- [ ] Run the complete offline acceptance suite against synthetic fixtures only; record that no benchmark, private review, locked submission, gold reference, experiment, or model call was used.

## Explicitly deferred from V1

- [ ] Keep EvalScope and annotation-platform integrations deferred.
- [ ] Keep CSV import, dashboards, direct execution, rollback, multi-reference scoring, nested values, and model-provider clients deferred.
- [ ] Keep null and floating-point annotation-value support deferred.
- [ ] Do not add production writes, remote registries, signature infrastructure, or unapproved schema extensions.

## Requirements traceability: acceptance criteria A–AG

| Criterion | Checklist implementation task(s) | Verification |
|---|---|---|
| A | Phase 3 unresolved status validation | Status-schema tests |
| B | Phase 3 unresolved/quarantine validation | Quarantine tests |
| C | Phase 3 status validation | Missing/unsupported-status tests |
| D | Phase 7 source/spec hash integrity | Hash-mismatch tests |
| E | Phase 3 resolved coverage; Phase 7 reference integrity | Coverage tests |
| F | Phase 3 resolved schema; Phase 4 reconciliation; Phase 7 approval gates | Fully resolved fixture |
| G | Phase 7 approval gate | Override-rejection test |
| H | Phase 7 later-defect quarantine | Historical/new-run tests |
| I | Phase 3 ambiguous schema | Valid unresolved-schema test |
| J | Phase 3 quarantined schema | Valid quarantine-schema test |
| K | Phase 3 resolved-only prohibition | Leakage tests |
| L | Phase 3 evidence registry | Unresolved evidence-ID tests |
| M | Phase 3 empty unresolved registry | Empty-registry test |
| N | Phase 2/4 temporal condition and reconciliation gates | Missing-temporal tests |
| O | Phase 4 one-to-one mapping | Extra-rule tests |
| P | Phase 4 exact threshold/boundary agreement | Mismatch tests |
| Q | Phase 4 instruction/predicate agreement | Association tests |
| R | Phase 2 original/structured source handling; Phase 4 source mapping | Structured-source tests |
| S | Phase 4 pointer/occurrence identity | Duplicate-identity tests |
| T | Phase 4 reconciliation gate | Unsuccessful-reconciliation tests |
| U | Phase 3/4 non-temporal omission rules | Non-temporal sidecar tests |
| V | Phase 7 approval gate | Approval-hash waiver test |
| W | Phase 9 manifest coverage and exclusions | Manifest eligibility tests |
| X | Phase 9 aggregate filtering | Denominator tests |
| Y | Phase 7 freeze; Phase 9 governance reporting | Governance-label tests |
| Z | Phase 9 conditional artifact coverage | Missing-artifact tests |
| AA | Phase 2/4 single governing event | Multi-field quarantine tests |
| AB | Phase 3/4 timestamp predicate prohibition | Operator rejection tests |
| AC | Phase 7 artifact-role schemas | Role-mismatch tests |
| AD | Phase 8 canonical ordering | Ordering invariance tests |
| AE | Phase 5 model projections | Prompt-visibility tests |
| AF | Phase 2/4 original-guideline temporal source | Original-source reconciliation tests |
| AG | Phase 2/4 governing-event agreement | Exact locator agreement tests |

## Completion gate

- [ ] All Phase 0–10 required tasks are complete.
- [ ] Every acceptance criterion A–AG has passing automated coverage.
- [ ] Run the complete Section 14 consistency audit across naming, status gates, authorization, types, temporal rules, predicates, evidence, governance, run coverage, hashing, lifecycle, versioning, freeze timing, hash dependencies, and metrics; record and resolve every discrepancy.
- [ ] Schema names and versions remain `acac-1.3`, manifest `1.3`, grader `acac-grader-1.3`, temporal sidecars `acac-auth-1.1`, and non-temporal sidecars `acac-auth-1.0`.
- [ ] No original requirements document, benchmark data, review submission, locked submission, or gold reference was modified.
- [ ] Implementation readiness is reported to the project owner with test evidence and any concrete failures.
