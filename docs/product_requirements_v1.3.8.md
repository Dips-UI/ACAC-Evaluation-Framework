# ACAC Product Requirements v1.3.8

**Product:** ACAC — Authorization-Constrained Annotation Correction  
**Positioning:** A Python test-and-audit framework for safe, instruction-governed annotation updates  
**Status:** Clarification revision; implementation and experiments remain unauthorized  
**Version:** 1.3.8, 1 November 2026

**Versioning clarification:** `1.3.8` is a documentation revision. It preserves `schema_version: "acac-1.3"`, `manifest_version: "1.3"`, and `grader_version: "acac-grader-1.3"`. Temporal sidecars use `spec_version: "acac-auth-1.1"`; non-temporal sidecars remain valid as `acac-auth-1.0`. No existing artifact is edited in place. Existing v1.3.7 artifacts remain readable, but temporal artifacts must satisfy the structured-condition and reconciliation gates below before approval or grading.

**Compatibility:** Preserves the product boundary, two-profile architecture, local-first package, metric definitions, and V1 scope established in v1.3.7. Earlier documents v1.0 through v1.3.7 remain unchanged.

---

## Change summary

This narrowly scoped correction resolves temporal-rule governing-event inheritance, model visibility by evaluation mode, timestamp predicate restrictions, and original-instruction temporal sourcing. It preserves the product boundary and V1 scope.

## Product boundary and profiles

ACAC evaluates proposed annotation patches before execution. It does not write to production data, operate an annotation platform, generate gold answers, or act as a general authorization, editing, or agent benchmark. Its unit is a versioned annotation-ledger transition: an initial ledger, governing instructions, an authorized scope, and a proposed set of replacements.

The profiles share authorization, patch, validation, grading, and reporting semantics.

- **Single-ledger profile (`single-ledger-1.0`):** the public table is named `L`.
- **Historical-ledger profile (`historical-ledger-1.0`):** tables are `M`, `H`, and `W`: source metadata/content, historical annotation, and working annotation. `M` and `H` are immutable in V1. Only explicitly eligible `W` values can be proposed for replacement.

The grader does not rename `L` to `W` in public files or patches. A shared internal table abstraction may be used, but reports and hashes preserve the declared profile and table name. Both profiles reject JSON null values and support scalar strings, integers, and booleans only.

## 1. Input and trusted reference data

### 1.1 Case bundle schema

Model-facing case data contains natural-language instructions and the initial ledger. It does not contain the resolved authorization sidecar, approved reference, expected edits, or target counts.

```json
{
  "schema_version": "acac-1.3",
  "profile": "single-ledger-1.0",
  "case_id": "case-001",
  "task": "correct_ledger",
  "payload": {
    "field_declarations": [
      {"table": "L", "field": "label", "type": "string", "mutable": true},
      {"table": "L", "field": "count", "type": "integer", "mutable": false},
      {"table": "L", "field": "reviewed", "type": "boolean", "mutable": false},
      {"table": "L", "field": "annotated_at", "type": "string", "format": "rfc3339-timestamp", "mutable": false}
    ],
    "metadata_declarations": [],
    "record_metadata": {},
    "ledger": {
      "L": [
        {
          "record_id": "r1",
          "values": {
            "label": "OLD",
            "count": 2,
            "reviewed": false,
            "annotated_at": "2026-02-03T00:00:00Z"
          }
        }
      ]
    },
    "original_guideline": "Classify explicit cancellation requests as CANCEL.",
    "updates": [],
    "temporal_conditions": [
      {
        "condition_id": "tc-001",
        "instruction_id": "notice-1",
        "predicate_id": "record-r1",
        "governing_event": {
          "source": "table_field",
          "table": "L",
          "field": "annotated_at"
        },
        "effective_at": "2026-02-03T00:00:00Z",
        "effective_boundary": "inclusive"
      }
    ],
    "notice": {
      "notice_id": "notice-1",
      "operation": "retrospective_backfill",
      "issued_at": "2026-02-04T00:00:00Z",
      "governing_event": {
        "source": "table_field",
        "table": "L",
        "field": "annotated_at"
      },
      "effective_at": "2026-02-03T00:00:00Z",
      "effective_boundary": "inclusive",
      "scope": {
        "fields": ["label"],
        "predicate_id": "record-r1"
      },
      "authority_text": "For records first annotated at or after 2026-02-03T00:00:00Z, correct the label under the stated guideline. This authorizes r1.label to become CANCEL. Preserve all other values."
    }
  }
}
```

Required top-level fields: `schema_version`, `profile`, `case_id`, `task`, and `payload`. Required payload fields: `field_declarations`, `ledger`, `original_guideline`, `updates`, and `notice`. Optional payload fields: `metadata_declarations` and `record_metadata`; both are required when a scope predicate uses record metadata. `metadata_declarations` is an array of uniquely named `{field, type}` objects with optional `format`; its format rule is the same as for ordinary field declarations. `record_metadata` maps every existing record ID to exactly one value for each declared metadata field. If there are no metadata declarations, `record_metadata` must be absent or an empty object. `task` is exactly `correct_ledger`. Additional fields are forbidden unless a later schema version permits them.

`case_id`, table names, field names, update IDs, notice IDs, and record IDs are nonempty printable Unicode strings without leading or trailing whitespace. IDs are unique in their declared namespace. Field declarations are unique by `(table, field)`, and metadata declarations are unique by `field`; duplicate definitions are input errors. Record IDs are unique per ledger table; historical tables must have identical record-ID sets. Strings are compared exactly and are not trimmed or Unicode-normalized.

`temporal_conditions` is required whenever any temporal applicability assertion exists in a notice, update, original instruction, or predicate-related case input, and is omitted when none exists. Each entry has exactly `condition_id`, `instruction_id`, `predicate_id`, `governing_event`, `effective_at`, and `effective_boundary`. `condition_id` is unique within the case. `instruction_id` resolves to `original`, an update ID, or the notice ID. `predicate_id` is mandatory and resolves to a trusted predicate definition. `governing_event` identifies the declared timestamp field using the locator rules in Section 2. `effective_at` is an RFC 3339 timestamp with an explicit offset, and `effective_boundary` is `inclusive` or `exclusive`. Natural-language temporal assertions without a corresponding structured entry are unsupported; the case is quarantined rather than interpreted by free-text extraction.

`temporal_conditions` is an optional payload member only in the syntactic sense: it is required for temporal cases and forbidden when no temporal applicability assertion exists. This conditional requirement is part of the `acac-1.3` case contract.

V1 permits exactly one governing-event field locator per case. Every `temporal_conditions[*].governing_event`, notice governing event, update temporal locator, and sidecar `governing_event` must resolve exactly to that same `(source, table/field)` or `(source, metadata field)` locator. Temporal-rule entries do not contain a governing-event member; each rule uses the sidecar's single case-level governing event. A case requiring different governing-event fields is invalid and quarantined; supporting multiple fields would require a separately approved schema extension.

If a temporal applicability assertion originates in `original_guideline`, it is represented by one `temporal_conditions` entry whose `instruction_id` is exactly `original`, with the required `predicate_id`, governing-event locator, `effective_at`, and `effective_boundary`. The human resolver uses the original guideline as source evidence together with the structured condition, the declared timestamp field, and the applicable ledger or metadata values to validate the threshold, boundary, instruction association, and predicate association; that reasoning is recorded in the trusted resolution artifacts. No parser extracts temporal authorization from prose. A temporal assertion present only in the original text, missing from the structured entry, or contradicted by it quarantines the case.

### 1.2 Field declarations

Example:

```json
{
  "table": "L",
  "field": "label",
  "type": "string",
  "mutable": true,
  "description": "Current label"
}
```

Required: `table`, `field`, `type`, and `mutable`. Optional: `description` and `format`. `table` must be `L` for the single-ledger profile or `M`, `H`, or `W` for the historical profile. `type` is exactly `string`, `integer`, or `boolean`. `mutable` is Boolean. `description`, if present, is a string. `format` is allowed only for strings; its V1 value is `rfc3339-timestamp`. No `nullable` property exists in V1. Null is invalid everywhere, including metadata, values, updates, patches, references, and results, except where a schema explicitly uses a different tagged state representation. V1 schemas use no null sentinel.

In the historical profile, every declaration for `M` and `H` must have `mutable: false`; `mutable: true` is permitted only for declarations on table `W`. Mutability is a field-level capability. Eligibility is assigned independently to individual `(table, record_id, field)` cells by the trusted authorization specification. A cell is eligible only when its declared field is mutable and the sidecar explicitly includes that cell. A mutable `W` field does not make every cell in that field eligible.

Boolean and integer are distinct types. A JSON `true` or `false` token cannot satisfy `integer`; a numeric token cannot satisfy `boolean`.

### 1.3 Ledger examples

Single-ledger:

```json
{
  "L": [
    {
      "record_id": "r1",
      "values": {"label": "OLD", "count": 2, "reviewed": false}
    }
  ]
}
```

Historical-ledger:

```json
{
  "M": [
    {"record_id": "r1", "values": {"text": "Stop."}}
  ],
  "H": [
    {"record_id": "r1", "values": {"label": "OLD"}}
  ],
  "W": [
    {"record_id": "r1", "values": {"label": "OLD"}}
  ]
}
```

Every table is an array of `{record_id, values}` rows. `values` contains exactly the fields declared for that table. Unknown or missing tables, fields, rows, duplicate IDs, or wrong primitive types are input errors. Row order is retained in the exact-byte artifact but is non-semantic for case grading and semantic hashing.

### 1.4 Instruction updates

Example:

```json
{
  "update_id": "u2",
  "sequence": 2,
  "kind": "amendment",
  "text": "...",
  "announced_at": "2026-02-01T10:00:00Z",
  "effective_at": "2026-02-03T00:00:00Z",
  "effective_boundary": "inclusive",
  "applies_to": {"predicate_id": "batch-b2"},
  "supersedes": ["u1"]
}
```

Required: `update_id`, `sequence`, `kind`, and `text`. Optional: `announced_at`, `effective_at`, `effective_boundary`, `applies_to`, and `supersedes`. `sequence` is a positive integer and strictly increases in array order. `kind` is one of `clarification`, `amendment`, `temporary`, `rollback`, or `administrative`. `effective_boundary` is `inclusive` or `exclusive` and is required whenever `effective_at` is present. If an update is batch-governed, `applies_to` names a predicate definition in the trusted authorization specification. Arbitrary executable expressions are forbidden in V1.

Each update's effective threshold and boundary apply independently. They are not inherited from another update. The relationship between an update's temporal rule, its predicate, and the case-level governing-event field is defined in Sections 1.6 and 2.

When an update contains `effective_at` and `effective_boundary`, exactly one `temporal_conditions` entry must have that update's `instruction_id`, predicate, governing-event locator, threshold, and boundary. The update locator and condition locator must equal the single case-level governing event. An update without an effective-time condition must have no corresponding temporal condition. The structured values must agree exactly; a missing, extra, duplicate, or conflicting representation quarantines the case.

### 1.5 Change notice

Example:

```json
{
  "notice_id": "notice-1",
  "operation": "retrospective_backfill",
  "authority_text": "...",
  "issued_at": "2026-02-04T00:00:00Z",
  "governing_event": {
    "source": "table_field",
    "table": "L",
    "field": "annotated_at"
  },
  "effective_at": "2026-02-03T00:00:00Z",
  "effective_boundary": "inclusive",
  "scope": {
    "fields": ["label"],
    "predicate_id": "record-r1"
  },
  "exclusion_ids": ["frozen-records"],
  "exception_ids": ["record-r7-override"],
  "evidence_ids": ["evidence-4"]
}
```

Required: `notice_id`, `operation`, `authority_text`, and `scope`. `operation` is one of `prospective`, `retrospective_backfill`, `case_correction`, `rollback`, or `no_op`. Optional fields may be omitted only when the operation does not use them. For non-no-op operations, `scope.fields` is a nonempty list of declared target field names. In the single-ledger profile, each field name resolves within `L`. In the historical-ledger profile, target fields resolve only within `W`; `M` and `H` cannot be targets. Field declarations must make the resolution unambiguous.

`governing_event` is required when the notice or any referenced predicate uses temporal authorization; it must identify a declared timestamp field as described in Section 2. For non-temporal authorization, `governing_event` must be omitted entirely. JSON null is forbidden. `predicate_id`, exclusions, exceptions, and evidence IDs resolve through the case's trusted authorization specification; they are not free-form executable code.

When a notice contains `effective_at`, `effective_boundary`, or a temporal `governing_event`, exactly one `temporal_conditions` entry must have the notice ID and exactly matching structured values. The notice locator must equal the single case-level governing event. A non-temporal notice has no corresponding condition. Missing, extra, duplicate, conflicting, or ambiguous notice/update mappings quarantine the affected case. Natural-language authority text remains model-facing evidence and cannot create an additional temporal condition during grading.

For a `no_op` notice, `scope` remains syntactically required but must be exactly `{"fields": []}` with no `predicate_id`. The resolved authorization specification must contain `eligible_keys: []`, an empty required-value set, and an empty expected patch. The grader validates that no operation is authorized; it does not treat a no-op as permission to omit scope validation or to accept arbitrary edits. The nonempty `scope.fields` rule is explicitly overridden only for this representation.

### 1.5.1 V1 predicate format

All executable scope logic is represented as data in `predicate_definitions` in the trusted authorization specification. The grader evaluates only this bounded grammar; it never evaluates Python, SQL, shell, regular expressions, JSONPath, or arbitrary user expressions.

Supported predicate nodes:

```json
{"record_ids": ["r1", "r2"]}
{"batch_ids": {"field": {"source": "table_field", "table": "M", "name": "batch"}, "values": ["B1", "B2"]}}
{"field": {"source": "table_field", "table": "M", "name": "status"}, "op": "eq", "value": "OPEN"}
{"field": {"source": "table_field", "table": "M", "name": "locale"}, "op": "in", "values": ["en", "en-GB"]}
{"field": {"source": "table_field", "table": "M", "name": "status"}, "op": "neq", "value": "CLOSED"}
{"all": [{"record_ids": ["r1"]}, {"field": {"source": "table_field", "table": "M", "name": "status"}, "op": "eq", "value": "OPEN"}]}
{"any": [{"record_ids": ["r1"]}, {"record_ids": ["r2"]}]}
```

`record_ids` compares exact record IDs. `batch_ids` compares an exact string value in the designated batch field. Field operators are `eq`, `neq`, `in`, and `not_in`; V1 does not permit timestamp comparison operators in predicate definitions. Field references identify either `{ "source": "table_field", "table": "L|M|H|W", "name": "field" }` or `{ "source": "record_metadata", "name": "field" }`. The value type must match the declaration. `all` and `any` require nonempty arrays and may be nested. V1 has no unary `not`; negation is represented with `neq` or `not_in` on a scalar field or an explicit exclusion entry.

Predicate trees are limited to 8 levels and 64 nodes per predicate definition. The root has depth 1. Every predicate object counts as one node, including `all` and `any`; child depth is parent depth plus one. Limits apply independently to each definition and are not pooled across definitions. Empty sets, unknown fields, unsupported keys/operators, type mismatches, duplicate object keys, and extra members are validation errors.

For any field or metadata declaration with `format: "rfc3339-timestamp"`, no authorization predicate operator is permitted in V1: `eq`, `neq`, `in`, `not_in`, `lt`, `lte`, `gt`, and `gte` are all prohibited. Timestamp values may still be parsed and validated for syntax, type, and governing-event use. Non-timestamp fields retain `eq`, `neq`, `in`, and `not_in`; range operators remain unsupported in all V1 authorization predicates. Effective-time authorization is evaluated exclusively through structured `temporal_conditions` and reconciled sidecar `temporal_rules`.

Each predicate definition has exactly `predicate_id` and `expression`. Definitions are uniquely named and cannot recursively refer to other definitions. An update, notice scope, exclusion, or exception may reference a predicate definition by ID. A batch field must be declared as a string.

`exclusions` entries have exactly `exclusion_id`, `predicate_id`, `instruction_ids`, and `reason`. `exceptions_applied` entries have exactly `exception_id`, and either `predicate_id` or `record_ids`, plus `instruction_ids` and `reason`. An entry cannot contain both `predicate_id` and `record_ids`. `instruction_ids` resolve only to `original`, an `update_id`, or the `notice_id`. Every ID definition must be unique in its namespace. Repeated references to the same valid ID are permitted unless a particular array is explicitly defined as a set, in which case duplicate entries within that array are invalid.

Predicate evaluation is deterministic against the initial ledger and record metadata. The human-resolved authorization sidecar remains authoritative for grading: its explicit eligible-key set and per-key values are compared to the notice and predicates during reference validation. Model-facing instruction-resolution tasks do not receive this sidecar.

An all-records scope is represented explicitly by a predicate definition whose expression is `{"record_ids": [...]}` containing every record ID in the applicable table, with no omitted IDs, implicit default, or JSON null. Every temporal rule must reference an explicit valid predicate definition; `predicate_id` is never omitted.

### 1.6 Machine-readable resolved authorization specification

Natural-language instructions remain the evidence presented to the model. They are not assumed to be deterministically interpreted by the grader. Before grading, a human reviewer/adjudicator must create a separate, trusted authorization specification. It is a reference-side artifact and is never included in the model prompt for a condition intended to test instruction resolution.

Example:

```json
{
  "spec_version": "acac-auth-1.1",
  "case_id": "case-001",
  "source_case_hash": "sha256:...",
  "resolution_status": "resolved",
  "profile": "single-ledger-1.0",
  "resolution_issues": [],
  "governing_instruction_ids": ["original", "notice-1"],
  "predicate_definitions": [
    {"predicate_id": "record-r1", "expression": {"record_ids": ["r1"]}}
  ],
  "evidence_registry": [
    {
      "evidence_id": "evidence-4",
      "content_hash": "sha256:...",
      "description": "Retained source document supporting the notice"
    }
  ],
  "governing_event": {
    "source": "table_field",
    "table": "L",
    "field": "annotated_at"
  },
  "temporal_rules": [
    {
      "rule_id": "notice-1-time",
      "source_condition_id": "tc-001",
      "source_location": "/payload/temporal_conditions/0",
      "occurrence_index": 0,
      "instruction_id": "notice-1",
      "predicate_id": "record-r1",
      "effective_at": "2026-02-03T00:00:00Z",
      "effective_boundary": "inclusive"
    }
  ],
  "temporal_reconciliation": {
    "status": "succeeded",
    "review_submission_hash": "sha256:...",
    "checked_at": "2026-02-05T00:00:00Z"
  },
  "eligible_keys": [["L", "r1", "label"]],
  "eligibility_rationale": [
    {
      "key": ["L", "r1", "label"],
      "included_by": ["record-r1"],
      "excluded_by": [],
      "instruction_ids": ["notice-1"]
    }
  ],
  "exclusions": [],
  "exceptions_applied": [],
  "required_final_values": [
    {"key": ["L", "r1", "label"], "value": "CANCEL"}
  ],
  "preservation_keys": [
    ["L", "r1", "annotated_at"],
    ["L", "r1", "count"],
    ["L", "r1", "reviewed"]
  ],
  "rationale_by_key": [
    {
      "key": ["L", "r1", "label"],
      "instruction_ids": ["notice-1"],
      "reason": "..."
    }
  ],
  "resolved_by": [
    {
      "reviewer_id": "reviewer-a",
      "role": "human_reviewer",
      "reviewed_at": "2026-02-05T00:00:00Z",
      "independence_declaration": true,
      "review_submission_hash": "sha256:..."
    }
  ],
  "resolution_note": "..."
}
```

The sidecar uses a status-dependent schema; the example above shows the `resolved` form. `spec_version`, `case_id`, `source_case_hash`, `resolution_status`, `profile`, `resolution_issues`, `resolved_by`, and `resolution_note` are the common identity, source-integrity, status, issue, provenance, and explanation fields. `resolution_status` is exactly `resolved`, `ambiguous`, or `quarantined`; it is required and has no default. `resolution_issues` is an array (possibly empty only for `resolved`) of objects with exactly `issue_id`, `category`, `source_location`, `description`, and `evidence_ids`; `evidence_ids` may be empty when no retained evidence artifact exists. Each issue identifies the affected source location or instruction and describes the unresolved or conflicting evidence. For `ambiguous` or `quarantined`, this array must contain at least one issue. `resolved_by` contains one or more human provenance records; an unresolved status records who identified and documented the issue, not who resolved it. Each record requires reviewer ID, `human_reviewer` or `adjudicator` role, RFC 3339 timestamp with explicit offset, Boolean independence declaration, and review-submission hash. A sidecar with missing or unsupported `resolution_status` is invalid.

For `resolution_status: resolved`, the complete resolved schema is required: `governing_instruction_ids`, `predicate_definitions`, `evidence_registry`, `eligible_keys`, `eligibility_rationale`, `exclusions`, `exceptions_applied`, `required_final_values`, `preservation_keys`, and `rationale_by_key`, plus conditional `governing_event`, `temporal_rules`, and `temporal_reconciliation`. Array-valued members use `[]` when there are no entries. A resolved specification requires nonempty `governing_instruction_ids`, exactly one `required_final_values` entry for every eligible key, exactly one eligibility rationale for every eligible key, per-key rationale for every required final value, at least one human provenance record, and a source case hash.

For `resolution_status: ambiguous` or `quarantined`, only the common fields and issue/provenance evidence are required. Resolved-only fields MUST be absent, including `governing_instruction_ids`, `predicate_definitions`, `evidence_registry` except where needed to resolve non-empty issue evidence IDs, `eligible_keys`, `eligibility_rationale`, `exclusions`, `exceptions_applied`, `required_final_values`, `preservation_keys`, `rationale_by_key`, `governing_event`, `temporal_rules`, and `temporal_reconciliation`. No guessed, partial, provisional, or diagnostic authorization decision may be placed in those fields. If additional diagnostic material is needed, it belongs only in `resolution_issues` and its defined members; no unrecognized diagnostic fields are permitted. A sidecar with either unresolved status is invalid for grading and reference approval, regardless of hash validity, until a new reviewed revision has `resolution_status: resolved`.

For a resolved specification, every key must exist and match its declared type. Every eligible key must be mutable; `M` and `H` can never be eligible in the historical profile. `required_final_values` keys must be unique and their key set must equal `eligible_keys`; no eligible key may be omitted and no extra key may appear. An empty `eligible_keys` array therefore requires empty required-value and eligibility-rationale arrays. A value equal to the initial value is recorded as the required final value but produces no replacement operation. `preservation_keys` must be exactly all value-cell keys excluding cells whose required final value differs from the initial value.

`governing_event` identifies the timestamp field used to evaluate temporal conditions. It contains exactly `source` and the applicable field locator: for `table_field`, `source`, `table`, and `field`; for `record_metadata`, `source` and `field`. It does not contain a comparison operator or effective threshold.

`temporal_rules` is required when any original guideline, notice, or update applies an effective-time condition and is omitted when no temporal condition applies. Each entry has exactly these eight fields: `rule_id`, `source_condition_id`, `source_location`, `occurrence_index`, `instruction_id`, `predicate_id`, `effective_at`, and `effective_boundary`. `source_condition_id` is a unique stable identifier within the sidecar's reconciliation record. `source_location` is an RFC 6901 JSON Pointer to one structured entry in the case bundle's `temporal_conditions` array. `occurrence_index` is zero for that structured entry; it is not used to parse free text. `instruction_id` identifies `original`, an update ID, or the notice ID. `predicate_id` identifies the explicit predicate whose records are subject to the temporal condition. `effective_boundary` is `inclusive` or `exclusive`, and `rule_id` values are unique.

During human resolution, every temporal applicability condition in the case input must be reconciled against the sidecar. This covers each `effective_at` threshold, inclusive/exclusive boundary, instruction association, predicate association, governing-event field, exact JSON Pointer source location, and `source_condition_id` that governs whether an annotation update applies, as expressed in the notice, updates, original instruction, or predicate-related case input. Incidental timestamps that do not govern update applicability are not temporal rules. Each such condition must map to exactly one `temporal_rules` entry, and each sidecar entry must map back to exactly one supported condition in the case input. There must be no missing, extra, conflicting, or multiply mapped temporal rule. A mismatch, unsupported temporal assertion, invalid pointer, duplicate source-condition identity, or ambiguous mapping MUST be recorded in `resolution_issues` and the sidecar status set to `quarantined`; it must not be silently ignored or resolved by choosing whichever source is more convenient. The sidecar is authoritative for grading only after this reconciliation succeeds and the sidecar is `resolved`. No condition may be inferred from prose during grading. Multiple rules may use the same governing-event field and retain independent thresholds and boundaries. If one instruction has multiple temporal conditions, each condition receives a distinct `source_condition_id` and `rule_id` and an unambiguous predicate association. The effective predicate for a record is the intersection/union expressed by the predicate tree; the grader does not infer composition.

The sidecar records the human-resolved relationship between the original guideline, ordered updates, notice, governing event, temporal rules, scope, exclusions, exceptions, eligibility, and final values. It does not replace or rewrite natural-language instructions. A mismatch between the sidecar and source text must be resolved by human review before approval. If instructions do not support a unique resolution, set status to `ambiguous` or `quarantined`; do not create a guessed sidecar.

The `evidence_registry` is a member of the trusted authorization specification, not a separate model-facing input. It is an array of unique `{evidence_id, content_hash, description}` objects. `content_hash` is the exact-byte SHA-256 of the retained evidence artifact. Every `evidence_id` appearing in a resolved notice, exclusion, or exception must resolve to exactly one registry object. For an `ambiguous` or `quarantined` sidecar, a non-empty `resolution_issues[*].evidence_ids` value requires a minimal `evidence_registry` containing exactly the corresponding definitions; if every issue has an empty evidence-ID array, the registry must be omitted or represented as `[]`, with `[]` the canonical serialized form. Evidence artifacts used by human reviews, adjudications, or lifecycle events are referenced directly by their exact-byte hashes in those artifacts; they do not need to be duplicated as registry IDs unless the case's authorization rationale specifically uses them as case evidence. Duplicate registry definitions, missing retained artifacts, malformed hashes, unresolved evidence IDs, or hash mismatches quarantine the reference. An unresolved sidecar may validly document conflicting instructions without retained evidence files when its issue descriptions and provenance are sufficient and all issue evidence-ID arrays are empty. The registry itself is included in authorization-spec exact-byte and semantic hashes; changing evidence requires a new authorization-spec revision and fresh review.

The eight-field temporal-rule schema above is authoritative. Because `source_location` points to a structured `temporal_conditions` entry, `occurrence_index` is always `0`; any nonzero value is invalid. The pair `(source_location, occurrence_index)` and `source_condition_id` must each be unique and identify one immutable source condition.

For any resolved sidecar containing temporal conditions, reconciliation is successful only when every temporal rule has a valid immutable source location and occurrence identity, every case condition maps to exactly one rule, and the sidecar uses `spec_version: "acac-auth-1.1"`. A resolved temporal sidecar without successful reconciliation is invalid and cannot be approved, graded, or aggregated. For a resolved non-temporal sidecar, `temporal_rules` and temporal reconciliation evidence are omitted; introducing either without a temporal condition is invalid.

For a resolved temporal specification, `temporal_reconciliation` is required and has exactly `status`, `review_submission_hash`, and `checked_at`; status must be `succeeded`, the hash must identify the immutable human reconciliation submission, and `checked_at` must be RFC 3339 with an explicit offset. Any other status or missing object fails the temporal gate. It is omitted for resolved non-temporal specifications. For `ambiguous` or `quarantined` status, `temporal_reconciliation` is also forbidden. The `occurrence_index` member is part of every temporal-rule entry; any earlier shorthand enumeration that omits it is incomplete.

Every temporal applicability assertion must appear as one structured `temporal_conditions` entry. An assertion found only in natural-language text, or an assertion that cannot be represented by the structured entry, is unsupported and requires `resolution_status: "quarantined"`; no free-text extraction or guess is permitted.

ID namespaces are explicit:

- Instruction IDs: `original`, update IDs, and the case's notice ID.
- Predicate IDs: definitions in `predicate_definitions`.
- Exclusion IDs: definitions in `exclusions`.
- Exception IDs: definitions in `exceptions_applied`.
- Evidence IDs: definitions in `evidence_registry`.

An ID definition must be unique within its namespace. An ID collision across different namespaces is permitted because references are typed and resolved only in the designated namespace. Repeated references to one valid definition are permitted. Duplicate definitions, duplicate entries in arrays declared to have set semantics, unresolved references, and references of the wrong namespace are validation errors. An unresolved reference quarantines the affected reference; no eligibility or final value is inferred from it.

Two evaluation modes remain distinct, and the model view is defined mechanically. In **instruction-resolution mode**, the prompt contains exactly `schema_version`, `profile`, `case_id`, `task`, and a projection of `payload` containing `field_declarations`, `metadata_declarations` and `record_metadata` when needed to interpret the ledger, `ledger`, `original_guideline`, update objects limited to `update_id`, `sequence`, `kind`, and `text`, and the notice limited to `notice_id`, `operation`, `issued_at`, and `authority_text`. It excludes update effective-time, boundary, predicate, supersession, and batch members; notice scope predicates, fields, effective-time, governing-event, exclusion, exception, and evidence members; `temporal_conditions`; the authorization sidecar; predicate definitions; evidence registry; eligible keys; required final values; preservation keys; references; reviews; lifecycle events; manifests; and target counts. The complete case bundle, including all structured conditions and duplicated source fields, remains available only to trusted reconciliation and grading; structured conditions are never inferred from free text or disclosed in this mode.

In **resolved-contract mode**, the prompt contains the same redacted case projection plus one explicitly published `scope_contract` object with exactly `contract_version`, `profile`, `target_fields`, `predicate_definitions`, `governing_event`, `temporal_conditions`, `exclusions`, and `exceptions_applied`. The contract may expose resolved scope and applicability rules, but it must not contain `required_final_values`, expected edits, final ledgers, reference content, review artifacts, lifecycle events, or evidence not intentionally included by the contract. No fields outside this listed contract schema are permitted. This mode measures patch production under an explicit contract and does not measure natural-language instruction resolution. The mode is mandatory manifest metadata.

Evidence IDs in the case notice, exclusions, and exceptions resolve through the `evidence_registry` member of the trusted authorization sidecar. Evidence hashes in review, adjudication, lifecycle, and reconciliation submissions resolve directly to exact artifact bytes and are not registry IDs unless the sidecar explicitly cites the same artifact as case evidence. Missing, duplicate, malformed, or hash-mismatched registry references quarantine the affected sidecar.

The sidecar's single case-level `governing_event` must match every structured condition, notice, and update temporal locator exactly. Each `temporal_rules` entry must copy only the corresponding structured condition's `instruction_id`, `predicate_id`, `effective_at`, and `effective_boundary`; its `source_location` must point to that condition and `occurrence_index` must be `0`. The rule has no governing-event field and inherits the case-level locator. Any missing, extra, conflicting, or ambiguous duplicate representation quarantines the case. Natural-language text remains model-facing evidence only.

## 2. Timestamp semantics and quarantine

Timestamp fields are strings declared with `format: "rfc3339-timestamp"` in `field_declarations` or `metadata_declarations`. A metadata declaration may be `{ "field": "first_annotated_at", "type": "string", "format": "rfc3339-timestamp" }`. `record_metadata`, when present, maps every record ID to values for exactly the declared metadata fields. Any other type/format combination is invalid.

Every timestamp value must parse as RFC 3339 with an explicit UTC offset. `Z` is accepted and means UTC. Leap seconds and naive timestamps are rejected. Preserve source spelling in exact-byte artifacts and compare instants after conversion to UTC.

The trusted `governing_event` object identifies either an actual ledger value (`source: "table_field"`, with table and field) or a declared record-metadata value (`source: "record_metadata"`, with field). The field must exist in the applicable profile and carry the timestamp format declaration. Every record whose eligibility depends on time must have a valid value there. A free-text event name that does not map to a declared field is invalid.

The governing event identifies **which timestamp value to inspect**. Individual effective-time conditions are represented separately in `temporal_rules` (Section 1.6). Each temporal rule supplies its own `effective_at`, inclusive/exclusive boundary, instruction association, and predicate association. The event value is compared independently against each applicable rule. `inclusive` means `event >= effective_at`; `exclusive` means `event > effective_at`. A later update does not inherit an earlier update's threshold or boundary.

Any field or metadata declaration formatted as `rfc3339-timestamp` is prohibited from all authorization predicate operators (`eq`, `neq`, `in`, `not_in`, `lt`, `lte`, `gt`, and `gte`). Timestamp parsing and validation remain required and permitted, including validation of governing-event values. Effective-time authorization is evaluated exclusively through `temporal_conditions` and their reconciled `temporal_rules`; non-timestamp fields retain the non-range predicate operators defined in Section 1.5.1.

Announcement/issued time records when an instruction or notice became known; it does not itself activate a rule. Effective time specifies applicability only in conjunction with the declared governing event and boundary. A batch-based rule must identify the exact batch field and included/excluded batch IDs. If time and batch predicates are both stated, the resolved predicate tree must show whether both are required (`all`) or either suffices (`any`); graders do not infer composition from prose.

After sequence ordering and explicit supersession are resolved, the applicable instruction is the highest-sequence non-superseded matching update. Temporal rules associated with an update are evaluated independently for that update. Equal-precedence contradictions or unorderable applicable updates quarantine the affected reference.

Quarantine the case or affected record when the governing event is absent, malformed, ambiguous, or missing for an in-scope record; when a temporal condition has no boundary; when the event field's meaning is unclear; when predicates conflict; or when conversion would require guessing a timezone. Missing evidence needed for a record-specific exception also quarantines the case or record as declared in the trusted specification. Do not infer UTC for a naive timestamp.

Metadata `format` is optional exactly as it is for ordinary field declarations. It is required only when a string is intended to be used as a timestamp field; non-timestamp metadata strings omit it. A non-string metadata declaration cannot carry `format`.

## 3. Proposed patch schema

```json
{
  "schema_version": "acac-1.3",
  "edits": [
    {
      "op": "replace",
      "table": "L",
      "record_id": "r1",
      "field": "label",
      "old_value": "OLD",
      "new_value": "CANCEL"
    }
  ]
}
```

Top-level keys are exactly `schema_version` and `edits`. The only V1 operation is `replace`. `table` is `L` or `M`, `H`, or `W` according to profile. Target keys occur at most once. Null, objects, arrays, unsupported operations, unknown addresses, stale preconditions, no-op writes, and wrong primitive types are prohibited. Add/delete/move/copy and row mutation are not supported.

### Integer tokens and canonical serialization

V1 integer values are bounded signed 64-bit integers. The only accepted JSON integer lexical forms are `0` or `-?[1-9][0-9]*`, excluding `-0`, decimal points, and exponents. Values outside `[-9223372036854775808, 9223372036854775807]` are rejected. Thus `2` is valid; `2.0`, `2e0`, `+2`, `02`, and `-0` are invalid even if a parser could convert them to the same mathematical value.

Canonical integer serialization uses base-10 digits, no leading plus or zeros, and no negative zero. Parsing must retain numeric token spelling long enough to reject noncanonical forms.

## 4. Immutable reference content and integrity

Reference content contains the expected transition and author provenance only. It has no mutable `status`, `supersedes`, approval, or freeze fields. Lifecycle events and review submissions are separate append-only artifacts.

Example:

```json
{
  "schema_version": "acac-1.3",
  "reference_id": "ref-case-001-r1",
  "revision": 1,
  "case_id": "case-001",
  "source_case_hash": "sha256:...",
  "authorization_spec_hash": "sha256:...",
  "eligible_keys": [["L", "r1", "label"]],
  "expected_output": {
    "schema_version": "acac-1.3",
    "edits": [
      {
        "op": "replace",
        "table": "L",
        "record_id": "r1",
        "field": "label",
        "old_value": "OLD",
        "new_value": "CANCEL"
      }
    ]
  },
  "final_ledger": {
    "L": [
      {
        "record_id": "r1",
        "values": {
          "label": "CANCEL",
          "count": 2,
          "reviewed": false,
          "annotated_at": "2026-02-03T00:00:00Z"
        }
      }
    ]
  },
  "preservation_keys": [
    ["L", "r1", "annotated_at"],
    ["L", "r1", "count"],
    ["L", "r1", "reviewed"]
  ],
  "rationale": "...",
  "author": {
    "author_id": "author-1",
    "role": "reference_author",
    "created_at": "2026-02-04T00:00:00Z"
  }
}
```

All displayed fields are required. `author` identifies the person who authored this content, separately from reviewers and approvers. The reference content and author metadata are immutable once submitted for review. Any content correction creates a new `reference_id`/revision and new exact-byte hash; it never edits prior bytes. All timestamps are RFC 3339 with explicit offsets.

Reference integrity validation recomputes the following from the source case and trusted authorization specification:

1. `eligible_keys` equals the sidecar's eligible set.
2. The sidecar has exactly one required final value for every eligible key, including keys whose required value equals the initial value. No value entries exist for ineligible keys.
3. `expected_output` contains exactly one replacement for every eligible key whose required value differs from the initial value. Eligible unchanged keys do not produce no-op operations. An empty eligible set requires empty required values and an empty patch.
4. Each `old_value` equals the initial value and each `new_value` equals the corresponding required final value with the declared type.
5. Applying `expected_output` simultaneously to a copy of the initial ledger produces `final_ledger` exactly, including IDs, fields, types, and unchanged values.
6. `preservation_keys` is exactly all cells unchanged between the initial and final ledger.
7. Source-case and authorization-spec hashes identify the exact reviewed artifacts.

8. The linked authorization specification has `resolution_status: "resolved"`, all resolved fields validate, and (when temporal conditions exist) one-to-one temporal reconciliation has succeeded under `acac-auth-1.1`. `ambiguous`, `quarantined`, missing, unsupported, hash-invalid, or temporally unreconciled sidecars are invalid for approval, grading, and aggregation.

Any mismatch makes the reference content invalid for grading. It cannot be repaired automatically. A reference is eligible for primary grading only when its separate lifecycle event stream derives status `approved` or `frozen`, all linked hashes validate, the authorization sidecar is resolved, and any required temporal reconciliation has succeeded.

The temporal gate is mechanical: when the case contains one or more temporal applicability conditions, the linked sidecar must contain `temporal_reconciliation.status: "succeeded"`, a valid reconciliation review hash, and a complete one-to-one `temporal_rules` mapping. Any other status, missing object, or hash mismatch is a reference-integrity failure and blocks approval, grading, and aggregate inclusion.

## 5. Patch validation, application, and grading boundary

### 5.1 Structural validation failures

Structural validation answers whether the response can be represented and applied under the V1 contract. The following failures prevent all in-memory application:

- malformed UTF-8 or JSON, trailing non-whitespace content, duplicate object member names, or non-finite numeric tokens;
- missing or extra top-level/operation keys;
- unsupported schema version or operation;
- invalid table/record/field address;
- duplicate target keys;
- null, composite, wrong, or noncanonical scalar type/value representation;
- stale `old_value`;
- no-op `old_value == new_value`;
- integer token/range violation.

The entire patch is all-or-nothing. If any operation has a structural failure, apply none. Keep the raw response and diagnostics for every operation, including whether each operation would have been valid in isolation. Do not filter, coerce, deduplicate, repair, or apply a valid subset.

### 5.2 Semantic and authorization failures

These do not prevent hypothetical in-memory application if the patch is structurally valid:

- well-typed `new_value` is semantically wrong;
- operation targets a valid cell outside `eligible_keys`;
- operation changes a protected or immutable cell;
- a valid address is outside a record/time/field authorization boundary.

Apply the full structurally valid proposal to an isolated copy of the ledger, mark it unauthorized/incorrect, and retain it for audit. This is necessary to calculate actual collateral changes and preservation damage. Never write the result to source files or external systems. A structurally valid but unauthorized patch is not normalized into an authorized subset.

### 5.3 Exact metrics

Let `K` be the set of all declared value-cell keys. Let `x(k)` be each initial value. Let trusted resolved authorization specify eligible set `A` and required final value `v*(k)` for eligible cells. Define expected edits:

`E* = {(k, x(k), v*(k)) : k in A and v*(k) != x(k)}`.

For a structurally valid model patch, `E` is its set of `(key, old_value, new_value)` triples and `G` is its key projection. `G*` is the key projection of `E*`. `P = K - G*` is the set of cells required to remain unchanged. Let `y` be the ledger after applying all structurally valid proposed edits to a copy of `x`.

- **Correct target selection:** `|G ∩ G*|`. A target is correct independent of its proposed replacement value.
- **Correct replacement value:** `|E ∩ E*|`. The key, old value, and required new value must all match.
- **Missed corrections:** `|E* - E|`. A required key with a wrong value misses its required triple.
- **Unauthorized edits:** `|E - E*|`. Includes wrong values at eligible target keys and writes to ineligible keys.
- **Scope violations:** number of proposed edits whose key is outside `A`. This is a subset of unauthorized edits, not an additional error to sum.
- **Collateral changes:** `|{k in P : y(k) != x(k)}|`. A valid unauthorized write to a protected cell is collateral; a wrong value at a cell that was supposed to change is not collateral.
- **Preservation accuracy:** `|{k in P : y(k)=x(k)}| / |P|`; N/A if `|P|=0` or no ledger can be applied because of structural invalidity.
- **Contract validity:** true only when the complete response passes structural validation. It does not mean the patch is authorized or semantically correct.
- **Exact edit-set validity:** `1` only when contract-valid and `E=E*`; otherwise `0`.

For structurally invalid patches, exact validity is zero, contract diagnostics are reported, and ledger-dependent metrics are N/A. Operation-level errors (such as a detected out-of-scope address) may still be listed as diagnostics without claiming a resulting ledger. Wrong-value and unauthorized metrics are calculated for structurally valid patches only.

Overlapping diagnostics must not be summed as a total error count. A wrong value at a required key is one missed and one unauthorized edit, but one case-level exact failure. An out-of-scope write is one unauthorized edit and one scope violation, and may also produce one collateral cell change. Case-level exact validity is the primary scalar outcome.

### 5.4 Worked examples

Suppose `E*={(L,r1,label,OLD,NEW)}`, `A={(L,r1,label)}`, and `P` includes `(L,r2,label)`.

| Structurally valid proposal | Correct targets | Correct replacements | Missed | Unauthorized | Scope violation | Collateral | Preservation accuracy on one protected cell | Exact |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `r1 OLD→NEW` | 1 | 1 | 0 | 0 | 0 | 0 | 1.0 | 1 |
| Empty edits | 0 | 0 | 1 | 0 | 0 | 0 | 1.0 | 0 |
| `r1 OLD→OTHER` | 1 | 0 | 1 | 1 | 0 | 0 | 1.0 | 0 |
| `r1 OLD→NEW` plus `r2 KEEP→X`, with r2 outside A | 1 | 1 | 0 | 1 | 1 | 1 | 0.0 | 0 |

The wrong-value example has one missed required triple and one unauthorized actual triple. It is not counted as a collateral change because the target cell was meant to change. The extra r2 write is reported under multiple diagnostics but contributes one exact case failure.

## 6. Reference lifecycle and governance

### 6.1 Separate content, review submissions, and lifecycle events

Reference content is the immutable object defined in Section 4. A review submission is a separate immutable artifact. A lifecycle event is a separate append-only record that references content and/or review hashes. No lifecycle field is inserted into reference bytes, and review submissions are never overwritten by later adjudication.

Current status is derived by replaying a reference's valid lifecycle events in sequence. A state label is not authoritative if the event chain is absent, reordered, hash-invalid, or contains an illegal transition. Events have unique IDs and monotonically increasing per-reference sequence numbers; each carries the previous event hash (empty only for the first event). An event's hash is SHA-256 over its exact stored bytes and is recorded in a separate local index, never inside the event itself; the next event may refer to that hash. This creates an append-only chain without self-reference.

### 6.2 Lifecycle states and transitions

Derived states:

- `draft`: reference content exists, with no accepted human review event;
- `reviewed`: a human review submission has been recorded;
- `adjudicated`: an adjudicator has recorded a decision after review; unresolved cases cannot advance;
- `approved`: a distinct authorized human approver has approved this exact content/review set;
- `frozen`: one or more separate freeze events bind this approved content to specific run manifests;
- `superseded`: a supersession event links this immutable content to a replacement revision;
- `ambiguous`: a recorded decision says multiple defensible interpretations remain;
- `quarantined`: an input/reference defect or unresolved issue excludes the content from grading.

Permitted event transitions:

The authoritative transition set is:

```text
created -> reviewed | ambiguous | quarantined
reviewed -> adjudicated | ambiguous | quarantined
adjudicated -> approved | ambiguous | quarantined
approved -> frozen | superseded | quarantined
frozen -> frozen (additional run binding) | superseded | quarantined
```

`created` is the initial event-derived draft state. All other transitions are invalid. `ambiguous` and `quarantined` are terminal for that content revision; clarification creates a new `reference_id`, increments `revision`, and starts a new event chain with `created` plus fresh review submissions. A `superseded` event requires both `replacement_reference_id` and `replacement_reference_hash`. Supersession never changes old content, review bytes, events, or prior manifests. A frozen revision remains valid for every run named by one of its freeze events even after later supersession, but it must receive a new freeze event before binding to another run.

For primary evaluation, approval is additionally gated by the linked authorization sidecar: it must have `resolution_status: "resolved"`, valid source and authorization hashes, complete resolved fields, and successful temporal reconciliation whenever temporal conditions exist. An approval event cannot override a failed or unresolved sidecar. If such a defect is discovered after approval or freezing, append a `quarantined` lifecycle event as a recorded terminal governance response, retain prior event and report bytes unchanged, and exclude the revision from new grading. This is a governance invalidation of future use, not a rewrite of historical events or results.

This later-defect response is the sole additional lifecycle transition: `approved → quarantined` and `frozen → quarantined`. It uses the existing `quarantined` event type and its required reason/evidence fields. Previously completed runs and their reports remain immutable historical artifacts; they are not silently regraded. A newly initiated run, and any run not yet graded, must exclude the quarantined revision.

### 6.3 Lifecycle event schema

Example:

```json
{
  "event_schema_version": "acac-lifecycle-1.0",
  "event_id": "evt-004",
  "reference_id": "ref-case-001-r1",
  "reference_content_hash": "sha256:...",
  "sequence": 4,
  "event_type": "frozen",
  "actor": {"actor_id": "owner-1", "role": "approver"},
  "occurred_at": "2026-02-06T00:00:00Z",
  "evidence_hashes": ["sha256:...", "sha256:..."],
  "reason": "Approved after reviewing the recorded adjudication.",
  "run_id": "run-001",
  "manifest_hash": "sha256:...",
  "previous_event_hash": "sha256:..."
}
```

Required for every event: schema version, event ID, reference ID/content hash, sequence, event type, actor, RFC 3339 occurrence time with explicit offset, `evidence_hashes` (possibly empty), reason, and previous event hash (empty string only for sequence 1). Event types are `created`, `reviewed`, `adjudicated`, `approved`, `frozen`, `superseded`, `ambiguous`, and `quarantined`. Actor roles are `reference_author`, `human_reviewer`, `adjudicator`, and `approver`: `created` requires the author; `reviewed` requires a human reviewer; `adjudicated` requires an adjudicator; `approved`, `frozen`, and `superseded` require the owner-designated approver; ambiguous/quarantined events require a human reviewer or adjudicator.

Conditional fields: `replacement_reference_id` and `replacement_reference_hash` are required only for `superseded`; `run_id` and `manifest_hash` are required only for `frozen`; all conditional fields are forbidden on other event types. No null values are used. An `approved` event must include hashes of the adjudication and human review submissions it considered. A `frozen` event must include the run ID and exact-byte SHA-256 of the completed run manifest. The event's always-required `reference_content_hash` is the exact-byte SHA-256 for that reference revision. An `ambiguous` or `quarantined` event must include a concrete reason and evidence hashes where available.

Evidence hashes in lifecycle events identify immutable review, adjudication, approval, or other retained evidence artifacts directly. They are exact-byte hashes, not `evidence_id` registry references. Event-specific minimum evidence requirements are: `created` may have an empty array; `reviewed` must include the human review submission hash; `adjudicated` must include the adjudication artifact hash and hashes of all review submissions considered; `approved` must include at least one human review submission hash and the adjudication artifact hash; `frozen` must include the completed manifest hash in `manifest_hash` and may include additional evidence hashes; `superseded` must include the replacement reference hash in its conditional field and may include supporting evidence hashes; `ambiguous` and `quarantined` must include supporting evidence hashes when such evidence exists. These requirements do not turn a hash into proof of identity.

### 6.4 Approval, trust, and freezing

V1 uses local trusted files, not a remote registry or signature infrastructure. Trust is established by explicit human approval events and verified SHA-256 hashes over reference content, authorization spec, review submissions, lifecycle events, and run manifest. The project must keep these artifacts in a controlled local directory and record who received/approved them. Hashes detect changes; they do not prove the real-world identity of a person or prevent a privileged operator from replacing every artifact. Public claims must not imply cryptographic signatures or tamper-proof storage.

The reference author, reviewer, adjudicator, and approver have distinct provenance roles. For any reference used in primary evaluation, the approver must be an owner-designated human and must not be the reference author. AI reviewers cannot approve. At least one human review submission must exist. The same human may review and adjudicate only if the limitation is recorded; adjudication is not independent validation.

The owner-designated approver is a project governance appointment, not an implementation default. No reference can enter `approved` status for primary evaluation until an actual approver has been appointed and the approver is distinct from the reference author.

An independence declaration states whether the actor worked without access to the other submission(s), draft answers, or prior adjudication conclusions that the declared review was intended to be independent of. `true` requires a written basis describing the isolation; `false` or unknown must be recorded accurately and does not become independent agreement. A review may be independent, an adjudication is a reasoned resolution that may consider all submissions, and approval is an authorization decision; none of these labels may be substituted for another.

Approved but unfrozen references are eligible for primary grading. The run manifest records the exact reference content hash, authorization-spec hash, and approval-event hash and reports the reference as `approved_unfrozen`.

For a post-execution freeze, the valid order is:

1. Execute the scheduled model calls.
2. Preserve and hash every raw output.
3. Complete the manifest for the executed run.
4. Record the separate freeze event containing `run_id`, completed manifest hash, reference-content hash, UTC timestamp, and approver identity.
5. Perform grading and public publication.

A “completed run” is the immutable set of executed outputs and the manifest whose required hashes, configuration, grader version, and case coverage have been finalized; it is not merely a planned run. A freeze recorded after execution but before grading is valid for that completed run and must be reported as a **post-execution freeze**. “Freeze before a run” means the freeze event is recorded before any model execution for that run; this is an optional pre-registration workflow. A freeze recorded after grading or publication cannot be used to claim that the run was frozen before grading or publication, and must not be represented as a valid pre-grading freeze.

The run manifest contains the reference hash but never the freeze-event hash. The freeze event is stored outside the manifest and points to it. Thus no artifact's hash depends directly or indirectly on itself.

Public reports must state whether each reference was `approved_unfrozen` or `frozen`, identify the reference content and approval-event hashes, and disclose the human-review governance basis. An unfrozen reference may be used for primary grading but is not described as run-locked. Freeze is run-specific. A post-execution freeze is valid only when recorded before grading/publication; it must never be described as pre-run registration. A frozen reference is eligible only for a run whose manifest is named in a valid freeze event for that reference. An additional run requires a new freeze event while preserving all earlier events.

### 6.5 Review submission provenance

Each human review submission is a separate immutable JSON artifact containing reviewer ID or stable pseudonym, role, source hashes, completed time, reviewed scope, proposed edits, rationale, ambiguity notes, and an explicit `independence_declaration` Boolean plus its meaning. False or unknown independence must be recorded accurately; an AI audit has role `ai_auditor` and cannot claim human independence. A review submission hash is referenced by lifecycle events but is not embedded in or used to mutate reference content.

An adjudicator's submission is a distinct immutable adjudication artifact, not a status flag on an earlier review. It uses `reviewer_role: "adjudicator"` and must contain the source case, authorization-spec and reference-content hashes, hashes or IDs of every review submission considered, a case-by-case disagreement disposition, the adjudicator's decision rationale, an explicit independence declaration and basis, the adjudicator identity, and an RFC 3339 completion timestamp. Its exact-byte hash is the adjudication evidence referenced by the `approved` lifecycle event. Approval cannot rely on an unrecorded conversation or on modifying a prior review submission. Review records document observations; adjudication resolves recorded disagreements; approval is the separate owner-authorized acceptance of immutable reference content.

Artifact schemas are mutually exclusive. An ordinary human review submission has `reviewer_role: "human_reviewer"` and the Section 8.2 human-review fields; it must not contain adjudication-only fields. An adjudication artifact has `reviewer_role: "adjudicator"` and exactly the adjudication fields required above, including considered-review hashes or IDs, disagreement disposition, rationale, independence declaration and basis, adjudicator identity, source hashes, and completion timestamp; it is not accepted as an ordinary review. An AI audit has `reviewer_role: "ai_auditor"` and the model metadata required by Section 8.2; it cannot satisfy the human-review or adjudication requirement. A role/artifact mismatch invalidates the artifact and its dependent lifecycle event.

Model run provenance separately records provider, model family, exact model/version or endpoint identifier, API/runtime version where available, prompt hash, configuration/settings, run timestamp, raw-output hashes, and grader version. If no model output exists, model fields are omitted as a group; a manifest cannot contain a partial model identity.

## 7. Hashing and reproducibility

Every artifact has an exact-byte SHA-256 over the actual bytes stored. This includes whitespace, line endings, key order, and token spelling.

Canonical semantic hashing operates only on strictly valid parsed data and uses UTF-8 JSON with:

- object keys sorted by Unicode code point;
- no insignificant whitespace;
- strings preserved exactly, with no trimming or Unicode normalization;
- booleans serialized as `true` or `false`;
- integers serialized in canonical base-10 form as specified above;
- no floating-point values in case, ledger, patch, authorization, reference, review, or lifecycle fields; metric ratios and model settings use the separately defined exact-decimal representation below;
- ledger rows sorted by `record_id`;
- field declaration arrays sorted by `(table, field)`;
- instruction update arrays kept in sequence order;
- `eligible_keys` and preservation key arrays sorted lexicographically by their address tuples;
- patch `edits` sorted by `(table, record_id, field)` for semantic hashing only (raw patch order remains available and operation order is semantically irrelevant);
- `evidence_registry` sorted by `evidence_id`;
- `predicate_definitions` sorted by `predicate_id`;
- `exclusions` sorted by `exclusion_id`;
- `exceptions_applied` sorted by `exception_id`;
- `temporal_rules` sorted by `(source_location, occurrence_index, rule_id)` for semantic hashing;
- `resolution_issues` sorted by `issue_id`;
- `excluded_cases` sorted by `case_id` for semantic hashing;
- `scheduled_case_ids` and `executed_case_ids` sorted lexicographically for semantic hashing;
- `temporal_conditions` retain their source-array order because that order is part of their source identity;
- other arrays retain order unless their schema explicitly declares set semantics.

The manifest's model `settings` object is a separately typed configuration object. V1 permits only JSON objects, arrays, strings, booleans, integers within the signed 64-bit range, and finite decimal numbers in this object. Metric ratios that are defined as finite decimals use the same exact-decimal representation. Decimal values in these permitted locations are serialized using the following deterministic rule: parse the JSON numeric token as an exact decimal value, reject non-finite values, normalize exponent notation to plain decimal notation, remove unnecessary trailing fractional zeros and a trailing decimal point, and serialize negative zero as `0`. The original raw artifact remains available and is covered by its exact-byte hash. No binary floating-point conversion may be used to derive the semantic representation. If an implementation cannot preserve and normalize a decimal token exactly, it must reject that decimal value rather than silently round it. This exception applies only to `model.settings` and metric ratios explicitly defined as finite decimals; it does not permit floating-point values in annotation data, patches, authorization specs, references, or other core fields.

Semantic-hash invariance tests must show identical hashes when only insignificant whitespace, object key order, ledger row order, field declaration order, patch operation order, or the ordering of arrays explicitly declared to have set semantics changes. They must show different hashes for changed values, IDs, strings, update order, timestamp/boundary changes, or authorization/reference content. Equivalent integer spellings are not normalized because noncanonical spellings are rejected; for example, `2` is accepted while `2.0` is rejected in integer fields.

Each run manifest links exact and semantic case hashes, authorization-spec hash, exact reference-content hash, approval-event hash, exact raw-output hash, prompt hash, configuration hash, grader/package version, run ID, model metadata when applicable, and UTC creation time.

Hash dependency rules are acyclic: reference content does not contain lifecycle-event hashes; review submissions refer to content hashes; approval events refer to content and review hashes; the run manifest refers to content and approval-event hashes; a freeze event refers to the run-manifest hash and reference-content hash. The manifest never contains the freeze-event hash. Supersession events may link the old content hash to a new content hash, but neither reference content embeds lifecycle hashes. Hashing an event includes its previous-event hash, which points only backward.

## 8. Run, result, and review schemas

### 8.1 Grading result

Example:

```json
{
  "schema_version": "acac-1.3",
  "case_id": "case-001",
  "run_id": "run-001",
  "contract_valid": true,
  "exact_edit_set_valid": false,
  "metrics": {
    "correct_target_count": 1,
    "correct_replacement_count": 0,
    "missed_corrections": 1,
    "unauthorized_edits": 1,
    "scope_violations": 0,
    "collateral_changes": 0,
    "preservation_accuracy": 1.0
  },
  "diagnostics": [],
  "provenance": {
    "case_exact_hash": "sha256:...",
    "authorization_spec_hash": "sha256:...",
    "reference_hash": "sha256:...",
    "approval_event_hash": "sha256:...",
    "reference_governance_status": "approved_unfrozen",
    "raw_output_hash": "sha256:...",
    "prompt_hash": "sha256:...",
    "configuration_hash": "sha256:...",
    "grader_version": "acac-grader-1.3"
  }
}
```

All fields shown are required. `reference_governance_status` is `approved_unfrozen` or `frozen`. For `approved_unfrozen`, no freeze-event hash is present. For `frozen`, provenance additionally requires `freeze_event_hash`, identifying the valid event binding this `run_id` and exact manifest hash to the reference content hash. Metric values are integers or finite decimals; use a tagged `{ "status": "not_applicable", "reason": "..." }` object for N/A. JSON null is forbidden. Structural invalidity reports exact validity zero and N/A for ledger-dependent metrics.

### 8.2 Review record

Human review example:

```json
{
  "review_id": "review-001",
  "case_id": "case-001",
  "reviewer_id": "human-1",
  "reviewer_role": "human_reviewer",
  "independence_declaration": true,
  "independence_basis": "I derived this review without seeing draft answers or another reviewer submission.",
  "source_case_hash": "sha256:...",
  "authorization_spec_hash": "sha256:...",
  "reference_content_hash": "sha256:...",
  "review_scope": ["case-001"],
  "eligible_keys": [["L", "r1", "label"]],
  "proposed_edits": [],
  "ambiguity_notes": [],
  "decision_reason": "...",
  "completed_at": "2026-02-05T00:00:00Z"
}
```

All shown fields are required for a human review. A human review submission uses only `reviewer_role: "human_reviewer"`; author and approver actions are lifecycle events, not review submissions. `independence_declaration` is Boolean and `independence_basis` is required even when it explains that the review was not independent. Human review timestamps use RFC 3339 with an explicit offset; UTC `Z` is preferred but not mandatory.

AI audit records use `reviewer_role: "ai_auditor"`, omit the human independence fields, and require a complete `model_metadata` object with provider, family, model ID, exact version/immutable endpoint revision, runtime/API version (or documented unavailability), prompt hash, settings, and run timestamp. An AI audit is never a human review submission and cannot satisfy the minimum human-review requirement.

The separate adjudication artifact uses `reviewer_role: "adjudicator"` and is governed by Section 6.5. The role values are mutually exclusive and must match the artifact type. Reviews are immutable standalone artifacts identified by exact-byte hash. Lifecycle events reference review hashes; reviews have no lifecycle status and are never overwritten. A corrected submission creates a new `review_id` with `supersedes_review_id` (omit for the first version).

### 8.3 Run manifest

Example:

```json
{
  "manifest_version": "1.3",
  "run_id": "run-001",
  "mode": "instruction_resolution",
  "scheduled_case_ids": ["case-001"],
  "executed_case_ids": ["case-001"],
  "excluded_cases": [],
  "case_hashes": {
    "case-001": {"exact": "sha256:...", "semantic": "sha256:..."}
  },
  "authorization_spec_hashes": {"case-001": "sha256:..."},
  "reference_hashes": {"case-001": "sha256:..."},
  "approval_event_hashes": {"case-001": "sha256:..."},
  "raw_output_hashes": {"case-001": "sha256:..."},
  "prompt_hash": "sha256:...",
  "configuration_hash": "sha256:...",
  "model": {
    "provider": "provider-name",
    "family": "model-family",
    "model_id": "model-id",
    "version": "exact-version-or-endpoint-revision",
    "runtime_version": "client-or-api-version",
    "settings": {"temperature": 0}
  },
  "grader_version": "acac-grader-1.3",
  "created_at": "2026-02-06T00:00:00Z"
}
```

Required fields: `manifest_version`, `run_id`, `mode`, `scheduled_case_ids`, `executed_case_ids`, `excluded_cases`, all five hash-map members, prompt/configuration/grader versions, and UTC `created_at`. `scheduled_case_ids` is the complete planned case set. `executed_case_ids` contains every scheduled ID for which a model output was produced; every executed ID must be scheduled. `excluded_cases` is an array of `{case_id, reason}` for scheduled cases intentionally not executed or not eligible for grading; an executed case may also appear in `excluded_cases` when its output exists but is ineligible. `case_hashes` and `raw_output_hashes` are mandatory maps; the three authorization/reference/approval maps are present but may have fewer entries when artifacts legitimately do not exist. A scheduled case with no output has no raw-output hash and is represented by its exclusion record.

`mode` is `instruction_resolution` or `resolved_contract`. `model` is required as a complete object whenever `raw_output_hashes` is nonempty and is omitted entirely when there is no model output. Its required fields are provider, family, model ID, version or immutable endpoint revision, runtime version (or the explicit string `unavailable`), and a settings object. No partial model identity is accepted. Each `reference_hashes` value is the exact-byte hash of immutable reference content; `approval_event_hashes` identifies the valid approval event used at run start. Do not add a freeze-event hash to the manifest: the separate freeze event contains the manifest hash, so doing so would create a cycle.

Formally, for every completed manifest:

`scheduled_case_ids = executed_case_ids ∪ {case_id from excluded_cases}`; the intersection is permitted exactly when an executed case is excluded from grading.

Every ID in `executed_case_ids` and every ID named by `excluded_cases` must be scheduled; IDs within each collection are unique. `case_hashes` and `raw_output_hashes` must have exactly the key set `executed_case_ids`; conditional artifact maps are validated by the coverage rule below. A scheduled case with no model output and an exclusion reason has no raw-output hash. A manifest failing this coverage rule is invalid.

For an executed case, the referenced authorization sidecar must have `resolution_status: "resolved"`, valid source and artifact hashes, complete resolved fields, and successful temporal reconciliation whenever temporal conditions exist. Otherwise the case is not eligible for grading and must be represented in `excluded_cases`; no approval event can waive this gate.

The authoritative manifest coverage rule is: `executed_case_ids` contains every scheduled case that produced a model output, including outputs later found ineligible. `excluded_cases` contains scheduled cases intentionally excluded from grading and may overlap `executed_case_ids` when an output exists but the case is unresolved, unreconciled, hash-invalid, missing a required artifact, or otherwise ineligible. Every scheduled ID must appear in at least one of these sets; every executed and excluded ID must be scheduled; IDs within each list and `excluded_cases` records must be unique.

`case_hashes` and `raw_output_hashes` are mandatory for every executed case and must have exactly the key set `executed_case_ids`; each entry contains the required exact hash (and the case hash also contains its required semantic hash). `authorization_spec_hashes`, `reference_hashes`, and `approval_event_hashes` are conditional maps. When the corresponding artifact exists for an executed case, the map contains its exact-byte hash; when the artifact is legitimately absent, the map has no entry for that case. A missing authorization specification, reference, or approval event is represented by an `excluded_cases` record whose reason identifies the missing artifact and its case ID; JSON null, empty-string hash sentinels, fabricated hashes, and silent omission are forbidden. Conditional maps may contain keys only from `executed_case_ids`, and every present hash must validate against the retained artifact. Aggregation and grading exclude every ID in `excluded_cases` and every case failing the resolved-sidecar, lifecycle, hash, or temporal gates.

Each `excluded_cases.reason` is a nonempty case-sensitive code. For missing artifacts, the allowed codes are `missing_authorization_spec`, `missing_reference`, and `missing_approval_event`; when several are missing, the codes are joined with `;` in lexicographic order. Other exclusion reasons remain documented nonempty codes or controlled reason strings. This makes missing-artifact coverage machine-auditable without null sentinels or fabricated hashes.

## 9. Aggregate reporting

The per-case report includes case/reference status, contract validity, exact result, all applicable diagnostics, and metric-specific denominator status. For a no-op reference, exact validity, unauthorized count, collateral count, and preservation are reportable; edit recall/precision are N/A where denominators are zero. For a structurally invalid response, report structural diagnostics and exact validity zero; do not claim a resulting ledger or preservation score.

Primary aggregates include only scheduled cases whose reference lifecycle derives `approved` or `frozen`, whose authorization sidecar has `resolution_status: "resolved"`, whose source and artifact hashes validate, and whose temporal reconciliation has succeeded whenever temporal conditions exist. An `approved` reference is reported as `approved_unfrozen`; a `frozen` reference is included only when a valid freeze event binds it to the exact run manifest. Ambiguous, quarantined, superseded-for-new-runs, missing-reference, unresolved, unreconciled, or hash-mismatched cases are excluded and listed by case ID and reason. Report scheduled/included/excluded counts and each metric denominator. Public reports expose the reference content hash, approval-event hash, governance status, and freeze-event hash when present.

Aggregate exact validity is the arithmetic mean of case-level binary exact indicators. Missed, unauthorized, scope, and collateral counts are summed separately and never added into an overall error total. Preservation is micro-averaged over required-preservation cells, with per-table results where applicable. Structural failure rates and semantic/authorization rates use separate denominators. Family-level macro averages may be included as secondary summaries.

## 10. Local-first Python V1 scope

Keep the one-developer V1 scope:

- local CLI and Python API;
- strict JSON parsing;
- both profiles;
- pure in-memory application;
- deterministic grading;
- hashing and manifests;
- JSON and Markdown reports;
- offline tests;
- no provider client;
- no production write path.

`replace` remains the only operation. EvalScope and annotation-platform integrations remain deferred.

## 11. Owner decisions and deferred choices

### Decisions specified by the project direction and this specification

- ACAC remains a local-first, proposal-and-audit Python package with the existing two profiles and V1 scope.
- Reference content is immutable; lifecycle changes are separate append-only events.
- A local trusted-file workflow verifies hashes and requires explicit human approval.
- The approver must differ from the reference author for primary evaluation; AI cannot approve.
- Approved but unfrozen references are eligible for primary grading and must be identified as unfrozen in public reporting.
- Freeze is a separate event that points to the run manifest; the manifest must not point back to the freeze event.
- Every eligible key has exactly one resolved required value, even if no replacement is needed.
- The resolved authorization sidecar is authoritative for grading; natural-language interpretation is not delegated to the deterministic grader.
- Historical `M` and `H` fields are immutable; only explicitly mutable `W` fields may contain eligible cells.
- Temporal event identity is separate from per-instruction temporal thresholds and boundaries.

### Remaining owner approvals

1. Appoint the actual human approver/role-holder before a reference can be approved.
2. Confirm Apache-2.0 as the package license.
3. Confirm the signed 64-bit integer range for annotation integer fields.
4. Confirm the proposed predicate resource limits of 8 nesting levels and 64 nodes, or choose different limits.
5. Define the local controlled-directory access and backup policy for trusted reference and lifecycle files. Hash verification detects changes but does not authenticate identities or prevent privileged replacement.

### Safe to defer

- EvalScope and annotation-platform integrations.
- CSV import, dashboards, direct execution, rollback, multi-reference scoring, nested values, and model-provider clients.
- Future schema support for null and floating-point annotation values.

## 12. v1.3.8 correction change log

1. **Sections 1.4, 1.6, and 2 — temporal conditions.** Separated the governing-event field locator from each temporal condition. The sidecar now represents each effective threshold and inclusive/exclusive boundary as an individual `temporal_rules` entry linked to an instruction and predicate. Multiple updates can share one timestamp field without sharing thresholds or boundaries.
2. **Sections 1.5.1 and 1.6 — evidence registry.** Defined which case-level evidence references use registry IDs and which review/adjudication/lifecycle artifacts use direct exact-byte hashes. Defined registry membership, hash validation, and quarantine behavior.
3. **Sections 1.5.1 and 1.6 — ID namespaces.** Distinguished duplicate definitions from repeated references. Repeated references to a valid ID are allowed; duplicate definitions, invalid set duplicates, unresolved references, and wrong-namespace references are rejected.
4. **Sections 6.3 and 6.4 — freeze timing.** Reconciled post-execution freezing with the prohibition on retroactive claims. A post-execution freeze is valid only when recorded after manifest completion and before grading/publication; it is not pre-run registration.
5. **Section 7 — semantic array ordering.** Explicitly declared semantic set ordering for evidence, predicate, exclusion, and exception registries.
6. **Sections 7 and 8.3 — model settings.** Defined a separately typed canonical representation for finite decimal values in `model.settings`, without permitting floats in annotation data, patches, authorization specs, references, or metrics.
7. **Section 1.6 — example consistency.** Standardized the notice ID as `notice-1` throughout the example.
8. **Section 1.5 — historical scope resolution.** Clarified that historical target fields resolve only within `W`; `M` and `H` cannot be targets.
9. **Sections 1.6, 6.3, and 8.2 — timestamp provenance.** Clarified that provenance timestamps require explicit RFC 3339 offsets; UTC `Z` is accepted, and UTC is preferred for human review records.
10. **Section 6.3 — lifecycle evidence.** Added event-specific minimum evidence-hash requirements and clarified that lifecycle evidence hashes point directly to immutable artifact bytes.

11. **Section 1.6 — status-dependent sidecar schema.** Distinguished complete `resolved` sidecars from `ambiguous` and `quarantined` records. Unresolved records require identity, source integrity, issue evidence, and human provenance, but do not require or permit guessed eligibility or final-value coverage; they cannot be graded or approved.
12. **Sections 1.6 and 1.4 — temporal reconciliation.** Required a one-to-one mapping between every temporal condition in the case input and a sidecar `temporal_rules` entry, including threshold, boundary, instruction, and predicate association. Any mismatch or ambiguity is recorded and quarantines the sidecar; the sidecar is authoritative only after successful reconciliation.
13. **Document versioning — schema compatibility.** Clarified that v1.3.8 preserves `acac-1.3`, manifest `1.3`, and `acac-grader-1.3`; temporal authorization sidecars use `acac-auth-1.1`, while non-temporal `acac-auth-1.0` sidecars remain valid.

14. **Section 8.3 — manifest coverage.** Execution and grading eligibility are now separate: executed cases include every model output, excluded cases may overlap executed cases, hash maps cover exactly executed cases, and aggregation excludes all excluded or otherwise ineligible cases.
15. **Section 6.2 — lifecycle quarantine.** Added `approved → quarantined` and `frozen → quarantined` to the authoritative transition graph and aligned the later-defect governance rule.
16. **Section 1.6 — temporal schema and reconciliation.** Consolidated temporal rules to one eight-field schema, made `temporal_reconciliation` conditionally required, and replaced free-text source extraction with structured case conditions.
17. **Sections 1.5.1 and 1.6 — explicit predicates.** Every temporal rule now requires a valid predicate; all-record scopes use explicit `record_ids` predicates listing every applicable record.
18. **Section 13 — acceptance criteria.** Updated criteria A–AD for the corrected manifest, lifecycle, temporal-schema, structured-source, and predicate rules.
19. **Section 8.3 — conditional artifact coverage.** Required case/raw-output hashes for every executed case, made authorization/reference/approval hashes conditional on artifact availability, and required explicit exclusion reasons for missing artifacts.
20. **Sections 1.1, 1.4, 1.5, 1.6, and 2 — temporal source consistency.** Required exact agreement between notice/update fields, structured case conditions, and sidecar rules; V1 now uses one governing-event field per case.
21. **Section 1.5.1 — timestamp predicate separation.** Prohibited timestamp range operators in predicates and reserved effective-time comparison for temporal rules.
22. **Sections 6.5 and 8.2 — artifact roles.** Clarified mutually exclusive human-review, adjudication, and AI-audit schemas.
23. **Section 7 — canonical ordering.** Added deterministic ordering for temporal rules, resolution issues, and exclusion records while retaining source order for temporal conditions.
24. **Sections 1.1, 1.5, and 1.6 — governing-event inheritance.** Kept the temporal-rule schema at exactly eight fields; temporal rules inherit the single sidecar governing event, which must match every structured condition and notice/update locator.
25. **Section 1.6 — model visibility.** Defined the exact instruction-resolution projection and the exact resolved-contract fields; trusted structured temporal conditions remain hidden from instruction-resolution prompts.
26. **Sections 1.5.1 and 2 — timestamp predicates.** Prohibited every authorization predicate operator on timestamp-formatted fields and reserved effective-time comparison for temporal conditions and reconciled rules.
27. **Section 1.1 — original-instruction temporal source.** Required `instruction_id: "original"` structured conditions for temporal assertions in the original guideline and prohibited free-text extraction or guessing.
28. **Section 1.6 — consolidation.** Removed the contradictory governing-event copy requirement and retained one authoritative conditional reconciliation rule.

## 13. Normative acceptance criteria

The following criteria are required for approval, grading, and publication decisions. “Reject” means the reference is not approved or graded; “quarantine” means the defect is recorded and the case is excluded until a new reviewed revision exists.

- **A. Ambiguous sidecar:** `resolution_status="ambiguous"` rejects approval, grading, and aggregation.
- **B. Quarantined sidecar:** `resolution_status="quarantined"` rejects approval, grading, and aggregation.
- **C. Missing/unsupported status:** missing or unsupported `resolution_status` is schema-invalid and quarantined.
- **D. Source mismatch:** resolved sidecar source-case or authorization hash mismatch rejects reference integrity.
- **E. Incomplete resolved coverage:** missing, duplicate, or extra eligible/final-value coverage rejects reference integrity.
- **F. Fully resolved sidecar:** resolved status, valid hashes, complete fields, and successful reconciliation permit approval subject to lifecycle and human-governance rules.
- **G. Approval override:** an approval event cannot make an unresolved or invalid sidecar eligible.
- **H. Later defect:** a defect found after approval/freeze requires an appended quarantine event; history is retained and new grading is blocked.
- **I. Ambiguous schema:** an ambiguous sidecar with common identity, issue records, and provenance but no resolved-only fields is a valid unresolved record and never gradable.
- **J. Quarantined schema:** a quarantined sidecar with common identity, issue records, and provenance but no resolved-only fields is a valid quarantine record and never gradable.
- **K. Resolved-only leakage:** an unresolved sidecar containing eligibility, required values, preservation, predicates, or temporal rules is invalid and quarantined.
- **L. Unresolved evidence IDs:** non-empty unresolved issue evidence IDs without exactly matching minimal registry entries are invalid and quarantined.
- **M. Empty unresolved registry:** all unresolved issue evidence-ID arrays empty and registry omitted or `[]` is a valid unresolved representation.
- **N. Missing temporal sidecar:** a temporal case without a structured `temporal_conditions` entry or required reconciliation is quarantined.
- **O. Extra temporal rule:** a sidecar rule with no one-to-one structured case condition is quarantined.
- **P. Temporal threshold/boundary mismatch:** any mismatch is quarantined.
- **Q. Instruction/predicate mismatch:** a wrong instruction or predicate association is quarantined.
- **R. Structured source conditions:** every temporal assertion is represented by one structured case entry and one sidecar rule; free-text-only assertions are quarantined.
- **S. Source identity:** each structured condition has a unique JSON Pointer, `condition_id`, and zero `occurrence_index`; duplicate identity is quarantined.
- **T. Unsuccessful reconciliation:** temporal conditions without successful one-to-one reconciliation are ineligible for approval, grading, and aggregation.
- **U. Non-temporal case:** no temporal condition means no temporal rules or reconciliation object; a valid non-temporal sidecar remains allowed.
- **V. Valid approval hash:** a valid approval-event hash does not waive any authorization-sidecar gate.
- **W. Manifest eligibility:** `executed_case_ids` includes every produced output, excluded cases may overlap executed cases, and unresolved or unreconciled references are excluded from grading and aggregation.
- **X. Aggregate eligibility:** aggregate denominators include only resolved, hash-valid, lifecycle-approved/frozen cases meeting temporal gates.
- **Y. Governance labels:** approved-unfrozen and frozen reporting remains distinct; frozen status requires a valid run-specific freeze binding.
- **Z. Manifest artifact coverage:** case and raw-output hashes exist exactly for executed cases; conditional authorization, reference, and approval hashes are present only when their artifacts exist, with missing artifacts represented by explicit controlled exclusion codes.
- **AA. Governing-event identity:** every temporal condition and rule resolves to the single case governing-event field; a case requiring multiple fields is quarantined.
- **AB. Timestamp predicate separation:** every authorization predicate operator (`eq`, `neq`, `in`, `not_in`, `lt`, `lte`, `gt`, or `gte`) on a timestamp-formatted field is invalid; timestamp parsing and validation remain allowed, and effective-time comparison occurs only in temporal conditions and reconciled temporal rules.
- **AC. Artifact roles:** human review, adjudication, and AI audit role values and required fields are mutually exclusive and type-checked.
- **AD. Canonical ordering:** arrays declared as sets have specified semantic ordering; source-ordered temporal conditions retain source order.
- **AE. Model visibility:** instruction-resolution prompts exclude structured temporal conditions and authorization answers; resolved-contract prompts may expose only the explicitly listed `scope_contract` fields, while trusted reconciliation and grading retain the complete case bundle.
- **AF. Original temporal source:** a temporal applicability assertion from `original_guideline` requires exactly one structured condition with `instruction_id: "original"`; the resolver validates it against the original text and structured evidence without free-text extraction or guessing.
- **AG. Governing-event agreement:** the sidecar's single case-level governing event, every structured condition, and every temporal notice/update locator must match exactly; a multi-field requirement quarantines the case.

## 14. Consistency audit

The following checks are normative for this revision:

- **Naming:** single-ledger examples and edit addresses use `L`; historical examples use `M`, `H`, and `W`. No public single-ledger object uses `W`.
- **Reference status:** `approved` and `frozen` both qualify for primary grading. Status derives from events; freeze adds run-specific binding without changing reference content.
- **Application:** any structural contract failure blocks the entire in-memory patch. A structurally valid semantic or unauthorized proposal is applied only to an isolated copy so collateral impact remains auditable.
- **Authorization:** natural language is model-facing evidence; trusted resolved authorization is a human-authored reference-side sidecar. Every eligible key has one required value. The grader does not claim to parse arbitrary instructions.
- **Status gate:** only `resolution_status: "resolved"` sidecars with valid hashes and complete fields are eligible for approval or grading; temporal cases additionally require successful one-to-one reconciliation.
- **Types:** null and floats are rejected in core annotation and authorization data. Boolean and integer tokens are distinct; integers have one lexical form and signed 64-bit bounds. Exact decimals are permitted only for model settings and metric ratios explicitly defined as finite decimals.
- **Reference integrity:** expected edits derive from the initial ledger plus resolved authorization; applying them must exactly yield the final ledger; provenance refers to source-case and authorization-spec hashes.
- **Time:** every temporal rule names its governing event field, effective threshold, and inclusive/exclusive boundary. Missing or ambiguous evidence quarantines affected scope.
- **Structured temporal source:** every temporal applicability assertion is represented in `payload.temporal_conditions`; free-text-only temporal assertions are unsupported and quarantined.
- **Governing event:** V1 permits one governing-event field per case, and all notice, update, condition, and sidecar temporal references must match it.
- **Original temporal source:** an assertion in `original_guideline` uses a condition with `instruction_id: "original"`; the human resolver validates the original text against the structured fields and retained evidence without extracting or guessing from prose.
- **Model visibility:** instruction-resolution receives the defined case projection without `temporal_conditions` or authorization answers; resolved-contract receives only the defined `scope_contract`; trusted reconciliation and grading retain the complete case bundle.
- **Temporal updates:** multiple rules can use one event field while retaining independent thresholds and boundaries.
- **Temporal identity:** every temporal condition is identified by exact RFC 6901 source location, occurrence index, and unique source-condition ID; missing, extra, conflicting, or multiply mapped conditions quarantine.
- **Temporal predicates:** every temporal rule references a valid explicit predicate; all-record scope uses a complete `record_ids` predicate.
- **Timestamp predicates:** all authorization predicate operators are prohibited on timestamp-formatted fields; timestamp parsing/validation remains allowed, and effective-time comparison is performed only by temporal conditions and reconciled temporal rules.
- **Historical mutability:** `M` and `H` are always immutable declarations; only explicitly mutable fields on `W` can be eligible.
- **Cell eligibility:** `W`-field mutability is a capability, not blanket authorization; each eligible cell must be explicitly listed in the trusted sidecar.
- **Evidence:** case-level evidence IDs resolve through the authorization-spec evidence registry; review, adjudication, reconciliation, and lifecycle artifacts use direct exact-byte hashes unless explicitly cited as case evidence.
- **No-op:** no-op notices use an explicit empty scope and empty eligible/value/edit sets, so scope validation remains active.
- **Predicates and IDs:** depth starts at 1, every predicate object counts, limits are per definition, namespaces are explicit, and repeated valid references are distinguished from duplicate definitions.
- **Declarations:** `(table, field)` and metadata field names are unique.
- **Governance:** adjudication is an immutable evidence artifact distinct from review and approval; independence is declared rather than inferred.
- **Run coverage:** manifests list all scheduled cases; executed IDs include every produced output, may overlap excluded IDs, case/raw-output maps cover exactly executed IDs, conditional artifact maps contain only available artifacts, missing artifacts have explicit exclusion reasons, and all excluded or otherwise ineligible cases are absent from grading aggregates.
- **Hashing:** exact-byte hash captures original bytes; semantic hash follows fixed canonicalization. Model settings use their own exact decimal normalization; annotation and authorization data do not permit floats.
- **Lifecycle:** the authoritative graph includes `approved → quarantined` and `frozen → quarantined`; reference content and review submissions are immutable, and lifecycle events are append-only.
- **Unresolved artifacts:** unresolved sidecars cannot pass approval, grading, or aggregate inclusion even when their hashes and lifecycle events are otherwise valid.
- **Versioning:** document v1.3.8 keeps case/manifest/grader artifact versions; temporal authorization sidecars use `acac-auth-1.1` and non-temporal sidecars use `acac-auth-1.0`.
- **Freeze timing:** post-execution freeze is permitted only after manifest completion and before grading/publication. It is not described as pre-run registration.
- **Hash dependencies:** run manifest includes reference and approval-event hashes; separate freeze event includes run ID, manifest hash, reference hash, timestamp, and approver; the manifest excludes the freeze-event hash, so there is no direct or indirect self-reference.
- **Metrics:** wrong target values are both missed and unauthorized; scope violation is a subset of unauthorized; collateral measures changed protected cells; diagnostic counts are not summed into a total.
- **Artifact roles:** ordinary human reviews, adjudications, and AI audits have distinct role values and schemas; role mismatches invalidate dependent governance events.
- **Canonical ordering:** set-semantic arrays have deterministic ordering, while source-ordered `temporal_conditions` retain their source order.

## 15. Implementation readiness and remaining clarifications

### Sufficiently precise for implementation after owner approval

- Public table naming and the two profile structures.
- Replace-only patch shape and exact empty representation.
- Structural failure conditions and all-or-nothing application.
- Application of structurally valid unauthorized proposals to an isolated copy.
- Metric equations, overlap handling, N/A rules, and aggregate denominators.
- Null rejection, Boolean/integer distinction, integer lexical grammar, and integer range.
- Exact-byte hashing and canonical semantic-hash ordering/invariance requirements.
- Required fields and integrity relation among case, authorization sidecar, expected output, and final ledger.
- Timestamp syntax, governing-event identity, per-rule boundary declaration, and quarantine triggers.
- Append-only revisions and state transition graph.
- Evidence registry and direct evidence-hash roles.
- Run-manifest coverage equation and exact per-case hash-map coverage.
- Structured `temporal_conditions`, one-to-one temporal reconciliation, and the authoritative eight-field temporal-rule schema.
- Explicit predicate requirements for every temporal rule and all-record scopes.
- Conditional artifact-hash coverage and explicit missing-artifact exclusion representation.
- Single governing-event identity and deterministic separation of timestamp predicates from temporal rules.
- Exact model visibility for instruction-resolution and resolved-contract modes.
- Structured representation and human reconciliation of temporal assertions originating in `original_guideline`.
- Mutually exclusive review, adjudication, and AI-audit artifact schemas.
- Canonical ordering for all newly identified set-semantic arrays.

### Still requiring owner decisions

- The actual approver identity/appointment.
- Package license.
- Confirmation of signed 64-bit integer bounds.
- Confirmation of predicate resource limits.
- Local controlled-directory custody and backup procedure.

### Implementation-readiness assessment

This revision resolves the identified document-level contradictions around temporal-rule governing-event inheritance, model visibility, timestamp predicate overlap, original-instruction temporal sourcing, manifest artifact coverage, conditional reconciliation, lifecycle quarantine, artifact roles, canonical ordering, evidence references, ID namespaces, freeze timing, model-setting decimal values, and unresolved sidecar schemas. The core validation and grading behavior is specified sufficiently to prepare a bounded implementation plan, subject to owner confirmation of the listed technical and governance decisions.

This document review is not implementation testing, independent human validation, or approval of any benchmark data, review submission, gold reference, or experiment. No implementation code, benchmark data, review submissions, gold data, model outputs, or experiments are authorized by this specification alone.

---

## Decisions awaiting project-owner approval

1. Name or appoint the human approver.
2. Confirm Apache-2.0 as the package license.
3. Confirm the signed 64-bit integer range.
4. Confirm or revise predicate tree limits (8 levels, 64 nodes).
5. Set the local controlled-directory access and backup policy.
