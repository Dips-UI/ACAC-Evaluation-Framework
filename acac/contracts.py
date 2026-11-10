"""Staged, task-aware validation. Permissions belong to scoring, not parsing."""

from dataclasses import dataclass, field
from .strict_json import JSONContractError, equal, loads, matches_type

TABLES = ("M", "H", "W")
EDIT_FIELDS = {"op", "table", "record_id", "field", "old_value", "new_value"}


@dataclass
class Validation:
    valid: bool
    stage: str | None = None
    reasons: list[str] = field(default_factory=list)
    parsed: dict | None = None
    proposed_count: int | None = None
    flags: list[str] = field(default_factory=list)


def exact_keys(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def cells(ledger):
    return {(table, row["record_id"], field): value
            for table in TABLES for row in ledger[table]
            for field, value in row["values"].items()}


def edit_key(edit):
    return (edit["table"], edit["record_id"], edit["field"])


def validate_input(document):
    """Raise for defective fixtures, never classify them as model errors."""
    def require(condition, message):
        if not condition:
            raise ValueError("invalid_input:" + message)

    require(exact_keys(document, {"schema_version", "task", "payload"}), "envelope")
    require(document["schema_version"] == "acac-1.0", "schema_version")
    require(document["task"] in ("correct_ledger", "label_records"), "task")
    p = document["payload"]
    def type_map(mapping):
        require(isinstance(mapping, dict) and bool(mapping), "field_types")
        require(all(type(k) is str and k and v in ("string", "integer", "boolean")
                    for k, v in mapping.items()), "field_type_declaration")
    def text(value):
        return type(value) is str and bool(value.strip())

    if document["task"] == "correct_ledger":
        require(exact_keys(p, {"field_types", "ledger", "original_guideline", "updates",
                               "notice", "supplied_edits"}), "correction_payload")
        require(exact_keys(p["field_types"], TABLES), "tables_in_types")
        require(exact_keys(p["ledger"], TABLES), "tables_in_ledger")
        id_sets = []
        for table in TABLES:
            ft = p["field_types"][table]
            type_map(ft)
            rows = p["ledger"][table]
            require(isinstance(rows, list) and bool(rows), "rows")
            ids = []
            for row in rows:
                require(exact_keys(row, {"record_id", "values"}), "row_shape")
                require(text(row["record_id"]), "record_id")
                ids.append(row["record_id"])
                require(exact_keys(row["values"], ft), "row_fields")
                for name, value in row["values"].items():
                    require(matches_type(value, ft[name]), "cell_type")
            require(len(ids) == len(set(ids)), "duplicate_record_id")
            id_sets.append(set(ids))
        require(id_sets[0] == id_sets[1] == id_sets[2], "unequal_record_sets")
        require(p["field_types"]["H"] == p["field_types"]["W"], "history_work_schema")
        require(text(p["original_guideline"]) and text(p["notice"]), "instruction")
        require(isinstance(p["updates"], list) and all(text(s) for s in p["updates"]), "updates")
        if p["supplied_edits"] is not None:
            from .strict_json import dumps
            v = validate_output(document, dumps({"edits": p["supplied_edits"]}), check_input=False)
            require(v.valid, "supplied_edits_contract")
    else:
        require(exact_keys(p, {"records", "field_types", "queries", "guideline", "evidence"}),
                "semantic_payload")
        type_map(p["field_types"])
        require(text(p["guideline"]), "guideline")
        require(isinstance(p["records"], list) and bool(p["records"]), "records")
        ids = []
        for row in p["records"]:
            require(exact_keys(row, {"record_id", "text"}) and text(row["record_id"])
                    and type(row["text"]) is str, "semantic_record")
            ids.append(row["record_id"])
        require(len(ids) == len(set(ids)), "duplicate_record_id")
        require(isinstance(p["queries"], list) and bool(p["queries"]), "queries")
        keys = []
        for q in p["queries"]:
            require(exact_keys(q, {"record_id", "field"}), "query_shape")
            require(type(q["record_id"]) is str and type(q["field"]) is str, "query_type")
            require(q["record_id"] in ids and q["field"] in p["field_types"], "query_address")
            keys.append((q["record_id"], q["field"]))
        require(len(keys) == len(set(keys)), "duplicate_query")
        require(set(q[1] for q in keys) == set(p["field_types"]), "unused_field_type")
        require(isinstance(p["evidence"], list), "evidence")
        for evidence in p["evidence"]:
            require(exact_keys(evidence, {"record_id", "text"}) and
                    type(evidence["record_id"]) is str and evidence["record_id"] in ids
                    and text(evidence["text"]), "evidence_record")


def validate_output(document, raw, *, check_input=True, truncated=False, refusal=False):
    if check_input:
        validate_input(document)
    flags = [name for name, active in (("truncated", truncated), ("refusal", refusal)) if active]
    # Completion metadata can establish an incomplete response even if text happens to parse.
    if flags:
        return Validation(False, "completion", flags.copy(), flags=flags)
    try:
        parsed = loads(raw)
    except JSONContractError as exc:
        return Validation(False, "parse", [str(exc)])
    correction = document["task"] == "correct_ledger"
    root = "edits" if correction else "labels"
    reasons = []
    if not exact_keys(parsed, {root}) or not isinstance(parsed.get(root), list):
        return Validation(False, "shape", ["wrong_envelope"])
    entries = parsed[root]
    fields = EDIT_FIELDS if correction else {"record_id", "field", "value"}
    for i, item in enumerate(entries):
        if not exact_keys(item, fields):
            reasons.append(f"item_{i}:wrong_fields")
        if correction and isinstance(item, dict):
            if item.get("op") != "replace":
                reasons.append(f"item_{i}:unsupported_operation")
                flags.append("unsupported_operation")
            if item.get("table") not in TABLES:
                reasons.append(f"item_{i}:invalid_table")
    if reasons:
        return Validation(False, "shape", reasons, parsed, len(entries), sorted(set(flags)))
    p = document["payload"]
    x = cells(p["ledger"]) if correction else None
    queries = set((q["record_id"], q["field"]) for q in p.get("queries", []))
    seen = set()
    for i, item in enumerate(entries):
        if type(item["record_id"]) is not str or type(item["field"]) is not str:
            reasons.append(f"item_{i}:address_type")
            continue
        key = edit_key(item) if correction else (item["record_id"], item["field"])
        if key in seen:
            reasons.append(f"item_{i}:duplicate_target")
        seen.add(key)
        if key not in (x if correction else queries):
            reasons.append(f"item_{i}:unknown_address")
            continue
        declared = p["field_types"][item["table"]][item["field"]] if correction else p["field_types"][item["field"]]
        for name in ("old_value", "new_value") if correction else ("value",):
            if not matches_type(item[name], declared):
                reasons.append(f"item_{i}:{name}_type")
    if not correction and seen != queries:
        reasons.append("query_set_mismatch")
    if reasons:
        return Validation(False, "address_type", reasons, parsed, len(entries))
    if correction:
        for i, item in enumerate(entries):
            if not equal(item["old_value"], x[edit_key(item)]):
                reasons.append(f"item_{i}:stale_old_value")
            if equal(item["new_value"], item["old_value"]):
                reasons.append(f"item_{i}:no_op")
        if reasons:
            return Validation(False, "precondition", reasons, parsed, len(entries))
    return Validation(True, parsed=parsed, proposed_count=len(entries))
