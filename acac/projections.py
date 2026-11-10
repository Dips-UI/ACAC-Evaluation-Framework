"""Mechanical model-facing case projections for V1."""


def _reject_nulls(value):
    if value is None:
        raise ValueError("json_null_forbidden")
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("string_object_keys_required")
        for child in value.values():
            _reject_nulls(child)
    elif isinstance(value, list):
        for child in value:
            _reject_nulls(child)


def instruction_resolution(case: dict) -> dict:
    payload = case["payload"]
    projected = {"schema_version": case["schema_version"], "profile": case["profile"], "case_id": case["case_id"], "task": case["task"], "payload": {
        "field_declarations": payload["field_declarations"],
        "ledger": payload["ledger"],
        "original_guideline": payload["original_guideline"],
        "updates": [{k: update[k] for k in ("update_id", "sequence", "kind", "text")} for update in payload.get("updates", [])],
        "notice": {k: payload["notice"][k] for k in ("notice_id", "operation", "issued_at", "authority_text") if k in payload["notice"]},
    }}
    if "metadata_declarations" in payload:
        projected["payload"]["metadata_declarations"] = payload["metadata_declarations"]
    if "record_metadata" in payload:
        projected["payload"]["record_metadata"] = payload["record_metadata"]
    return projected


def resolved_contract(case: dict, contract: dict) -> dict:
    allowed = {"contract_version", "profile", "target_fields", "predicate_definitions", "governing_event", "temporal_conditions", "exclusions", "exceptions_applied"}
    if not isinstance(contract, dict) or set(contract) != allowed:
        raise ValueError("invalid_scope_contract")
    _reject_nulls(contract)
    result = instruction_resolution(case)
    result["scope_contract"] = contract
    return result
