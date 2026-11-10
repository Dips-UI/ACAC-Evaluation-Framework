"""Append-only local artifacts for a later caller; no collection or model access."""

from pathlib import Path
import re

from .dataset import inside
from .strict_json import dumps


def persist_record(root, artifact_id, record, raw):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", artifact_id):
        raise ValueError("artifact_id_must_be_a_simple_filename")
    if record.get("source_kind") not in ("synthetic_test", "model_response"):
        raise ValueError("artifact_provenance_required")
    if record.get("response_received") != (raw is not None):
        raise ValueError("response_presence_mismatch")
    raw_relative = f"raw_outputs/{artifact_id}.txt"
    result_relative = f"results/per_case/{artifact_id}.json"
    raw_path, result_path = [inside(root, p) for p in (raw_relative, result_relative)]
    if raw_path.exists() or result_path.exists():
        raise FileExistsError("artifact_id_already_used")
    output = dict(record, raw_output_path=raw_relative if raw is not None else None)
    serialized = dumps(output)
    if raw is not None:
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        # newline='' preserves original CR/LF sequences and absent final newline.
        with raw_path.open("x", encoding="utf-8", newline="") as handle:
            handle.write(raw)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    with result_path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(serialized)
    return output
