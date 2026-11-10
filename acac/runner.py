"""Offline planning and provider-neutral interface. Execution is intentionally absent."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Protocol

from .dataset import index, read, inside, digest
from .strict_json import dumps


@dataclass(frozen=True)
class Request:
    instruction: str
    input_json: str


class ModelAdapter(Protocol):
    def generate(self, request: Request) -> str: ...


class DisabledAdapter:
    def generate(self, request):
        raise RuntimeError("Real model execution is disabled. Human gold freeze and explicit user approval are required; no provider adapter is installed.")


def prepare_request(root, configuration_id):
    """Read model-facing input only. Does not read gold or issue a request."""
    manifest, records = index(root)
    record = records[configuration_id]
    path = inside(root, record["input_path"])
    if digest(path) != record["input_hash"]:
        raise ValueError("input_hash_mismatch")
    document = read(path)
    prompt = Path(root) / "prompts" / (document["task"] + ".txt")
    if digest(prompt) != manifest["prompt_hashes"][document["task"]]:
        raise ValueError("prompt_hash_mismatch")
    # Preserve exact input bytes as text; do not reconstruct or enrich from private metadata.
    return Request(prompt.read_text(encoding="utf-8"), path.read_text(encoding="utf-8"))


def schedule(plan):
    ids, models, reps = plan["configurations"], plan["model_slots"], plan["repetitions"]
    for values in (ids, models, reps):
        if not values or len(values) != len(set(values)):
            raise ValueError("empty_or_duplicate_schedule_dimension")
    slots = []
    for model in models:
        for cid in ids:
            for repetition in reps:
                repetition = int(repetition)
                key = f'{plan["pilot_version"]}|{model}|{cid}|{repetition}'
                slots.append({"model_slot": model, "configuration_id": cid, "repetition": repetition,
                              "schedule_key": hashlib.sha256(key.encode("utf-8")).hexdigest()})
    if len(slots) != plan["expected_slots"]:
        raise ValueError("unexpected_schedule_size")
    return sorted(slots, key=lambda s: s["schedule_key"])
