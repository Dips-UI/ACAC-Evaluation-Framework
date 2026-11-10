"""Load, hash, and mechanically audit fixtures without evaluating a model."""

from collections import Counter
from copy import deepcopy
import hashlib
from pathlib import Path

from .contracts import cells
from .scoring import validate_gold
from .strict_json import loads_legacy as loads, equal

EXPECTED_MAIN = {"S1-A": 2, "S1-B": 1, "S1-C": 1, "S1-D": 3,
                 "S3-A": 1, "S3-B": 2, "S3-C": 2, "S3-D": 0,
                 "S4-A": 2, "S4-B": 2, "S4-C": 1,
                 "S5-A": 0, "S5-B": 2, "S5-C": 1, "S2-A": 4, "S2-B": 4}
ANCHORS = ("S1-A", "S3-A", "S4-A", "S5-A", "S2-A")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return loads(Path(path).read_text(encoding="utf-8"))


def inside(root, relative):
    root = Path(root).resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError("path_escapes_project")
    return path


def index(root):
    manifest = read(Path(root) / "data/manifest.json")
    records = manifest["configurations"]
    by_id = {r["configuration_id"]: r for r in records}
    if len(by_id) != len(records):
        raise ValueError("duplicate_configuration")
    return manifest, by_id


def load_configuration(root, configuration_id, *, verify_hashes=True):
    _, records = index(root)
    record = records[configuration_id]
    paths = [inside(root, record[key]) for key in ("input_path", "gold_path")]
    if verify_hashes and any(digest(path) != record[k] for path, k in zip(paths, ("input_hash", "gold_hash"))):
        raise ValueError("fixture_hash_mismatch:" + configuration_id)
    return read(paths[0]), read(paths[1]), record


def audit(root, source_root=None):
    manifest, records = index(root)
    expected_ids = {c + "__main" for c in EXPECTED_MAIN}
    expected_ids |= {a + "__" + kind for a in ANCHORS for kind in ("explicit_patch", "order", "wording", "semantic")}
    expected_ids |= {c + "__resolved" for c in ("S1-A", "S4-A", "S4-B")}
    if set(records) != expected_ids:
        raise ValueError("configuration_inventory_mismatch")
    loaded = {}
    for cid in records:
        d, g, r = load_configuration(root, cid)
        validate_gold(d, g)
        if g["review_status"] != "draft_unapproved":
            raise ValueError("draft_gold_status_changed")
        if r["case_id"] + "__" + r["condition"] != cid or r["family"] != r["case_id"][:2]:
            raise ValueError("identity_mismatch")
        loaded[cid] = d, g, r
        supplied = d["payload"].get("supplied_edits")
        if r["condition"] == "explicit_patch":
            if supplied != g["expected_output"]["edits"]:
                raise ValueError("explicit_patch_mismatch")
        elif supplied is not None:
            raise ValueError("gold_leak_in_input")
        if r["condition"] == "main" and len(g["expected_output"]["edits"]) != EXPECTED_MAIN[r["case_id"]]:
            raise ValueError("main_gold_count_mismatch")
    for cid, (d, g, record) in loaded.items():
        kind = record["condition"]
        if kind in ("main", "semantic"):
            continue
        base, bg, _ = loaded[record["case_id"] + "__main"]
        if g["eligible_keys"] != bg["eligible_keys"] or g["expected_output"] != bg["expected_output"]:
            raise ValueError("control_gold_mismatch")
        left, right = cells(d["payload"]["ledger"]), cells(base["payload"]["ledger"])
        if left.keys() != right.keys() or any(not equal(left[k], right[k]) for k in left):
            raise ValueError("control_ledger_mismatch")
        expected = deepcopy(base)
        if kind == "order":
            for table in ("M", "H", "W"):
                expected["payload"]["ledger"][table].reverse()
        elif kind == "wording":
            expected["payload"]["notice"] = d["payload"]["notice"]
        elif kind == "explicit_patch":
            expected["payload"]["supplied_edits"] = g["expected_output"]["edits"]
        elif kind == "resolved":
            for key in ("original_guideline", "notice"):
                expected["payload"][key] = d["payload"][key]
            expected["payload"]["updates"] = []
        if d != expected:
            raise ValueError("unintended_control_difference")
    for a, b in (("S1-A", "S1-B"), ("S3-A", "S3-B"), ("S5-A", "S5-B")):
        da = deepcopy(loaded[a + "__main"][0]); db = deepcopy(loaded[b + "__main"][0])
        da["payload"]["notice"] = db["payload"]["notice"]
        if da != db:
            raise ValueError("counterfactual_changes_more_than_notice")
    for name, expected_count in (("full", 234), ("reduced", 60)):
        plan = read(Path(root) / f"plans/{name}.json")
        if len(plan["configurations"]) != len(set(plan["configurations"])) or not set(plan["configurations"]) <= records.keys():
            raise ValueError("invalid_plan_inventory")
        count = len(plan["configurations"]) * len(plan["model_slots"]) * len(plan["repetitions"])
        if count != expected_count or plan["expected_slots"] != expected_count or plan["execution_authorized"] is not False:
            raise ValueError("plan_count_or_authorization_error")
    for task, expected in manifest["prompt_hashes"].items():
        if digest(Path(root) / f"prompts/{task}.txt") != expected:
            raise ValueError("prompt_hash_mismatch")
    if source_root:
        for name, expected in manifest["source_sha256"].items():
            if digest(Path(source_root) / name) != expected:
                raise ValueError("original_report_changed:" + name)
    return {"audit_type": "mechanical_fixture_consistency_not_model_evaluation",
            "main_cases": 16, "configurations": len(records), "expected_main_edits": sum(EXPECTED_MAIN.values()),
            "conditions": dict(Counter(r["condition"] for r in records.values())),
            "full_slots": 234, "reduced_slots": 60, "human_gold_approved": False}
