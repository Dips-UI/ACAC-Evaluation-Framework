"""Offline implementation-readiness audit for the v1 module surface."""
from pathlib import Path


REQUIRED_MODULES = ("case_validation", "predicates", "authorization", "temporal", "patches", "grader", "references", "lifecycle", "canonical", "manifest", "results", "governance", "reports_v1")


def implementation_surface(root: str | Path) -> dict:
    root = Path(root)
    present = {name: (root / "acac" / f"{name}.py").exists() for name in REQUIRED_MODULES}
    return {"required_modules": present, "all_present": all(present.values())}
