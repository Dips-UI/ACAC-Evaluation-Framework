"""Checklist/readiness evidence helpers; never marks requirements complete itself."""
from pathlib import Path


def checklist_status(path: str | Path) -> dict[str, int]:
    text = Path(path).read_text(encoding="utf-8")
    return {"unchecked": text.count("- [ ]"), "checked": text.count("- [x]")}
