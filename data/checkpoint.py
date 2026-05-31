"""
Checkpoint manager — phase-level resume support for bb.py.

After each scan phase completes, its results are serialised to
  {output_dir}/.checkpoints/{safe_domain}.json

When --resume is passed on a subsequent run, completed phases are
loaded from disk and their network work is skipped entirely.
"""

import json
from datetime import datetime
from pathlib import Path


def get_path(output_dir: str, domain: str) -> Path:
    safe = domain.replace(".", "_").replace("/", "_").replace(":", "_")
    return Path(output_dir) / ".checkpoints" / f"{safe}.json"


def load(path: Path) -> dict:
    try:
        if path.exists():
            with open(path) as fh:
                return json.load(fh)
    except Exception:
        pass
    return {}


def save(path: Path, existing: dict, *, phase: str, data, domain: str = "", base_url: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now().isoformat(timespec="seconds")
    updated: dict = {**existing}
    if not updated.get("created_at"):
        updated["created_at"] = now
        updated["domain"]     = domain
        updated["base_url"]   = base_url
    updated["updated_at"] = now
    completed = set(updated.get("completed_phases", []))
    completed.add(phase)
    updated["completed_phases"] = sorted(completed)
    updated[f"{phase}_data"] = _make_serializable(data)
    try:
        with open(path, "w") as fh:
            json.dump(updated, fh, indent=2, default=str)
    except Exception:
        pass


def clear(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def list_all(output_dir: str) -> list[dict]:
    """Return metadata for every checkpoint found under output_dir/.checkpoints/."""
    ckpt_dir = Path(output_dir) / ".checkpoints"
    if not ckpt_dir.exists():
        return []
    results = []
    for fp in sorted(ckpt_dir.glob("*.json")):
        try:
            with open(fp) as fh:
                data = json.load(fh)
            results.append({
                "path":             fp,
                "domain":           data.get("domain", fp.stem.replace("_", ".")),
                "base_url":         data.get("base_url", ""),
                "created_at":       data.get("created_at", ""),
                "updated_at":       data.get("updated_at", ""),
                "completed_phases": data.get("completed_phases", []),
            })
        except Exception:
            pass
    results.sort(key=lambda r: r.get("updated_at", ""), reverse=True)
    return results


def _make_serializable(obj):
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_serializable(i) for i in obj]
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8", errors="replace")
        except Exception:
            return "<bytes>"
    return str(obj)
