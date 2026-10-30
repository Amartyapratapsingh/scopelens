"""Versioned procedural packs, loaded only from the application release manifest."""

import hashlib
import json
from pathlib import Path


class SkillRejected(ValueError):
    pass


def load_pack(root: Path, name: str):
    manifest = json.loads((root / "manifest.json").read_text())
    entry = manifest.get("packs", {}).get(name)
    if not entry or entry.get("review_state") != "reviewed":
        raise SkillRejected("skill is not reviewed")
    path = (root / entry["file"]).resolve()
    if root.resolve() not in path.parents:
        raise SkillRejected("skill path escapes release root")
    content = path.read_bytes()
    if len(content) > 16000 or hashlib.sha256(content).hexdigest() != entry["sha256"]:
        raise SkillRejected("skill version mismatch")
    return {
        "name": name,
        "version": entry["version"],
        "sha256": entry["sha256"],
        "procedure": content.decode(),
        "permissions_granted": [],
    }
