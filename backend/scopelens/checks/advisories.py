"""Offline, versioned OSV advisory snapshots. No target content selects a feed.

OSV field definitions: https://ossf.github.io/osv-schema/
Only explicit versions and stable numeric SEMVER ranges are interpreted. Other version
schemes remain unassessed; vendor backports are never inferred from a banner.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AdvisoryBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=1)
    source: str = Field(min_length=1)
    # Explicit mapping from our fingerprint name to an OSV ecosystem/package key.
    packages: dict[str, str]
    records: list[dict[str, Any]]
    provenance: dict[str, Any] = Field(default_factory=dict)


def load_bundle(path: Path | None, *, expected_sha256: str | None = None) -> dict[str, Any]:
    if path is None:
        return {}
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError("advisory snapshot differs from its reviewed content pin")
    if len(raw) > 10 * 1024 * 1024:
        raise ValueError("advisory bundle exceeds 10 MiB")
    bundle = AdvisoryBundle.model_validate(json.loads(raw))
    for record in bundle.records:
        if (
            not record.get("id")
            or not record.get("modified")
            or not isinstance(record.get("affected"), list)
        ):
            raise ValueError("advisory requires id, modified and affected")
    return {"sha256": digest, "bundle": bundle.model_dump()}


def affected_version(version: str, affected: dict[str, Any]) -> bool | None:
    if version in affected.get("versions", []):
        return True
    ranges = affected.get("ranges", [])
    if not ranges:
        return False if affected.get("versions") else None
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        return None
    current = tuple(int(n) for n in version.split("."))
    unknown = False
    for item in ranges:
        # PyPI/Maven stable x.y.z releases share numeric ordering. Qualifiers,
        # distro revisions, epochs, GIT ranges and other ecosystems stay unknown.
        numeric_ecosystem = affected.get("package", {}).get("ecosystem") in {"PyPI", "Maven"}
        if item.get("type") != "SEMVER" and not (
            item.get("type") == "ECOSYSTEM" and numeric_ecosystem
        ):
            unknown = True
            continue
        lower = None
        matched = False
        valid = bool(item.get("events"))
        for event in item.get("events", []):
            if len(event) != 1:
                valid = False
                break
            for kind, value in event.items():
                if kind not in {"introduced", "fixed", "limit", "last_affected"}:
                    valid = False
                    break
                if value == "0" and kind == "introduced":
                    bound = (0, 0, 0)
                elif isinstance(value, str) and re.fullmatch(r"\d+\.\d+\.\d+", value):
                    bound = tuple(int(n) for n in value.split("."))
                else:
                    valid = False
                    break
                if kind == "introduced":
                    if lower is not None:
                        valid = False
                        break
                    lower = bound
                else:
                    if lower is None or bound < lower:
                        valid = False
                        break
                    matched |= current >= lower and (
                        current <= bound if kind == "last_affected" else current < bound
                    )
                    lower = None
        if not valid:
            unknown = True
            continue
        if matched or (lower is not None and current >= lower):
            return True
    return None if unknown else False
