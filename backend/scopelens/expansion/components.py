"""Offline expanded component inputs for the existing candidate-only advisory check.

Only the coordinator selects the shipped snapshot. Observed asset URLs are metadata:
this module opens no connections and never follows advisory or package links.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

from scopelens.checks.advisories import load_bundle
from scopelens.domain.collection import CollectedResponse
from scopelens.domain.enums import ProfileName
from scopelens.domain.surface import AttackSurfaceMap, TechFingerprint

EXPANDED_ADVISORY_SHA256 = "c4a1a13a6a9bcda89880b90d0f1ca0311b13522e85222b5ec438f5be5053e20f"
FINGERPRINT_VERSION = "components-expanded-v1"
_VERSION_TOKEN = r"([0-9][0-9A-Za-z.+_-]*)"
_SEMVER = re.compile(
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_BANNERS = {
    "jquery": r"\bjQuery(?: JavaScript Library)?\s+v?",
    "bootstrap": r"\bBootstrap\s+v?",
    "angularjs": r"\bAngularJS\s+v?",
    "angular": r"\bng-version=[\"']",
    "lodash": r"\blodash(?:[ /-]|\.VERSION\s*=\s*[\"'])",
    "react": r"\bReact\s+v?",
    "vue.js": r"\bVue(?:\.js)?\s+v?",
    "axios": r"\baxios\s+v?",
    "moment": r"\bmoment(?:\.js)?\s*[: /-]?\s*v?",
    "next.js": r"\bNext\.js\s+v?",
    "nuxt": r"\bNuxt(?:\.js)?\s+v?",
    "express": r"\bExpress\s+v?",
}


def advisory_snapshot_for_profile(
    profile: ProfileName, *, registry_dir: Path, legacy_path: Path | None
) -> dict:
    """Freeze the profile's local corpus; a changed expansion file fails the pin."""
    if not profile.expanded:
        shipped = registry_dir / "advisories" / "osv.json"
        return load_bundle(
            legacy_path,
            expected_sha256=EXPANDED_ADVISORY_SHA256
            if legacy_path is not None and legacy_path.resolve() == shipped.resolve()
            else None,
        )
    snapshot = load_bundle(registry_dir / "tooling" / "expansion" / "advisories.json")
    if snapshot["sha256"] != EXPANDED_ADVISORY_SHA256:
        raise ValueError("expanded advisory snapshot differs from its reviewed content pin")
    return {
        **snapshot,
        "selection": {
            "profile": profile.value,
            "path": "tooling/expansion/advisories.json",
            "pinned_sha256": EXPANDED_ADVISORY_SHA256,
            "fingerprint_version": FINGERPRINT_VERSION,
        },
    }


def expanded_component_surface(
    profile: ProfileName,
    surface: AttackSurfaceMap,
    responses: Iterable[CollectedResponse],
) -> AttackSurfaceMap:
    """Add reproducible passive observations from trusted broker response captures.

    Callers must first persist/validate the responses through trusted evidence intake.
    A claimed version is never a confirmation, including corroborating banners. Unlike
    the earlier exposure-pack regex, suffixes are preserved and malformed dotted values
    cannot silently become a stable version (e.g. 1.2.3-vendor or 1.2.3.4).
    """
    if not profile.expanded:
        return surface
    # Re-derive supported versions from captures. Earlier crawler regexes may have
    # shortened a malformed/suffixed token, so importing their version claim would
    # bypass the stricter parsing below. Uncovered technology remains inventory.
    fingerprints = [f for f in surface.tech if f.name.lower() not in _BANNERS]
    for response in responses:
        if not response.via_proxy or not 200 <= response.status < 300:
            continue
        route = urlsplit(response.url).path or "/"
        body_hash = hashlib.sha256(response.body_excerpt.encode()).hexdigest()

        def add(name, raw_version, source, signal, *, route=route, body_hash=body_hash):
            version = raw_version if _SEMVER.fullmatch(raw_version) else None
            fingerprints.append(
                TechFingerprint(
                    name=name,
                    version=version,
                    source=source,
                    evidence=(
                        f"{FINGERPRINT_VERSION}: {signal} on {route}; "
                        f"captured excerpt sha256={body_hash}; "
                        f"version syntax {'accepted' if version else 'unsupported'}; "
                        "component identity, exact build and exploitability unverified"
                    ),
                )
            )

        for name, prefix in _BANNERS.items():
            for match in re.finditer(prefix + _VERSION_TOKEN, response.body_excerpt, re.I):
                add(name, match.group(1), "body", "named library banner/runtime attribute")
            # Inspect only the captured URL's path, never query parameters or links
            # mentioned by the target. Package aliases are exact and escaped.
            path_name = {
                "angularjs": "angular",
                "angular": "@angular/core",
                "vue.js": "vue",
                "next.js": "next",
            }.get(name, name)
            for match in re.finditer(
                rf"(?:^|/){re.escape(path_name)}[@/-]v?{_VERSION_TOKEN}(?=/|$)", route, re.I
            ):
                add(name, match.group(1), "path", "versioned asset path (identity unverified)")
        for key in ("server", "x-powered-by"):
            value = response.header(key) or ""
            for name in ("express", "next.js", "nuxt"):
                match = re.fullmatch(rf"{re.escape(name)}[/ ]v?{_VERSION_TOKEN}", value, re.I)
                if match:
                    add(name, match.group(1), "header", f"{key} version claim")
    derived_names = {f.name.lower() for f in fingerprints}
    for prior in surface.tech:
        if prior.name.lower() in _BANNERS and prior.name.lower() not in derived_names:
            fingerprints.append(
                prior.model_copy(
                    update={
                        "version": None,
                        "evidence": prior.evidence
                        + "; exact version not established by expanded capture parsing",
                    }
                )
            )
    unique = {(f.name, f.version, f.source, f.evidence): f for f in fingerprints}
    return surface.model_copy(update={"tech": tuple(unique.values())})
