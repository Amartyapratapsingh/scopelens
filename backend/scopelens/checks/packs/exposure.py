"""Bounded exposure checks with independent fallback controls and content proof.

No response contents or credential values leave this module. Classification is performed
before redaction; the retained observations contain only structure, hashes and locations.
A caller must capture this result through trusted intake before supplying evidence_ref.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Callable, Iterable
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as Outcome

PACK_VERSION = "exposure-v2.1"
BODY_CAP = 65536
CONTROL_IDS = {
    "config": "SL-C05-CONFIG-02",
    "debug": "SL-C05-DEBUG-02",
    "management": "SL-C05-MANAGEMENT-01",
    "source_map": "SL-C05-SOURCEMAP-01",
    "private": "SL-C05-PRIVATE-02",
}
CANONICAL = {
    "config": "exposure.configuration_backup",
    "debug": "exposure.runtime_diagnostics",
    "management": "exposure.management_data",
    "source_map": "exposure.source_map_private_material",
    "private": "exposure.private_key_material",
}
# Selected only after observing the relevant technology, except common config paths.
PROBES = (
    ("config", "/.env", ()),
    ("config", "/config.json.bak", ()),
    ("config", "/wp-config.php.bak", ("wordpress", "php")),
    ("debug", "/phpinfo.php", ("php",)),
    ("debug", "/server-status?auto", ("apache",)),
    ("management", "/actuator/env", ("spring", "spring boot")),
    ("management", "/actuator/configprops", ("spring", "spring boot")),
    ("private", "/server.key", ()),
)
SECRET_NAME = re.compile(r"(?:password|passwd|secret|private[_-]?key|access[_-]?token)", re.I)
MASKED = re.compile(
    r"^(?:\*+|x+|\[?redacted\]?|\$\{[^}]+\}|<[^>]+>|null|none|changeme|example.*)$", re.I
)
PRIVATE_KEY = re.compile(
    r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY)-----[\s\S]+?-----END \1-----"
)


class ProbeObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    family: str
    url: str
    state: str  # exposed, candidate, clear, inconclusive, blocked
    reason: str
    status: int | None = None
    body_hash: str | None = None
    negative_control_hash: str | None = None
    bytes_read: int = 0
    truncated: bool = False


class ComponentObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str
    version: str
    source_url: str
    signal: str
    # Distinct observations corroborate identity, not vulnerability/exploitability.
    identity_corroborated: bool = False


class ExposurePackResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = PACK_VERSION
    observations: list[ProbeObservation] = Field(default_factory=list)
    components: list[ComponentObservation] = Field(default_factory=list)
    requests: int = 0
    gaps: list[str] = Field(default_factory=list)
    selected_families: list[str] = Field(default_factory=list)


def _origin(url: str) -> tuple[str, str | None, int]:
    p = urlsplit(url)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("HTTP origin without credentials required")
    return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == "https" else 80)


def _has_secret(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if SECRET_NAME.search(str(key)) and isinstance(item, dict) and "value" in item:
                item = item["value"]
            if SECRET_NAME.search(str(key)) and isinstance(item, (str, int)):
                text = str(item).strip()
                if (
                    len(text) >= 8
                    and not MASKED.fullmatch(text)
                    and not text.startswith(("pk_live_", "pk_test_", "public_"))
                ):
                    return True
            if _has_secret(item):
                return True
    elif isinstance(value, list):
        return any(_has_secret(item) for item in value)
    return False


def classify(family: str, body: str, content_type: str) -> tuple[str, str]:
    """Classify complete, distinct HTTP 200 content; secret authenticity stays unknown."""
    html = "html" in content_type or bool(re.match(r"\s*<(?:!doctype|html)", body, re.I))
    if family == "private":
        match = PRIVATE_KEY.search(body)
        if match:
            from cryptography.exceptions import UnsupportedAlgorithm
            from cryptography.hazmat.primitives.serialization import load_pem_private_key

            try:
                load_pem_private_key(match.group().encode(), password=None)
            except (ValueError, TypeError, UnsupportedAlgorithm):
                return (
                    "candidate",
                    "Private-key envelope observed; key parse/authenticity unresolved",
                )
            return (
                "exposed",
                "Parsable private-key material delivered without authentication; no key use attempted",
            )
        return "clear", "No private-key envelope in this response"
    if family == "config":
        if html:
            return "clear", "HTML page does not establish configuration-file exposure"
        try:
            obj = json.loads(body)
        except (ValueError, RecursionError):
            obj = None
        if isinstance(obj, dict) and _has_secret(obj):
            return (
                "exposed",
                "JSON configuration exposes a nonmasked secret-valued property; credential validity unknown",
            )
        assignments = re.findall(r"(?m)^(?:export\s+)?([A-Z][A-Z0-9_]+)\s*=\s*(.+)$", body)
        if len(assignments) >= 2 and any(
            SECRET_NAME.search(k) and len(v.strip()) >= 8 and not MASKED.fullmatch(v.strip())
            for k, v in assignments
        ):
            return (
                "exposed",
                "Configuration assignment structure includes nonmasked private settings; values omitted",
            )
        if "<?php" in body and re.search(r"define\s*\(\s*['\"]DB_(?:PASSWORD|USER)['\"]", body):
            return "exposed", "PHP configuration source discloses database setting definitions"
        return "clear", "No supported private configuration structure"
    if family == "debug":
        if re.search(r"<title>phpinfo\(\)</title>", body, re.I) and all(
            x in body for x in ("PHP Version", "DOCUMENT_ROOT", "SERVER_SOFTWARE")
        ):
            return "exposed", "phpinfo document exposes server runtime/environment information"
        if all(
            re.search(rf"(?m)^{key}:\s*\d+", body)
            for key in ("Total Accesses", "Total kBytes", "BusyWorkers", "IdleWorkers")
        ):
            return (
                "exposed",
                "Apache machine-readable status exposes live worker and request counters",
            )
        return "clear", "No supported runtime-diagnostic structure; a login page is not proof"
    if family == "management":
        try:
            obj = json.loads(body)
        except (ValueError, RecursionError):
            return "clear", "No management JSON structure"
        spring = isinstance(obj, dict) and (
            isinstance(obj.get("propertySources"), list) or isinstance(obj.get("contexts"), dict)
        )
        if spring and _has_secret(obj):
            return "exposed", "Management data contains nonmasked private configuration values"
        if spring:
            return "clear", "Management structure observed, but private values absent or masked"
        return "clear", "No supported management-data structure"
    if family == "source_map":
        try:
            obj = json.loads(body)
        except (ValueError, RecursionError):
            return "clear", "Not a complete source-map JSON object"
        if (
            not isinstance(obj, dict)
            or obj.get("version") != 3
            or not isinstance(obj.get("sources"), list)
            or not isinstance(obj.get("sourcesContent"), list)
        ):
            return "clear", "No embedded-source map structure"
        texts = [s for s in obj["sourcesContent"] if isinstance(s, str)]
        if any(
            PRIVATE_KEY.search(s)
            or re.search(
                r"(?i)(?:client_secret|api_secret|private_key)\s*[:=]\s*['\"][^'\"]{12,}['\"]", s
            )
            for s in texts
        ):
            return (
                "candidate",
                "Source map embeds private-material-shaped source; credential authenticity unverified",
            )
        return "clear", "Public source map alone is not a vulnerability"
    raise ValueError("unknown exposure family")


def identify_components(url: str, headers: dict[str, str], body: str) -> list[ComponentObservation]:
    """Multiple passive forms; package identity is bounded to named supported packages."""
    result = []
    patterns = {
        "jquery": r"jQuery(?: JavaScript Library)?\s+v?(\d+\.\d+\.\d+)",
        "bootstrap": r"Bootstrap\s+v?(\d+\.\d+\.\d+)",
        "angular": r"ng-version=[\"'](\d+\.\d+\.\d+)",
        "angularjs": r"AngularJS\s+v(\d+\.\d+\.\d+)",
        "lodash": r"(?:lodash[ /-]|lodash\.VERSION\s*=\s*[\"'])(\d+\.\d+\.\d+)",
        "react": r"React\s+v?(\d+\.\d+\.\d+)",
        "vue.js": r"Vue(?:\.js)?\s+v?(\d+\.\d+\.\d+)",
        "axios": r"axios\s+v?(\d+\.\d+\.\d+)",
        "moment": r"moment(?:\.js)?\s*[: /-]?\s*v?(\d+\.\d+\.\d+)",
    }
    for name, pattern in patterns.items():
        matches = [(m.group(1), "body library signature") for m in re.finditer(pattern, body, re.I)]
        matches += [
            (m.group(1), "versioned asset URL")
            for m in re.finditer(rf"(?:^|[/@-]){name}[/@-]v?(\d+\.\d+\.\d+)(?:[/.-]|$)", url, re.I)
        ]
        for version, signal in dict.fromkeys(matches):
            result.append(
                ComponentObservation(
                    name=name,
                    version=version,
                    source_url=url,
                    signal=signal,
                    identity_corroborated=len({s for v, s in matches if v == version}) > 1,
                )
            )
    return result


def collect_exposure_pack(
    client,
    origin: str,
    *,
    technologies: Iterable[str] = (),
    discovered_urls: Iterable[str] = (),
    approved_urls: Iterable[str] | None = None,
    admit_url: Callable[[str], bool] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    max_requests: int = 24,
    max_body_bytes: int = BODY_CAP,
) -> ExposurePackResult:
    """Use a supplied broker-bound httpx client; no new sockets, cookies or credentials."""
    target_origin = _origin(origin)
    if max_requests < 1 or not 1 <= max_body_bytes <= BODY_CAP:
        raise ValueError("positive request cap and body cap <= 65536 required")
    result = ExposurePackResult()
    tech = {t.lower() for t in technologies}
    probes = [
        (family, urljoin(origin.rstrip("/") + "/", path))
        for family, path, required in PROBES
        if not required or tech.intersection(required)
    ]
    for raw in list(discovered_urls)[:100]:
        url = urljoin(origin, raw)
        try:
            same = _origin(url) == target_origin
        except ValueError:
            same = False
        if same and urlsplit(url).path.endswith(".map"):
            probes.append(("source_map", url))
    probes = list(dict.fromkeys(probes))
    if approved_urls is not None:
        approved = set(approved_urls)
        probes = [(family, url) for family, url in probes if url in approved]
    if admit_url is not None:
        probes = [(family, url) for family, url in probes if admit_url(url)]
    result.selected_families = list(dict.fromkeys(f for f, _ in probes))

    def fetch(url):
        if admit_url is not None and not admit_url(url):
            return None, "outside reviewed path scope"
        if cancelled():
            return None, "cancelled"
        if result.requests >= max_requests:
            return None, "request limit reached"
        result.requests += 1
        try:
            with client.stream("GET", url, follow_redirects=False) as response:
                body = bytearray()
                for block in response.iter_bytes(chunk_size=4096):
                    if cancelled():
                        return None, "cancelled during response"
                    body.extend(block[: max_body_bytes + 1 - len(body)])
                    if len(body) > max_body_bytes:
                        break
                return (
                    response.status_code,
                    dict(response.headers),
                    bytes(body[:max_body_bytes]),
                    len(body) > max_body_bytes,
                ), None
        except (httpx.HTTPError, OSError, ValueError):
            return None, "broker or transport refused/failed request"

    # Negative control is in the same parent directory, retaining extension for rewrite rules.
    controls = {}
    for family, url in probes:
        parts = urlsplit(url)
        parent = parts.path.rsplit("/", 1)[0]
        suffix = "." + parts.path.rsplit(".", 1)[1] if "." in parts.path.rsplit("/", 1)[-1] else ""
        key = (parent, suffix)
        if key not in controls:
            path = parent + "/scopelens-absent-" + secrets.token_hex(12) + suffix
            controls[key] = fetch(urljoin(origin, path))
        negative, negative_error = controls[key]
        sample, error = fetch(url)
        base = dict(family=family, url=url)
        if error or negative_error:
            result.observations.append(
                ProbeObservation(
                    **base, state="blocked", reason=error or negative_error or "unknown"
                )
            )
            continue
        status, headers, body, truncated = sample
        ns, negative_headers, nb, nt = negative
        base.update(
            status=status,
            body_hash=hashlib.sha256(body).hexdigest(),
            negative_control_hash=hashlib.sha256(nb).hexdigest(),
            bytes_read=len(body),
            truncated=truncated,
        )
        if status in {404, 410}:
            state, reason = "clear", "Reviewed path is absent"
        elif status != 200:
            state, reason = (
                "inconclusive",
                "Non-success response does not establish exposure or absence",
            )
        elif truncated or nt or ns not in {200, 404, 410}:
            state, reason = "inconclusive", "Complete response and usable negative control required"
        elif ns == 200 and (
            body == nb
            or classify(
                family, nb.decode("utf-8", "replace"), negative_headers.get("content-type", "")
            )[0]
            in {"exposed", "candidate"}
        ):
            state, reason = "inconclusive", "Fallback response reproduces the exposure signature"
        else:
            state, reason = classify(
                family, body.decode("utf-8", "replace"), headers.get("content-type", "")
            )
        result.observations.append(ProbeObservation(**base, state=state, reason=reason))
        result.components.extend(identify_components(url, headers, body.decode("utf-8", "replace")))
    result.gaps = sorted(
        {o.reason for o in result.observations if o.state in {"blocked", "inconclusive"}}
    )
    return result


def evaluate_exposure_pack(
    result: ExposurePackResult, evidence_ref: str | None
) -> tuple[ControlOutcome, ...]:
    outcomes = []
    for family in result.selected_families:
        rows = [o for o in result.observations if o.family == family]
        hits = [o for o in rows if o.state in {"exposed", "candidate"}]
        confirmed = bool(evidence_ref and any(o.state == "exposed" for o in hits))
        missing = [o for o in rows if o.state in {"blocked", "inconclusive", "candidate"}]
        proof = (
            ProofResult(
                satisfied=confirmed,
                status=EvidenceStatus.CONFIRMED if confirmed else EvidenceStatus.POTENTIAL,
                reasons=tuple(dict.fromkeys(o.reason for o in hits)),
                evidence_refs=(evidence_ref,) if evidence_ref else (),
            )
            if hits
            else None
        )
        outcomes.append(
            ControlOutcome(
                check_id=CONTROL_IDS[family],
                canonical_control=CANONICAL[family],
                category=Category.C05_DATA_EXPOSURE,
                status=Outcome.CONFIRMED_ISSUE
                if confirmed
                else Outcome.INCONCLUSIVE
                if hits or missing or not evidence_ref
                else Outcome.PASS,
                summary=f"{len(hits)} exposure observation(s) across {len(rows)} reviewed locations; credential validity never tested",
                locations=tuple(
                    Location(route=urlsplit(o.url).path, detail=o.reason) for o in hits
                ),
                proposed_severity=Severity.HIGH
                if family in {"private", "config", "management", "source_map"} and hits
                else Severity.MEDIUM
                if hits
                else None,
                proof=proof,
                required_instances=tuple(o.url for o in rows),
                completed_instances=tuple(
                    o.url
                    for o in rows
                    if o.state == "clear" or (o.state == "exposed" and evidence_ref)
                ),
                incomplete_reasons=tuple(o.reason for o in missing)
                + (() if evidence_ref else ("Trusted evidence not attached",)),
            )
        )
    return tuple(outcomes)


def component_fingerprints(responses):
    """Convert captured responses to existing advisory-engine inputs without new traffic."""
    from scopelens.domain.surface import TechFingerprint

    fingerprints = {}
    for response in responses:
        for item in identify_components(response.url, response.headers, response.body_excerpt):
            key = item.name, item.version, item.signal
            fingerprints[key] = TechFingerprint(
                name=item.name,
                version=item.version,
                evidence=f"{item.signal}; identity corroborated={item.identity_corroborated}; exploitability unverified",
                source="path" if item.signal == "versioned asset URL" else "body",
            )
    return tuple(fingerprints.values())
