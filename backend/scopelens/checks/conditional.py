"""The reviewed configuration portion of the conditional pack; no credentialed tests."""

import hashlib
import json
import os
from urllib.parse import urlencode

from scopelens.adapters.scanners import ScannerObservation, ScannerResult
from scopelens.broker.probe_tasks import PROBE_HEADER, conditional_reference
from scopelens.checks.crawl import Crawler
from scopelens.domain.enums import ProfileName
from scopelens.scope.paths import canonical_path


def approvals(settings, scope):
    if not scope.allowed_check_profile.includes_active_pack:
        return []
    pack = json.loads((settings.checks_registry_dir / "tooling/conditional-pack.json").read_text())
    if scope.lab_binding:
        return pack["lab_services"].get(scope.lab_binding.service, [])
    explicit = pack["production_origins"].get(scope.origin)
    if explicit is not None:
        return explicit
    # Only the unauthenticated active profile permits this reviewed default. It
    # sends two Origin headers on the authorized crawl seed, never invents an input
    # parameter or authorizes a discovered endpoint/host. Expanded plans own their
    # explicit role and endpoint approvals independently.
    if (
        scope.allowed_check_profile != ProfileName.EXTERNAL_DAST
        or "GET" not in scope.allowed_methods
    ):
        return []
    for prefix in sorted(scope.allowed_path_prefixes, key=lambda p: (len(p), p)):
        path = canonical_path(prefix)
        if any(
            path == excluded or path.startswith(excluded.rstrip("/") + "/")
            for excluded in map(canonical_path, scope.excluded_paths)
        ):
            continue
        return [{"kind": "cors", "path": path, "review": pack["default_read_only_cors"]["version"]}]
    return []


def collect(config):
    reviewed = json.loads(os.environ.get("SCOPELENS_CONDITIONAL_PROBES", "[]"))
    result = ScannerResult(tool="conditional-config", version="m3.1", state="completed")
    if not reviewed:
        result.state = "not_tested"
        result.errors = ["No reviewed endpoints enabled for this profile and origin"]
        return result
    collector = Crawler(config)
    for entry in reviewed:
        if entry["kind"] not in {"cors", "redirect"}:
            continue
        path = entry["path"]
        if not path.startswith("/") or "?" in path or "#" in path or path.startswith("//"):
            raise ValueError("reviewed probe must use an exact absolute path")
        captures = []
        for origin in ["https://scopelens-a.invalid", "https://scopelens-b.invalid"]:
            url = config.origin + path
            if not collector._in_scope(url):
                result.state = "partial"
                result.errors.append("reviewed endpoint outside this scope")
                continue
            headers = {PROBE_HEADER: conditional_reference(entry)}
            if entry["kind"] == "cors":
                headers["Origin"] = origin
            elif entry["kind"] == "redirect":
                url += "?" + urlencode({entry["parameter"]: origin + "/marker"}, safe=":/")
            else:
                raise ValueError("unknown reviewed probe")
            # The crawler's client is already bound to the proxy and CA. No redirect is
            # followed, and a returned Location never becomes another target request.
            try:
                with collector._http().stream(
                    "GET", url, headers=headers, follow_redirects=False
                ) as response:
                    captures.append(
                        {
                            "origin": origin,
                            "status": response.status_code,
                            "allow_origin": response.headers.get("access-control-allow-origin"),
                            "allow_credentials": response.headers.get(
                                "access-control-allow-credentials"
                            ),
                            "location": response.headers.get("location"),
                        }
                    )
            except Exception as exc:  # noqa: BLE001 - a failed probe is visible, never a pass
                result.state = "partial"
                result.errors.append(type(exc).__name__)
        raw = json.dumps(captures, sort_keys=True)
        digest = hashlib.sha256(raw.encode()).hexdigest()
        result.observations.append(
            ScannerObservation(
                tool=result.tool,
                tool_version=result.version,
                rule_id=entry["kind"],
                title="Observed " + entry["kind"] + " configuration",
                reported_severity="informational",
                locations=[config.origin + path],
                evidence=raw,
                output_hash=digest,
            )
        )
    return result
