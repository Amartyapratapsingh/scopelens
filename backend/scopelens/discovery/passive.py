"""Control-plane CT inventory and DNS only. Never connect to discovered hosts.

The two fixed public providers are independent of scan-worker egress and target
request accounting. Results grant no scope, action or vulnerability coverage.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import threading
import time
from collections import OrderedDict
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import httpx

CT_URL = "https://crt.sh/"
CT_FALLBACK_URL = "https://api.certspotter.com/v1/issuances"
DNS_URL = "https://dns.google/resolve"
CT_CAP = 2_097_152
DNS_CAP = 65_536
MAX_HOSTS = 500
MAX_RESOLVE = 24
TTL = 3600
FAILURE_TTL = 300
_cache = OrderedDict()
_cache_lock = threading.Lock()


def hostname(value):
    try:
        name = value.strip().rstrip(".").lower().encode("idna").decode("ascii")
    except (UnicodeError, AttributeError):
        return None
    if len(name) > 253 or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in name.split(".")
    ):
        return None
    return name


@lru_cache(maxsize=1)
def _suffixes():
    rules = Path(__file__).with_name("data").joinpath("public_suffix_list.dat").read_text()
    return {
        rule.strip().encode("idna").decode("ascii")
        for rule in rules.splitlines()
        if rule.strip() and not rule.startswith("//")
    }


def registrable_domain(value):
    """PSL prevailing rule, including private suffixes and wildcard exceptions."""
    name = hostname(value)
    if not name:
        return None
    try:
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    labels = name.split(".")
    rules = _suffixes()
    length = 1
    matched = False
    for index in range(len(labels)):
        suffix = ".".join(labels[index:])
        if "!" + suffix in rules:
            length = len(labels) - index - 1
            matched = True
            break
        if suffix in rules or (index > 0 and "*." + suffix in rules):
            length = max(length, len(labels) - index + (suffix not in rules))
            matched = True
    # Unknown/internal suffixes are not a reason to query a public provider.
    return ".".join(labels[-length - 1 :]) if matched and len(labels) > length else None


class SourceUnavailable(RuntimeError):
    pass


def _json(client, url, params, cap, timeout, *, deadline=None, clock=time.monotonic):
    with client.stream("GET", url, params=params, timeout=timeout) as response:
        response.raise_for_status()
        if int(response.headers.get("content-length", "0")) > cap:
            raise SourceUnavailable("response_size_cap")
        body = bytearray()
        for chunk in response.iter_bytes():
            if deadline is not None and clock() >= deadline:
                raise SourceUnavailable("source_time_cap")
            body.extend(chunk[: cap + 1 - len(body)])
            if len(body) > cap:
                raise SourceUnavailable("response_size_cap")
        return json.loads(body)


def collect(origin, *, client=None, clock=time.monotonic, sleep=time.sleep, now=None):
    """Bounded snapshot with fixed errors; injection supports offline fixtures."""
    root = registrable_domain(urlsplit(origin).hostname or "")
    observed = (now or datetime.now(UTC)).isoformat()
    result = {
        "version": "passive-hosts-v1",
        "registrable_domain": root,
        "observed_at": observed,
        "state": "not_applicable" if not root else "complete",
        "coverage_notes": [] if root else ["no_public_registrable_domain"],
        "hosts": [],
        "target_http_requests": 0,
        "dns_provider": "dns.google",
    }
    if not root:
        return result
    if client is None:
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=5) as http:
            return collect(origin, client=http, clock=clock, sleep=sleep, now=now)
    deadline = clock() + 25
    provider = "crt.sh"
    try:
        try:
            records = _json(
                client,
                CT_URL,
                {"q": "%." + root, "output": "json"},
                CT_CAP,
                5,
                deadline=deadline,
                clock=clock,
            )
            if not isinstance(records, list):
                raise SourceUnavailable("invalid_response")
        except (httpx.HTTPError, SourceUnavailable, ValueError, TypeError):
            result["coverage_notes"].append("crt_sh_source_unavailable")
            provider = "certspotter"
            records = _json(
                client,
                CT_FALLBACK_URL,
                {"domain": root, "include_subdomains": "true", "expand": "dns_names"},
                CT_CAP,
                min(5, max(0.01, deadline - clock())),
                deadline=deadline,
                clock=clock,
            )
            # This endpoint lists unexpired issuances. We retain only its first
            # page, so neither historical nor pagination completeness is implied.
            result["coverage_notes"].append("certificate_transparency_first_page_only")
        if not isinstance(records, list):
            raise SourceUnavailable("invalid_response")
        names = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            values = (
                str(record.get("name_value", "")).splitlines()
                if provider == "crt.sh"
                else record.get("dns_names", [])
            )
            if not isinstance(values, list):
                continue
            for value in values:
                if not isinstance(value, str):
                    continue
                wildcard = value.startswith("*.")
                name = hostname(value[2:] if wildcard else value)
                if name and (name == root or name.endswith("." + root)):
                    names[name] = names.get(name, False) or wildcard
        if len(names) > MAX_HOSTS:
            result["coverage_notes"].append("certificate_transparency_host_cap")
            result["state"] = "partial"
        result["hosts"] = [
            {
                "host": name,
                "role": "inventory_only",
                "evidence": "Certificate name, not evidence of a live service or scan authority.",
                "sources": ["certificate-transparency"],
                "observations": [
                    {
                        "source": "certificate-transparency",
                        "provider": provider,
                        "observed_at": observed,
                        "wildcard": names[name],
                    }
                ],
                "dns_status": "not_checked",
                "dns_addresses": [],
                "dns_observed_at": None,
            }
            for name in sorted(names)[:MAX_HOSTS]
        ]
    except (httpx.HTTPError, SourceUnavailable, ValueError, TypeError):
        result.update(
            state="source_unavailable",
            coverage_notes=["certificate_transparency_source_unavailable"],
        )
        return result
    last_query = -float("inf")
    for host in result["hosts"][:MAX_RESOLVE]:
        answers = []
        try:
            for kind in ("A", "AAAA"):
                sleep(max(0, 0.25 - (clock() - last_query)))
                remaining = deadline - clock()
                if remaining <= 0:
                    raise SourceUnavailable("dns_deadline")
                last_query = clock()
                payload = _json(
                    client,
                    DNS_URL,
                    {"name": host["host"], "type": kind},
                    DNS_CAP,
                    min(2, remaining),
                    deadline=deadline,
                    clock=clock,
                )
                status = payload.get("Status")
                if status not in {0, 3}:
                    raise SourceUnavailable("dns_source_unavailable")
                for answer in payload.get("Answer", []):
                    if answer.get("type") in {1, 28}:
                        answers.append(str(ipaddress.ip_address(answer["data"])))
            host.update(
                dns_status="resolvable" if answers else "unresolved",
                dns_addresses=sorted(set(answers)),
            )
        except (
            httpx.HTTPError,
            SourceUnavailable,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
        ):
            host["dns_status"] = "resolvable" if answers else "unavailable"
            host["dns_addresses"] = sorted(set(answers))
            result["coverage_notes"].append("dns_source_unavailable")
        host["dns_observed_at"] = (now or datetime.now(UTC)).isoformat()
        host["sources"].append("dns")
        host["observations"].append(
            {
                "source": "dns",
                "provider": "dns.google",
                "observed_at": host["dns_observed_at"],
                "wildcard": False,
            }
        )
        if clock() >= deadline:
            break
    if any(host["dns_status"] == "not_checked" for host in result["hosts"]):
        result["coverage_notes"].append("dns_count_or_time_cap")
    result["coverage_notes"] = sorted(set(result["coverage_notes"]))
    if result["coverage_notes"]:
        result["state"] = "partial"
    return result


def cached_collect(origin):
    root = registrable_domain(urlsplit(origin).hostname or "")
    # Serialize source fetches to prevent a concurrent request stampede. At most 64 roots.
    with _cache_lock:
        entry = _cache.get(root)
        if entry and entry[0] > time.monotonic():
            return copy.deepcopy(entry[1])
        result = collect(origin)
        ttl = FAILURE_TTL if result["state"] == "source_unavailable" else TTL
        _cache[root] = (time.monotonic() + ttl, copy.deepcopy(result))
        _cache.move_to_end(root)
        while len(_cache) > 64:
            _cache.popitem(last=False)
        return result


def merge_inventory(inventory, discovery):
    """Deduplicate provenance without promoting CT/DNS names to tested hosts."""
    merged = {}
    for row in [*(inventory or []), *(discovery or {}).get("hosts", [])]:
        name = hostname(str(row.get("host", "")))
        if not name:
            continue
        current = merged.setdefault(name, {**row, "host": name, "sources": [], "observations": []})
        sources = row.get("sources") or (["crawl"] if row.get("role") == "primary" else ["link"])
        current["sources"] = sorted(set(current["sources"]) | set(sources))
        for observation in row.get("observations", []):
            if observation not in current["observations"]:
                current["observations"].append(observation)
        for field in ("dns_status", "dns_addresses", "dns_observed_at"):
            if field in row:
                current[field] = row[field]
    return list(merged.values())
