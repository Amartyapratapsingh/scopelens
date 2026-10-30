"""Reviewed paired input probes and deterministic proof rules for the conditional pack."""

import hashlib
import json
import os
from functools import partial
from urllib.parse import urlencode

from scopelens.broker.probe_tasks import PROBE_HEADER, conditional_reference
from scopelens.checks.crawl import Crawler
from scopelens.checks.engine import Control
from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as Outcome

DEFINITIONS = {
    "xss": ("SL-C03-XSS-01", "input.reflected_xss", "C03", "high"),
    "sql": ("SL-C03-SQL-01", "input.sql_boolean", "C03", "high"),
    "html": ("SL-C03-HTML-01", "input.html_injection", "C03", "medium"),
    "redirect": ("SL-C04-REDIRECT-01", "browser.open_redirect", "C04", "medium"),
    "cors": ("SL-C04-CORS-01", "browser.cors_reflection", "C04", "low"),
}

# Per reviewed endpoint. No redirects or automatic retries are issued here. A
# fresh HTTPS connection can consume an additional broker-counted CONNECT.
HTTP_PROBE_LIMITS = {"sql": 18, "redirect": 2, "cors": 2}


def sql_probes(entry):
    """Bounded read-only comparisons for common input contexts, with no row extraction.

    A reviewed endpoint may supply a known ordinary search value. Without a useful
    baseline, the result remains inconclusive instead of inventing SQL coverage.
    """
    seed = str(entry.get("baseline_value", "apple"))[:100]
    number = str(entry.get("numeric_baseline", "1"))[:20]
    if not number.isdecimal():
        raise ValueError("numeric baseline must be decimal")
    if entry.get("sql_context") == "like":
        # Reviewed search endpoints may place the value inside a LIKE expression
        # and up to two grouping parentheses. Still repeated boolean comparisons
        # over ordinary public search results; no UNION, schema or credential reads.
        for depth in range(3):
            for name, value in [
                ("baseline", seed),
                ("negative", "scopelens-absent"),
                ("true1", f"{seed}%'{')' * depth} AND 1=1-- "),
                ("false1", f"{seed}%'{')' * depth} AND 1=2-- "),
                ("true2", f"{seed}%'{')' * depth} AND 2=2-- "),
                ("false2", f"{seed}%'{')' * depth} AND 2=3-- "),
            ]:
                yield f"like{depth}", name, value
        return
    if entry.get("sql_context", "comparison") != "comparison":
        raise ValueError("unknown reviewed SQL context")
    for group, baseline, negative, quote in [
        ("single", seed, "scopelens-absent", "'"),
        ("double", seed, "scopelens-absent", '"'),
        ("numeric", number, "0", ""),
    ]:

        def expression(left, right, baseline=baseline, quote=quote):
            if quote:
                return f"{baseline}{quote} AND {quote}{left}{quote}={quote}{right}"
            return f"{baseline} AND {left}={right}"

        for name, value in [
            ("baseline", baseline),
            ("negative", negative),
            ("true1", expression(1, 1)),
            ("false1", expression(1, 2)),
            ("true2", expression(2, 2)),
            ("false2", expression(2, 3)),
        ]:
            yield group, name, value


def http_probes(config):
    reviewed = json.loads(os.environ.get("SCOPELENS_CONDITIONAL_PROBES", "[]"))
    crawler = Crawler(config)
    client = crawler._http()
    for entry in reviewed:
        kind, path = entry["kind"], entry["path"]
        if kind not in {"sql", "redirect", "cors"} or not crawler._in_scope(config.origin + path):
            continue
        captures = []
        error = None
        if kind == "sql":
            probes = list(sql_probes(entry))
        else:
            probes = [
                (None, "first", "https://scopelens-a.invalid/marker"),
                (None, "second", "https://scopelens-b.invalid/marker"),
            ]
        if len(probes) > HTTP_PROBE_LIMITS[kind]:
            raise ValueError("reviewed endpoint probe budget exceeded")
        for group, name, value in probes:
            url = config.origin + path
            headers = {"Cache-Control": "no-cache", PROBE_HEADER: conditional_reference(entry)}
            if kind == "cors":
                headers["Origin"] = value.removesuffix("/marker")
            else:
                url += "?" + urlencode(
                    {entry["parameter"]: value}, safe=":/" if kind == "redirect" else ""
                )
            try:
                with client.stream("GET", url, headers=headers, follow_redirects=False) as r:
                    body = bytearray()
                    for chunk in r.iter_bytes():
                        if len(body) + len(chunk) > config.max_body_bytes:
                            raise ValueError("response cap")
                        body.extend(chunk)
                    captures.append(
                        {
                            "name": name,
                            **({"group": group} if group is not None else {}),
                            "probe_value": value,
                            "location": r.headers.get("location"),
                            "allow_origin": r.headers.get("access-control-allow-origin"),
                            "status": r.status_code,
                            "body_hash": hashlib.sha256(body).hexdigest(),
                            "location_matches": r.headers.get("location") == value,
                            "origin_matches": r.headers.get("access-control-allow-origin")
                            == headers.get("Origin")
                            and "Origin" in headers,
                            "acac": r.headers.get("access-control-allow-credentials") == "true",
                        }
                    )
            except Exception as exc:  # noqa: BLE001 - missing measurement remains unassessed
                error = type(exc).__name__
                break
        yield {
            "kind": "active_probe",
            "source": "active",
            "data": {
                "kind": kind,
                "route": path,
                "parameter": entry.get("parameter"),
                "captures": captures,
                "error": error,
                "reviewed": True,
            },
        }


def proof(kind, captures):
    if kind in {"xss", "html"}:
        if len(captures) != 3 or any(
            c.get("status") != 200 or not c.get("response_url_matches") for c in captures
        ):
            return None
        if captures[0].get("marker_present"):
            return None
        nonces = [c.get("nonce") for c in captures]
        if not all(isinstance(n, str) and len(n) == 32 for n in nonces) or len(set(nonces)) != 3:
            return None
        positive = [bool(c.get("marker_present") and c.get("nonce_matches")) for c in captures[1:]]
        if (
            any(c.get("marker_present") and not c.get("nonce_matches") for c in captures[1:])
            or len(set(positive)) != 1
        ):
            return None
        return all(positive)
    if kind == "sql":
        if any("group" in c for c in captures):
            groups = {c.get("group") for c in captures}
            if (
                groups not in ({"single", "double", "numeric"}, {"like0", "like1", "like2"})
                or len(captures) != 18
            ):
                return None
            values = [
                proof(
                    "sql",
                    [
                        {k: v for k, v in c.items() if k != "group"}
                        for c in captures
                        if c.get("group") == group
                    ],
                )
                for group in sorted(groups)
            ]
            return True if True in values else False if False in values else None
        byname = {c["name"]: c for c in captures}
        if (
            len(captures) != 6
            or set(byname) != {"baseline", "negative", "true1", "false1", "true2", "false2"}
            or any(c["status"] != 200 for c in captures)
        ):
            return None
        hashes = {k: v["body_hash"] for k, v in byname.items()}
        if (
            hashes["baseline"] == hashes["negative"]
            or hashes["true1"] != hashes["true2"]
            or hashes["false1"] != hashes["false2"]
        ):
            return None
        return (
            hashes["baseline"] == hashes["true1"] == hashes["true2"]
            and hashes["negative"] == hashes["false1"] == hashes["false2"]
            and hashes["baseline"] != hashes["negative"]
        )
    if len(captures) != 2 or any(not 200 <= c["status"] < 400 for c in captures):
        return None
    if kind == "redirect":
        positive = [
            c["status"] in {301, 302, 303, 307, 308} and c["location_matches"] for c in captures
        ]
    else:
        positive = [c["origin_matches"] and c["acac"] for c in captures]
    return all(positive) if len(set(positive)) == 1 else None


def evaluate(kind, ctx):
    check, canonical, category, severity = DEFINITIONS[kind]
    captures = [a for a in ctx.active_captures if a.get("data", {}).get("kind") == kind]
    outcomes = []
    evidence = []
    locations = []
    required = []
    completed = []
    for a in captures:
        raw = a["data"]
        route = raw["route"]
        required.append(route)
        ref = a.get("evidence_ref")
        value = (
            proof(kind, raw.get("captures", []))
            if ref in ctx.evidence.values() and raw.get("reviewed") and not raw.get("error")
            else None
        )
        outcomes.append(value)
        if value is not None:
            completed.append(route)
        if value:
            evidence.append(ref)
            locations.append(Location(route=route, parameter=raw.get("parameter")))
    status = (
        Outcome.CONFIRMED_ISSUE
        if evidence
        else Outcome.PASS
        if captures and all(v is False for v in outcomes)
        else Outcome.NOT_TESTED
        if not captures
        else Outcome.INCONCLUSIVE
    )
    summary = (
        "Reviewed paired probes observed the condition"
        if evidence
        else "No issue observed under the reviewed paired probes"
        if status == Outcome.PASS
        else "No conclusive approved paired probe completed"
    )
    if kind == "cors" and evidence:
        summary = "Two foreign origins were reflected with credentials allowed; protected-data exposure was not tested"
    return ControlOutcome(
        check_id=check,
        canonical_control=canonical,
        category=Category(category),
        status=status,
        summary=summary,
        proposed_severity=Severity(severity) if evidence else None,
        locations=tuple(locations),
        required_instances=tuple(required or ["approved-endpoint"]),
        completed_instances=tuple(completed),
        proof=ProofResult(
            satisfied=True,
            status=EvidenceStatus.CONFIRMED,
            reasons=(summary,),
            evidence_refs=tuple(evidence),
        )
        if evidence
        else None,
    )


CONTROLS = tuple(
    Control(check_id=definition[0], evaluate=partial(evaluate, kind))
    for kind, definition in DEFINITIONS.items()
)
