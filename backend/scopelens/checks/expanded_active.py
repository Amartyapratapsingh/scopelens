"""Reviewed input probes over discovered request templates through an injected broker client.

Captures contain response facts and digests, never credentials or response bodies. The
trusted supervisor must attach evidence provenance before a finding can be confirmed.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from scopelens.broker.probe_tasks import PROBE_HEADER, input_reference
from scopelens.discovery.catalogue import changing_json_fields
from scopelens.discovery.requests import render_request
from scopelens.domain.assessment import AssessmentPlanVersion, DiscoveryCatalogue

CONTROL_KINDS = {
    "SL-C03-SQL-01": "sql",
    "SL-C04-REDIRECT-01": "redirect",
    "SL-C04-CORS-01": "cors",
    "SL-C04-HDRINJECT-01": "header_injection",
    "SL-C03-XSS-01": "xss",
    "SL-C03-HTML-01": "html",
    "SL-C03-DOMXSS-01": "dom_xss",
}
NOISE_FIELD = re.compile(
    r"(?:^|/)(?:timestamp|request_id|requestId|trace_id|traceId|nonce|generated_at)$"
)


class ProbeStopped(Exception):
    pass


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _without_fields(value, excluded, pointer=""):
    if isinstance(value, dict):
        return {
            key: _without_fields(
                child, excluded, pointer + "/" + key.replace("~", "~0").replace("/", "~1")
            )
            for key, child in value.items()
            if pointer + "/" + key.replace("~", "~0").replace("/", "~1") not in excluded
        }
    if isinstance(value, list):
        return [_without_fields(child, excluded, f"{pointer}/{n}") for n, child in enumerate(value)]
    return value


def evaluate_expanded(
    kind: str, captures: list[dict], *, error: str | None = None
) -> tuple[str, str]:
    """Pure proof evaluation. Browser families require the controlled browser collector."""
    if error:
        return "inconclusive", error
    if not captures or any(c.get("truncated") for c in captures):
        return "inconclusive", "complete_response_required"
    if kind in {"xss", "html", "dom_xss"}:
        byname = {c.get("name"): c for c in captures}
        if set(byname) != {"baseline", "probe1", "probe2"} or len(captures) != 3:
            return "inconclusive", "complete_browser_control_series_required"
        nonces = [c.get("nonce") for c in captures]
        if not all(isinstance(n, str) and len(n) == 32 for n in nonces) or len(set(nonces)) != 3:
            return "inconclusive", "independent_browser_nonces_required"
        if any(
            c.get("status") != 200
            or not c.get("response_url_matches")
            or c.get("blocked_subrequests")
            for c in captures
        ):
            return "inconclusive", "navigation_or_dependency_incomplete"
        if byname["baseline"].get("marker_present"):
            return "inconclusive", "baseline_marker_contamination"
        positive = [byname[name] for name in ("probe1", "probe2")]
        if kind == "dom_xss" and any(c.get("marker_in_response") is not False for c in positive):
            return "inconclusive", "reflection_channel_not_dom_only_proof"
        if all(c.get("marker_present") and c.get("nonce_matches") for c in positive):
            return (
                "confirmed",
                "fresh_context_marker_rendering"
                if kind == "html"
                else "fresh_context_marker_execution",
            )
        if all(c.get("marker_present") is False for c in positive):
            return "pass", "marker_not_rendered" if kind == "html" else "marker_not_executed"
        return "inconclusive", "inconsistent_repeated_browser_observation"
    if kind == "sql":
        verdicts = []
        groups = {c.get("group") for c in captures}
        if not groups or not groups <= {"single", "double", "numeric"}:
            return "inconclusive", "unknown_sql_context"
        for group in sorted(groups):
            rows = {c["name"]: c for c in captures if c.get("group") == group}
            if set(rows) != {
                "baseline1",
                "baseline2",
                "negative1",
                "negative2",
                "true1",
                "true2",
                "false1",
                "false2",
            } or any(r["status"] != 200 for r in rows.values()):
                verdicts.append(None)
                continue
            hashes = {name: row["normalized_hash"] for name, row in rows.items()}
            stable = all(
                hashes[f"{name}1"] == hashes[f"{name}2"]
                for name in ("baseline", "negative", "true", "false")
            )
            if not stable or hashes["baseline1"] == hashes["negative1"]:
                verdicts.append(None)
                continue
            verdicts.append(
                hashes["baseline1"] == hashes["true1"] and hashes["negative1"] == hashes["false1"]
            )
        if True in verdicts:
            return "confirmed", "repeated_boolean_difference_matches_baseline_and_negative"
        if all(value is False for value in verdicts):
            return "pass", "no_boolean_injection_under_tested_contexts"
        return "inconclusive", "unstable_or_nondiscriminating_sql_baseline"
    byname = {c["name"]: c for c in captures}
    if set(byname) != {"baseline", "probe1", "probe2"} or any(
        not 200 <= c["status"] < 400 for c in captures
    ):
        return "inconclusive", "complete_successful_control_series_required"
    if kind == "redirect":
        positives = [
            byname[n]["status"] in {301, 302, 303, 307, 308}
            and byname[n].get("controlled_location")
            for n in ("probe1", "probe2")
        ]
    elif kind == "cors":
        positives = [
            byname[n].get("origin_matches") and byname[n].get("credentials_allowed")
            for n in ("probe1", "probe2")
        ]
    elif kind == "header_injection":
        if byname["baseline"].get("marker_header"):
            return "inconclusive", "marker_header_present_in_baseline"
        positives = [byname[n].get("marker_header_matches") for n in ("probe1", "probe2")]
    else:
        return "inconclusive", "unsupported_proof_family"
    if positives == [True, True]:
        reason = (
            "foreign_origin_reflection_with_credentials_config_only"
            if kind == "cors"
            else "two_independent_controlled_markers_confirmed"
        )
        return "confirmed", reason
    if positives == [False, False]:
        return "pass", "condition_absent_under_tested_inputs"
    return "inconclusive", "inconsistent_repeated_observation"


def run_expanded_checks(
    catalogue: DiscoveryCatalogue,
    plan: AssessmentPlanVersion,
    client: httpx.Client,
    *,
    secret_resolver: Callable[[str], str] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    max_requests: int = 200,
    max_body_bytes: int = 1048576,
    authenticated_transport=None,
) -> list[dict[str, Any]]:
    """Execute only ready HTTP tasks through caller's mandatory broker-bound client.

    The caller must validate frozen policy, scope/version and task budget before invocation.
    This limit is an additional per-call bound; the broker owns durable shared budgets.
    Browser-only tasks emit blocked artifacts so their coverage cannot disappear.
    """
    templates = {t.id: t for t in catalogue.templates}
    request_count = 0
    artifacts = []

    def fetch(template, key=None, value=None, extra_headers=None):
        nonlocal request_count
        if cancelled():
            raise ProbeStopped("cancelled")
        if request_count >= max_requests:
            raise ProbeStopped("request_budget_exhausted")
        args = render_request(template, {key: value} if key is not None else {}, secret_resolver)
        args["headers"].update({"Cache-Control": "no-cache", **(extra_headers or {})})
        if template.method == "GET":
            args["headers"][PROBE_HEADER] = input_reference(task.id)
        request_count += 1
        body = bytearray()
        stream = (
            authenticated_transport.stream(template, **args, follow_redirects=False)
            if template.role_id != "anonymous" and authenticated_transport is not None
            else client.stream(**args, follow_redirects=False)
        )
        with stream as response:
            for chunk in response.iter_bytes():
                if cancelled():
                    raise ProbeStopped("cancelled")
                body.extend(chunk[: max_body_bytes + 1 - len(body)])
                if len(body) > max_body_bytes:
                    break
            data = bytes(body[:max_body_bytes])
            try:
                decoded = (
                    json.loads(data) if "json" in response.headers.get("content-type", "") else None
                )
            except (ValueError, UnicodeDecodeError):
                decoded = None
            capture = {
                "status": response.status_code,
                "body_hash": _digest(data),
                "normalized_hash": _digest(data),
                "body_bytes": len(data),
                "truncated": len(body) > max_body_bytes,
                "response_url_matches": urlsplit(str(response.url)).path
                == urlsplit(args["url"]).path,
            }
            return capture, decoded, response.headers

    for task in plan.tasks:
        kind = CONTROL_KINDS.get(task.control_id)
        template = templates.get(task.template_id)
        state, reason, captures = "blocked", task.reason, []
        error = None
        used_before = request_count
        if task.state == "ready" and template is not None:
            if kind in {"xss", "html", "dom_xss"}:
                reason = "controlled_browser_confirmation_required"
            elif kind is None:
                reason = "unimplemented_control"
            elif template.authority in {"unapproved", "resource_only"}:
                reason = "origin_not_granted_for_assessment"
            elif not template.baseline_complete:
                reason = "request_baseline_incomplete"
            elif template.role_id != "anonymous" and (
                authenticated_transport is None or not authenticated_transport.accepts(template)
            ):
                reason = "authenticated_input_transport_not_integrated"
            else:
                location = next((i for i in template.inputs if i.key == task.input_key), None)
                error = None
                try:
                    if kind == "sql":
                        if (
                            location is None
                            or location.baseline_value is None
                            or location.secret_ref
                        ):
                            raise ProbeStopped("ordinary_baseline_missing")
                        seed = str(location.baseline_value)[:100]
                        for group, quote in (("single", "'"), ("double", '"'), ("numeric", "")):
                            if not quote and not seed.isdecimal():
                                continue
                            base = seed
                            negative = (
                                "0" if not quote else "scopelens-absent-" + uuid.uuid4().hex[:12]
                            )
                            truth = (
                                f"{base}{quote} AND {quote}1{quote}={quote}1"
                                if quote
                                else f"{base} AND 1=1"
                            )
                            falsity = (
                                f"{base}{quote} AND {quote}1{quote}={quote}2"
                                if quote
                                else f"{base} AND 1=2"
                            )
                            values = (
                                ("baseline1", base),
                                ("baseline2", base),
                                ("negative1", negative),
                                ("negative2", negative),
                                ("true1", truth),
                                ("true2", truth),
                                ("false1", falsity),
                                ("false2", falsity),
                            )
                            decoded_rows = []
                            group_captures = []
                            for name, value in values:
                                capture, decoded, _ = fetch(template, task.input_key, value)
                                capture.update(name=name, group=group)
                                group_captures.append(capture)
                                captures.append(capture)
                                decoded_rows.append(decoded)
                            noisy = (
                                changing_json_fields(decoded_rows[:2])
                                if all(v is not None for v in decoded_rows)
                                else ()
                            )
                            ignored = tuple(p for p in noisy if NOISE_FIELD.search(p))
                            if ignored:
                                for row, decoded in zip(group_captures, decoded_rows, strict=True):
                                    row["normalized_hash"] = _digest(
                                        json.dumps(
                                            _without_fields(decoded, set(ignored)),
                                            sort_keys=True,
                                            separators=(",", ":"),
                                        ).encode()
                                    )
                                    row["ignored_noise_fields"] = ignored
                    else:
                        for n, name in enumerate(("baseline", "probe1", "probe2")):
                            marker = uuid.uuid4().hex
                            destination = f"https://{marker}.scopelens.invalid/marker"
                            extra_headers = (
                                {"Origin": destination.removesuffix("/marker")}
                                if kind == "cors" and n
                                else {}
                            )
                            value = (
                                destination
                                if kind == "redirect"
                                else f"scopelens-{marker}\r\nX-Scopelens-Probe: {marker}"
                            )
                            capture, _, headers = fetch(
                                template,
                                task.input_key if n and kind != "cors" else None,
                                value,
                                extra_headers,
                            )
                            capture["name"] = name
                            if kind == "redirect":
                                actual = urljoin(
                                    template.origin + template.path, headers.get("location", "")
                                )
                                capture["controlled_location"] = (
                                    actual == destination and urlsplit(actual).username is None
                                )
                            elif kind == "cors":
                                capture["origin_matches"] = bool(
                                    extra_headers
                                ) and headers.get_list("access-control-allow-origin") == [
                                    extra_headers["Origin"]
                                ]
                                capture["credentials_allowed"] = headers.get_list(
                                    "access-control-allow-credentials"
                                ) == ["true"]
                            else:
                                capture["marker_header"] = bool(
                                    headers.get_list("x-scopelens-probe")
                                )
                                capture["marker_header_matches"] = headers.get_list(
                                    "x-scopelens-probe"
                                ) == [marker]
                            captures.append(capture)
                except ProbeStopped as exc:
                    error = str(exc)
                except (httpx.HTTPError, ValueError, OSError, KeyError, TypeError) as exc:
                    error = type(exc).__name__
                state, reason = evaluate_expanded(kind, captures, error=error)
        elif template is None:
            reason = "carried_task_template_not_in_current_catalogue"
        artifacts.append(
            {
                "kind": "expanded_active_probe",
                "source": "expanded_active",
                "data": {
                    "task_id": task.id,
                    "plan_id": plan.id,
                    "template_id": task.template_id,
                    "control_id": task.control_id,
                    "input_key": task.input_key,
                    "kind": kind,
                    "route": template.path if template else None,
                    "method": template.method if template else None,
                    "role_id": template.role_id if template else None,
                    "state": state,
                    "reason": reason,
                    "error": error,
                    "captures": captures,
                    "requests_used": request_count - used_before,
                    "reviewed": True,
                },
            }
        )
    return artifacts
