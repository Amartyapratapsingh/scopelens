"""Harmless rendering/execution proof in fresh broker-bound browser contexts.

The caller supplies a context factory configured with the mandatory proxy, scoped egress
capability and reviewed identity. This module never creates an unrestricted browser.
"""

import json
import uuid
from contextlib import nullcontext
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError

from scopelens.broker.probe_tasks import PROBE_HEADER, input_reference
from scopelens.discovery.catalogue import canonical_origin
from scopelens.discovery.planner import SIDE_EFFECT
from scopelens.discovery.requests import render_request
from scopelens.identities.sessions import SessionUnavailable

BROWSER_CONTROLS = {
    "SL-C03-XSS-01": "xss",
    "SL-C03-HTML-01": "html",
    "SL-C03-DOMXSS-01": "dom_xss",
}


def run_expanded_browser_checks(
    catalogue,
    plan,
    context_factory,
    *,
    secret_resolver=None,
    probe_lifecycle=None,
    cancelled=lambda: False,
    max_actions=30,
    navigation_timeout_ms=10000,
    action_admission=None,
    max_exploration_actions=None,
):
    """context_factory(role_id) -> fresh context with externally enforced scope and budgets.

    Initial requests may use an explicitly reviewed POST body; subrequests are GET/HEAD
    only. A page can never submit additional writes through this collector. DOM-XSS
    confirmation additionally requires the marker absent from the initial response body.
    """
    templates = {t.id: t for t in catalogue.templates}
    allowed_origins = {
        t.origin for t in catalogue.templates if t.authority in {"primary", "scan", "resource_only"}
    }
    actions = 0
    exploration_actions = 0
    exploration_limit = (
        max_exploration_actions if max_exploration_actions is not None else min(max_actions, 30)
    )
    artifacts = []
    for task in plan.tasks:
        kind = BROWSER_CONTROLS.get(task.control_id)
        if kind is None:
            continue
        template = templates.get(task.template_id)
        captures = []
        identity_proofs = []
        reason, state = task.reason, "blocked"
        if (
            task.state == "ready"
            and template
            and template.authority in {"primary", "scan"}
            and template.baseline_complete
        ):
            try:
                if template.role_id != "anonymous" and probe_lifecycle is None:
                    raise ValueError("authenticated_browser_identity_proof_required")
                for name in ("baseline", "probe1", "probe2"):
                    if cancelled():
                        raise ValueError("cancelled")
                    if actions >= max_actions:
                        raise ValueError("browser_action_budget_exhausted")
                    if template.method != "GET" and exploration_actions >= exploration_limit:
                        raise ValueError("browser_action_budget_exhausted")
                    marker = uuid.uuid4().hex
                    payload = (
                        f'<span data-scopelens-marker="{marker}">ScopeLens</span>'
                        if kind == "html"
                        else f"<svg onload=\"window.__scopelensMarker='{marker}'\"></svg>"
                    )
                    if template.role_id != "anonymous":
                        probe_lifecycle.validate(task, template, plan.id, name)
                    request = render_request(
                        template,
                        {task.input_key: payload} if name != "baseline" else {},
                        secret_resolver,
                    )
                    if template.method == "GET":
                        request["headers"][PROBE_HEADER] = input_reference(task.id)
                    if "json" in request:
                        body = json.dumps(request["json"])
                    else:
                        body = request.get("content")
                    authenticated = None
                    if template.role_id != "anonymous":
                        authenticated = probe_lifecycle.open(task, template, plan.id, name, request)
                        identity_proofs.append(authenticated.proof)
                    context = None
                    initial_sent = False
                    blocked = []
                    try:
                        context = (
                            authenticated.before()
                            if authenticated
                            else context_factory(template.role_id)
                        )
                        cookie_header = request["headers"].pop("Cookie", "")
                        if cookie_header:
                            context.add_cookies(
                                [
                                    {
                                        "name": item.strip().split("=", 1)[0],
                                        "value": item.strip().split("=", 1)[1],
                                        "url": template.origin,
                                    }
                                    for item in cookie_header.split(";")
                                ]
                            )

                        def guard(
                            route,
                            _request=None,
                            *,
                            request=request,
                            blocked=blocked,
                            body=body,
                            authenticated=authenticated,
                        ):
                            nonlocal initial_sent
                            pending = route.request
                            try:
                                allowed = canonical_origin(pending.url) in allowed_origins
                            except ValueError:
                                allowed = False
                            first = (
                                pending.is_navigation_request()
                                and not initial_sent
                                and pending.url == request["url"]
                            )
                            if (
                                cancelled()
                                or not allowed
                                or (
                                    not first
                                    and (
                                        pending.method not in {"GET", "HEAD"}
                                        or SIDE_EFFECT.search(urlsplit(pending.url).path)
                                    )
                                )
                            ):
                                blocked.append("subrequest_not_admitted")
                                route.abort()
                                return
                            if authenticated:
                                try:
                                    authenticated.available()
                                    if canonical_origin(pending.url) != authenticated.origin:
                                        raise SessionUnavailable(
                                            "browser credential origin mismatch"
                                        )
                                    if first:
                                        initial_sent = True
                                        authenticated.navigate(route, request, body)
                                    else:
                                        authenticated.navigate(
                                            route,
                                            {
                                                "url": pending.url,
                                                "method": pending.method,
                                                "headers": {},
                                            },
                                            None,
                                            supply_headers=False,
                                        )
                                    return
                                except (
                                    SessionUnavailable,
                                    PermissionError,
                                    KeyError,
                                    OSError,
                                    PlaywrightError,
                                ):
                                    authenticated.failed = True
                                    blocked.append("authenticated_request_unavailable")
                                    route.abort()
                                    return
                            if first:
                                initial_sent = True
                                route.continue_(
                                    method=request["method"],
                                    headers={**pending.headers, **request["headers"]},
                                    post_data=body,
                                )
                            else:
                                route.continue_()

                        context.route("**/*", guard)
                        page = context.new_page()
                        actions += 1
                        with (
                            action_admission(task, request)
                            if action_admission is not None
                            else nullcontext(False)
                        ) as reviewed:
                            if reviewed is not True:
                                if exploration_actions >= exploration_limit:
                                    raise ValueError("browser_action_budget_exhausted")
                                exploration_actions += 1
                            response = page.goto(
                                request["url"],
                                wait_until="networkidle",
                                timeout=navigation_timeout_ms,
                            )
                            if response is None:
                                raise ValueError("navigation_response_missing")
                            if cancelled():
                                raise ValueError("cancelled")
                            present = (
                                page.locator(f'[data-scopelens-marker="{marker}"]').count() > 0
                                if kind == "html"
                                else page.evaluate(
                                    "nonce => window.__scopelensMarker === nonce", marker
                                )
                            )
                            captures.append(
                                {
                                    **(
                                        {"context_id": authenticated.context_id}
                                        if authenticated
                                        else {}
                                    ),
                                    "name": name,
                                    "nonce": marker,
                                    "status": response.status,
                                    "marker_present": bool(present),
                                    "nonce_matches": bool(present),
                                    "response_url_matches": urlsplit(page.url).path == template.path
                                    and canonical_origin(page.url) == template.origin,
                                    "blocked_subrequests": len(blocked),
                                    "marker_in_response": marker in response.text(),
                                }
                            )
                    finally:
                        if authenticated:
                            authenticated.finish()
                        elif context is not None:
                            context.close()
                from scopelens.checks.expanded_active import evaluate_expanded

                state, reason = evaluate_expanded(kind, captures)
            except ValueError as exc:
                state, reason = (
                    "inconclusive",
                    str(exc)
                    if str(exc)
                    in {
                        "cancelled",
                        "browser_action_budget_exhausted",
                        "browser_action_not_admitted",
                        "navigation_response_missing",
                        "authenticated_browser_identity_proof_required",
                    }
                    else "request_not_renderable",
                )
            except (SessionUnavailable, PermissionError, KeyError, OSError):
                state, reason = "inconclusive", "authenticated_browser_identity_unavailable"
            except PlaywrightError as exc:
                state, reason = "inconclusive", type(exc).__name__
        artifacts.append(
            {
                "kind": "expanded_active_probe",
                "source": "expanded_browser",
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
                    "captures": captures,
                    **(
                        {"browser_identity_proofs": identity_proofs}
                        if template and template.role_id != "anonymous"
                        else {}
                    ),
                    "actions_used": len(captures),
                    "reviewed": True,
                },
            }
        )
    return artifacts
