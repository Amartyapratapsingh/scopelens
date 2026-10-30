"""Fixed expanded browser collector inside the existing isolated browser worker image.

The launch path requires the scan proxy, its CA and a durable browser owner. Frozen
configuration grants constrain browser/API requests locally; the proxy independently
checks every request against live authority and the shared persisted scan budgets.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

from scopelens.browser.admission import ReviewedCaptureAdmission
from scopelens.browser.bridge import Bridge
from scopelens.browser.expanded_active import run_expanded_browser_checks
from scopelens.browser.worker import Controller
from scopelens.browser.workflow_checks import run_browser_workflow
from scopelens.checks.crawl import Crawler, config_from_env
from scopelens.discovery.catalogue import canonical_origin
from scopelens.discovery.planner import SIDE_EFFECT
from scopelens.domain.assessment import AssessmentPlanVersion, DiscoveryCatalogue
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import IdentityProfile, PermissionMatrix
from scopelens.expansion.authenticated_browser import AuthenticatedBrowserLifecycle
from scopelens.expansion.client import AssessmentControlClient
from scopelens.expansion.worker import emit
from scopelens.identities.browser import BrowserIdentitySessions
from scopelens.identities.cors import (
    collect_cors_proof,
    cors_configuration_binding,
    evaluate_cors_proof,
)
from scopelens.identities.proof import select_identity_response
from scopelens.identities.sessions import SessionUnavailable

_cancelled = False


def _cancel(*_):
    global _cancelled
    _cancelled = True


class RequestGuard:
    """Local request cap and exact write grants; neither replaces proxy authorization."""

    def __init__(self, configuration, catalogue, plan, crawl, *, cancelled, limit, cleanup=False):
        self.cancelled, self.limit, self.used = cancelled, limit, 0
        self.cleanup_only = cleanup
        self.primary, self.crawl = canonical_origin(crawl.origin), crawl
        self.origins = {self.primary} | {
            grant.origin for grant in configuration.related_origins if grant.purpose == "scan"
        }
        self.explicit = set()
        self.writes = set()
        for identity in configuration.identities:
            for request in (
                identity.login.request if identity.login else None,
                identity.probe.request if identity.probe else None,
            ):
                if request:
                    self.add(request.method, request.url)
        for recipe in configuration.browser_workflows:
            requests = (
                (recipe.readback, recipe.cleanup)
                if cleanup
                else (recipe.readback, recipe.mutation, recipe.cleanup)
            )
            for request in requests:
                self.add(request.method, request.url)
            for url in (
                () if cleanup else (recipe.viewer_url, recipe.foreign_url, recipe.upload_form_url)
            ):
                if url:
                    self.add("GET", url)
        if not cleanup:
            for recipe in configuration.cors_recipes:
                self.add("GET", recipe.target.request.url)
                self.add("GET", recipe.foreign_url)
        ready = {task.template_id for task in plan.tasks if task.state == "ready"}
        for template in catalogue.templates:
            if not cleanup and template.id in ready and template.authority in {"primary", "scan"}:
                self.add(template.method, template.origin + template.path)

    @staticmethod
    def key(method, url):
        return method.upper(), canonical_origin(url), urlsplit(url).path or "/"

    def add(self, method, url):
        key = self.key(method, url)
        self.explicit.add(key)
        if method.upper() not in {"GET", "HEAD"}:
            self.writes.add(key)

    def admit(self, method, url):
        if self.cancelled():
            raise SessionUnavailable("browser_cancelled")
        if self.used >= self.limit:
            raise SessionUnavailable("browser_request_budget_exhausted")
        try:
            key = self.key(method, url)
        except ValueError as exc:
            raise SessionUnavailable("browser_destination_invalid") from exc
        if key[1] not in self.origins:
            raise SessionUnavailable("browser_origin_not_granted")
        if self.cleanup_only and key not in self.explicit:
            raise SessionUnavailable("cleanup_request_not_granted")
        path = key[2]
        if key[1] == self.primary and (
            not any(path.startswith(prefix) for prefix in self.crawl.allowed_path_prefixes)
            or any(path.startswith(prefix) for prefix in self.crawl.excluded_paths)
        ):
            raise SessionUnavailable("browser_path_not_granted")
        if (key[0] not in {"GET", "HEAD"} and key not in self.writes) or (
            SIDE_EFFECT.search(path) and key not in self.explicit
        ):
            raise SessionUnavailable("browser_action_not_granted")
        self.used += 1


class _RequestAPI:
    def __init__(self, context, guard, token):
        self.api, self.guard, self.token = context.request, guard, token

    def fetch(self, url, **kwargs):
        self.guard.admit(kwargs.get("method", "GET"), url)
        kwargs["headers"] = {**kwargs.get("headers", {}), "x-scopelens-egress": self.token}
        kwargs["max_redirects"] = 0
        kwargs["max_retries"] = 0
        return self.api.fetch(url, **kwargs)

    def get(self, url, **kwargs):
        return self.fetch(url, method="GET", **kwargs)


class _Route:
    def __init__(self, route, guard, token):
        self.raw, self.guard, self.token = route, guard, token
        self.request = route.request

    def abort(self, *args, **kwargs):
        return self.raw.abort(*args, **kwargs)

    def fulfill(self, *args, **kwargs):
        # Rendering an already broker-fetched response adds no network authority.
        return self.raw.fulfill(*args, **kwargs)

    def continue_(self, **kwargs):
        try:
            self.guard.admit(kwargs.get("method", self.request.method), self.request.url)
        except SessionUnavailable:
            return self.raw.abort()
        kwargs["headers"] = {
            **kwargs.get("headers", self.request.headers),
            "x-scopelens-egress": self.token,
        }
        return self.raw.continue_(**kwargs)


class GuardedContext:
    """Keep the local guard even when a collector installs its own route handler."""

    def __init__(self, context, guard, token):
        self.raw, self.guard, self.token = context, guard, token
        self.request = _RequestAPI(context, guard, token)
        self.route("**/*", lambda route: route.continue_())
        context.route_web_socket("**/*", lambda ws: ws.close())
        context.on("page", self._page)

    @staticmethod
    def _page(page):
        page.set_default_timeout(5000)
        page.set_default_navigation_timeout(10000)
        page.on("dialog", lambda dialog: dialog.dismiss())
        page.on("popup", lambda popup: popup.close())
        page.on("download", lambda download: download.cancel())

    def route(self, pattern, callback):
        self.raw.route(pattern, lambda route: callback(_Route(route, self.guard, self.token)))

    def __getattr__(self, name):
        return getattr(self.raw, name)


def collect_browser_assessments(
    configuration,
    catalogue,
    plan,
    browser,
    control,
    crawl,
    emit_artifact,
    *,
    owner,
    token,
    cancelled,
    max_actions=30,
    max_requests=240,
    action_admission=None,
    max_exploration_actions=None,
):
    """Collect bound evidence; only the supervisor can attach trusted evidence IDs."""
    if not owner:
        raise ValueError("browser action owner required")
    guard = RequestGuard(
        configuration, catalogue, plan, crawl, cancelled=cancelled, limit=max_requests
    )
    cleanup_guard = RequestGuard(
        configuration, catalogue, plan, crawl, cancelled=lambda: False, limit=60, cleanup=True
    )
    profiles = configuration.identities
    if not any(profile.id == "anonymous" for profile in profiles):
        profiles = (*profiles, IdentityProfile(id="anonymous", role="anonymous", anonymous=True))

    def factory(request_guard):
        def create(_identity):
            raw = browser.new_context(
                viewport={"width": 1280, "height": 720},
                service_workers="block",
                accept_downloads=False,
            )
            return GuardedContext(raw, request_guard, token)

        return create

    input_lifecycle = AuthenticatedBrowserLifecycle(
        catalogue, plan, profiles, factory(guard), control.secret, cancelled=cancelled
    )

    sessions = BrowserIdentitySessions(
        profiles, control.secret, factory(guard), cancelled=cancelled
    )
    cleanup_sessions = BrowserIdentitySessions(profiles, control.secret, factory(cleanup_guard))
    incomplete = []
    try:
        try:
            for artifact in run_expanded_browser_checks(
                catalogue,
                plan,
                factory(guard),
                probe_lifecycle=input_lifecycle,
                secret_resolver=lambda ref: control.secret(ref).get_secret_value(),
                cancelled=cancelled,
                max_actions=max_actions,
                action_admission=action_admission,
                max_exploration_actions=max_exploration_actions,
            ):
                emit_artifact(artifact["kind"], artifact["data"])
                if artifact["data"].get("state") not in {"pass", "confirmed"}:
                    incomplete.append(artifact["data"].get("task_id", "browser_input"))
        except (SessionUnavailable, PermissionError):
            incomplete.append("browser_identity_or_control_unavailable")
            emit_artifact(
                "expansion_gap",
                {"reason": "browser_identity_or_control_unavailable", "plan_id": plan.id},
            )
        cors_binding = cors_configuration_binding(configuration)
        for recipe in configuration.cors_recipes:

            def emit_cors(proof, recipe=recipe):
                emit_artifact(
                    "identity_observation",
                    {
                        "proof_type": "credentialed_cors",
                        "proof_id": recipe.id,
                        "kind": "credentialed_cors_proof",
                        **proof,
                    },
                )

            proof = collect_cors_proof(
                recipe,
                profiles,
                factory(guard),
                control.secret,
                action_owner=owner,
                configuration_binding=cors_binding,
                allowed_foreign_origins=frozenset(guard.origins),
                cancelled=cancelled,
                capture=emit_cors,
            )
            state, _ = evaluate_cors_proof(
                recipe, profiles, proof, configuration_binding=cors_binding
            )
            if state != "confirmed":
                incomplete.append(recipe.id)
        for recipe in configuration.browser_workflows:
            binding = {"proof_type": "browser_workflow", "proof_id": recipe.id}

            def observe(identity_id, request, status, document, binding=binding):
                response = SimpleNamespace(status_code=status, json=lambda: document)
                selected = select_identity_response(
                    identity_id,
                    request,
                    response,
                    profiles,
                    PermissionMatrix(version="browser-probes-v1", objects=(), rules=()),
                    evidence_ref="pending-intake",
                )
                emit_artifact("identity_response", {**selected.model_dump(mode="json"), **binding})

            sessions.response_observer = observe
            cleanup_sessions.response_observer = observe

            def capture(data, binding=binding):
                emit_artifact("identity_observation", {**data, **binding})
                return "pending-intake"

            result = run_browser_workflow(
                recipe,
                sessions,
                cleanup_sessions,
                control,
                capture,
                admit=lambda item: (
                    item in configuration.browser_workflows and bool(item.action_grant_id)
                ),
                allowed_foreign_origins=frozenset(guard.origins),
                action_owner=owner,
            )
            emit_artifact("workflow_capture", {**result.model_dump(mode="json"), **binding})
            if result.state not in {"pass", "confirmed"} or result.cleanup_state != "clean":
                incomplete.append(recipe.id)
    finally:
        for item in (sessions, cleanup_sessions):
            with suppress(Exception):
                item.close()
    return {
        "requests": guard.used,
        "cleanup_requests": cleanup_guard.used,
        "cancelled": cancelled(),
        "complete": not cancelled() and not incomplete,
        "incomplete_instances": incomplete,
    }


def _install_proxy_ca():
    home = Path("/tmp/browser-home")
    db = home / ".pki/nssdb"
    db.mkdir(parents=True, exist_ok=True)
    ca = home / "proxy.pem"
    ca.write_text(os.environ["SCOPELENS_PROXY_CA_PEM"])
    subprocess.run(
        ["certutil", "-N", "-d", f"sql:{db}", "--empty-password"], check=True, capture_output=True
    )
    subprocess.run(
        [
            "certutil",
            "-A",
            "-d",
            f"sql:{db}",
            "-n",
            "ScopeLens capture proxy",
            "-t",
            "C,,",
            "-i",
            str(ca),
        ],
        check=True,
        capture_output=True,
    )


def main():
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGINT, _cancel)
    payload = json.loads(os.environ["SCOPELENS_EXPANSION_INPUT"])
    configuration = AssessmentConfiguration.model_validate(payload["configuration"])
    catalogue = DiscoveryCatalogue.model_validate(payload["catalogue"])
    plan = AssessmentPlanVersion.model_validate(payload["plan"])
    crawl = config_from_env()
    owner, token = os.environ["SCOPELENS_BROWSER_OWNER"], os.environ["SCOPELENS_EGRESS_TOKEN"]
    _install_proxy_ca()
    ok = False
    with Bridge(os.environ["HTTP_PROXY"], token) as proxy:
        controller = Controller(crawl, proxy, owner)
        opened = False
        try:
            controller.command("open")
            opened = True
            with Crawler(crawl)._http() as http, sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    chromium_sandbox=True,
                    proxy={"server": proxy},
                    args=[
                        "--disable-quic",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                    ],
                )
                try:
                    result = collect_browser_assessments(
                        configuration,
                        catalogue,
                        plan,
                        browser,
                        AssessmentControlClient(http),
                        crawl,
                        emit,
                        owner=owner,
                        token=token,
                        cancelled=lambda: _cancelled,
                        max_exploration_actions=min(
                            int(os.environ.get("SCOPELENS_BROWSER_MAX_ACTIONS", "30")), 100
                        ),
                        max_actions=int(
                            os.environ.get("SCOPELENS_BROWSER_MAX_ACTIVE_ACTIONS", "500")
                        ),
                        action_admission=ReviewedCaptureAdmission(controller).capture,
                        max_requests=min(
                            int(os.environ.get("SCOPELENS_BROWSER_MAX_REQUESTS", "240")), 240
                        ),
                    )
                    emit("expanded_browser_summary", result)
                    ok = not _cancelled and result.get("complete") is True
                finally:
                    browser.close()
        except Exception as exc:  # noqa: BLE001 - preserve already emitted evidence
            emit("expansion_gap", {"reason": type(exc).__name__, "stage": "expanded_browser"})
        finally:
            if opened:
                with suppress(Exception):
                    controller.command("close")
            controller.http.close()
    print("SCOPELENS_RESULT " + json.dumps({"ok": ok, "body_bytes": 0}), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
