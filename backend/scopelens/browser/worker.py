"""Reviewed bounded Playwright explorer. No model or target supplied code is executed.

Page JavaScript runs inside Chromium's enabled browser sandbox. Controller JavaScript is
fixed instrumentation for DOM discovery. HTTP and action traffic use the policy broker.
"""

import base64
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

from scopelens.broker.probe_tasks import PROBE_HEADER
from scopelens.browser.bridge import Bridge
from scopelens.browser.policy import UNSAFE, BrowserAction, action_reason
from scopelens.checks.crawl import KEPT_HEADERS, CrawlConfig, config_from_env
from scopelens.domain.collection import CollectedResponse
from scopelens.security.redaction import redact_text

ARTIFACT = "SCOPELENS_ARTIFACT "
RESULT = "SCOPELENS_RESULT "


class ActionDenied(RuntimeError):
    pass


class Controller:
    def __init__(self, config: CrawlConfig, proxy: str, owner: str):
        self.config = config
        self.owner = owner
        self.sequence = 0
        self.events = []
        self.responses = []
        self.gaps = []
        self.states = []
        self.seen = set()
        self.visited_controls = set()
        self.request_templates = set()
        self.pending_requests = {}
        self.pending_request_count = 0
        self.http = httpx.Client(
            proxy=proxy,
            headers={"x-scopelens-egress": os.environ["SCOPELENS_EGRESS_TOKEN"]},
            timeout=10,
            trust_env=False,
        )

    def command(self, operation, **fields):
        payload = {"owner": self.owner, "operation": operation, "sequence": self.sequence, **fields}
        response = self.http.post("http://scopelens-broker.invalid/browser", json=payload)
        response.raise_for_status()
        decision = response.json()
        if not decision.get("allowed"):
            raise ActionDenied(decision.get("reason", "denied"))
        return decision

    def in_scope(self, url):
        u = urlsplit(url)
        origin = urlsplit(self.config.origin + "/")

        def port(x):
            return x.port or (443 if x.scheme == "https" else 80)

        path = u.path or "/"
        return (
            (u.scheme, u.hostname, port(u)) == (origin.scheme, origin.hostname, port(origin))
            and any(path.startswith(p) for p in self.config.allowed_path_prefixes)
            and not any(path.startswith(p) for p in self.config.excluded_paths)
        )

    def route(self, route):
        request = route.request
        self.capture_request_intent(request)
        if (
            not self.in_scope(request.url)
            or request.method not in {"GET", "HEAD"}
            or UNSAFE.search(urlsplit(request.url).path)
        ):
            self.gaps.append(
                {"url": redact_text(request.url), "reason": "scope_or_side_effect_guard"}
            )
            route.abort()
            return
        headers = {k: v for k, v in request.headers.items() if k.lower() != PROBE_HEADER}
        probe = getattr(self, "probe_request", None)
        if probe and request.url == probe[0]:
            headers[PROBE_HEADER] = probe[1]
            self.probe_request = None
        headers["x-scopelens-egress"] = os.environ["SCOPELENS_EGRESS_TOKEN"]
        route.continue_(headers=headers)

    def request_started(self, request):
        """Keep bounded transport metadata, never request headers or request bodies."""
        if self.in_scope(request.url):
            self.pending_request_count += 1
            if len(self.pending_requests) < 500:
                self.pending_requests[request] = time.monotonic()

    def request_completed(self, request):
        self.pending_requests.pop(request, None)
        if self.in_scope(request.url):
            self.pending_request_count = max(0, self.pending_request_count - 1)

    def request_finished(self, request):
        self.request_completed(request)
        captured = self.capture_response(request.response())
        watched = getattr(self, "settling_requests", {})
        if request in watched:
            watched[request] = bool(captured)

    def request_failed(self, request):
        self.request_completed(request)
        watched = getattr(self, "settling_requests", {})
        if request in watched:
            watched[request] = False
        self.gaps.append({"url": redact_text(request.url), "reason": "request_failed"})

    def pending_transport(self):
        """Distinguish an uncompleted asset transfer from a missing readiness event.

        Admission and a response-start event do not establish a complete response.
        These records describe pending transfers only and never count as captures.
        Retain at most 500 request objects and 20 descriptions in a gap artifact.
        """
        pending = getattr(self, "pending_requests", {})
        now = time.monotonic()
        return {
            "pending_request_count": getattr(self, "pending_request_count", len(pending)),
            "pending_metadata_limited": getattr(self, "pending_request_count", len(pending))
            > min(20, len(pending)),
            "pending_requests": [
                {
                    "url": redact_text(request.url),
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "pending_seconds": round(max(0, now - started), 1),
                }
                for request, started in list(pending.items())[:20]
            ],
        }

    def capture_request_intent(self, request):
        """Describe in-scope requests even when their method is denied by exploration."""
        from scopelens.browser.discovery import request_templates

        if not self.in_scope(request.url):
            return
        if len(self.request_templates) >= 500:
            if not getattr(self, "request_template_cap_reported", False):
                self.gaps.append({"reason": "browser_request_template_limit"})
                self.request_template_cap_reported = True
            return
        try:
            for template in request_templates(
                self.config.origin,
                url=request.url,
                method=request.method,
                headers=request.all_headers(),
                post_data=request.post_data,
            ):
                if template.id in self.request_templates:
                    continue
                self.request_templates.add(template.id)
                print(
                    ARTIFACT
                    + json.dumps(
                        {
                            "kind": "browser_request_template",
                            "data": {
                                "template": template.model_dump(mode="json"),
                                "state": "observed_intent",
                            },
                        }
                    ),
                    flush=True,
                )
        except (ValueError, TypeError, RecursionError, PlaywrightError):
            # Exception strings may contain the original body or authentication values.
            self.gaps.append({"reason": "browser_request_metadata_unavailable"})

    def capture_response(self, response):
        if response is None or getattr(self, "active_probe", False):
            return
        try:
            if not self.in_scope(response.url):
                return
            # Broker caps transfer; controller caps the retained excerpt independently.
            # Chromium intentionally does not retain redirect bodies. Their status
            # and Location header are still valid captured evidence.
            body = b"" if response.status in {301, 302, 303, 307, 308} else response.body()
            # Header RPCs can yield to the next navigation, which evicts Chromium's
            # body buffer. Retain the finished body before those metadata calls.
            values = response.headers_array()
            headers = {
                k.lower(): v for k, v in response.all_headers().items() if k.lower() in KEPT_HEADERS
            }
            if response.status == 403:
                try:
                    refusal = json.loads(body)
                except (ValueError, UnicodeDecodeError):
                    refusal = None
                if isinstance(refusal, dict) and refusal.get("error") == "scope_denied":
                    self.gaps.append({"url": redact_text(response.url), "reason": "broker_denied"})
                    return
            cap = self.config.max_body_bytes
            record = CollectedResponse(
                url=response.url,
                route=urlsplit(response.url).path or "/",
                status=response.status,
                headers=headers,
                header_values={
                    k: tuple(h["value"] for h in values if h["name"].lower() == k) for k in headers
                },
                content_type=headers.get("content-type"),
                body_excerpt=body[:cap].decode("utf-8", "replace")
                if any(
                    t in headers.get("content-type", "")
                    for t in ["text/", "json", "javascript", "xml"]
                )
                else "",
                body_bytes=len(body),
                truncated=len(body) > cap,
                set_cookie=tuple(h["value"] for h in values if h["name"].lower() == "set-cookie"),
                via_proxy=True,
            )
            self.responses.append(record.model_dump(mode="json"))
            print(
                ARTIFACT + json.dumps({"kind": "response", "data": self.responses[-1]}), flush=True
            )
            return 200 <= record.status < 300 and not record.truncated
        except PlaywrightError as exc:
            self.gaps.append(
                {
                    "url": redact_text(response.url),
                    "reason": "response_capture_failed",
                    "detail": redact_text(str(exc))[:300],
                }
            )

    def state(self, page):
        raw_text = page.locator("body").inner_text(timeout=3000)
        text = redact_text(raw_text)[:32000]
        dom = redact_text(page.locator("body").aria_snapshot(timeout=3000))[:32000]
        signature = hashlib.sha256((page.url + "\n" + text + "\n" + dom).encode()).hexdigest()
        shot = page.screenshot(
            type="jpeg",
            quality=35,
            full_page=False,
            mask=[
                page.locator(
                    "body"
                    if redact_text(raw_text) != raw_text
                    else "input,textarea,[contenteditable=true]"
                )
            ],
        )
        record = {
            "state_hash": signature,
            "url": redact_text(page.url),
            "context_id": self.context_id,
            "role": "unauthenticated",
            "page_id": "main",
            "frame_ids": [f"frame-{i}" for i, _ in enumerate(page.frames)],
            "frame_urls": [redact_text(f.url) for f in page.frames],
            "dom": dom,
            "text": text,
            "screenshot_jpeg": base64.b64encode(shot).decode(),
            "masked": "input fields; unauthenticated lab capture",
        }
        self.states.append(record)
        print(ARTIFACT + json.dumps({"kind": "browser_state", "data": record}), flush=True)
        return signature

    def act(self, page, action, perform):
        sequence = self.sequence + 1
        self.command("admit", sequence=sequence, action=action.model_dump())
        self.sequence = sequence
        before = action.state_hash
        result = "failed"
        after = ""
        try:
            perform()
            try:
                # A committed response is not a parsed document. Rate-limited classic
                # scripts can keep the parser in <head> beyond the old 10s idle wait.
                page.wait_for_load_state("domcontentloaded", timeout=30000)
            except PlaywrightTimeout:
                self.gaps.append(
                    {
                        "url": redact_text(page.url),
                        "reason": "document_ready_timeout",
                        **self.pending_transport(),
                    }
                )
            try:
                # Give SPA updates a bounded settling interval without requiring
                # analytics/long polling to become idle before capturing a usable DOM.
                page.wait_for_load_state("networkidle", timeout=1500)
            except PlaywrightTimeout:
                if not self.settle_static_assets(page):
                    self.gaps.append(
                        {
                            "url": redact_text(page.url),
                            "reason": "background_requests_pending",
                            **self.pending_transport(),
                        }
                    )
            after = self.state(page)
            result = "succeeded"
            return after
        finally:
            self.command("complete", before_hash=before, after_hash=after, result=result)

    def settle_static_assets(self, page):
        """Briefly await known image/font transfers, never excuse unknown busy work."""
        pending = getattr(self, "pending_requests", {})
        count = getattr(self, "pending_request_count", 0)
        if (
            not count
            or count != len(pending)
            or any(request.resource_type not in {"image", "font"} for request in pending)
        ):
            return False
        # Track exact request objects, so a failed transfer or URL collision cannot
        # masquerade as the successful response of another request.
        self.settling_requests = dict.fromkeys(pending)
        try:
            deadline = time.monotonic() + min(5.0, self.config.timeout)
            while (
                self.pending_request_count
                or any(v is None for v in self.settling_requests.values())
            ) and time.monotonic() < deadline:
                if any(v is False for v in self.settling_requests.values()):
                    return False
                pending = self.pending_requests
                if self.pending_request_count != len(pending) or any(
                    request.resource_type not in {"image", "font"} for request in pending
                ):
                    return False
                page.wait_for_timeout(min(50, max(1, (deadline - time.monotonic()) * 1000)))
            remaining = deadline - time.monotonic()
            if (
                self.pending_request_count
                or remaining <= 0
                or not all(self.settling_requests.values())
            ):
                return False
            try:
                page.wait_for_load_state("networkidle", timeout=min(1000, remaining * 1000))
            except PlaywrightTimeout:
                return False
            return self.pending_request_count == 0
        finally:
            self.settling_requests = {}

    def search_form(self, page, current):
        for form in page.locator("form").all()[:20]:
            method = (form.get_attribute("method") or "GET").upper()
            url = urljoin(page.url, form.get_attribute("action") or page.url)
            field = form.locator("input[type=search],input[name=q],input[name=search]").first
            key = (url, "search-form")
            if key in self.visited_controls or method != "GET" or not field.count():
                continue
            if not field.is_visible() or not self.in_scope(url):
                continue
            self.visited_controls.add(key)
            action = BrowserAction(
                kind="type",
                url=url,
                label="Search",
                form_method=method,
                value="scopelens",
                state_hash=current,
            )
            if action_reason(action):
                continue
            current = self.act(page, action, lambda field=field: field.fill("scopelens"))
            action = action.model_copy(update={"kind": "submit", "state_hash": current})
            return self.act(page, action, lambda field=field: field.press("Enter"))
        return None

    def vision_fallback(self, page, current):
        if (page.url, "vision") in self.visited_controls:
            return None
        self.visited_controls.add((page.url, "vision"))
        response = self.http.post(
            "http://scopelens-broker.invalid/vision",
            json={
                "owner": self.owner,
                "screenshot": self.states[-1]["screenshot_jpeg"],
                "dom": self.states[-1]["dom"],
            },
        )
        suggestion = response.json()
        if not suggestion.get("allowed"):
            return None
        point = suggestion["point"]
        # Validate the actual DOM element under the model's coordinates. A model label
        # does not grant authority to an unrelated button or canvas action.
        label = page.evaluate(
            """({x,y}) => {
          const e = document.elementFromPoint(x,y)?.closest('button,[role=button],[role=tab],summary');
          return e && !e.closest('form') ? (e.getAttribute('aria-label') || e.innerText) : '';
        }""",
            point,
        )
        action = BrowserAction(
            kind="coordinate",
            url=page.url,
            label=label or "",
            x=point["x"],
            y=point["y"],
            state_hash=current,
        )
        if action_reason(action, vision_enabled=True):
            return None
        return self.act(page, action, lambda: page.mouse.click(point["x"], point["y"]))

    def explore(self, page):
        entry = self.config.entry_url()
        self.context_id = self.command("open")["context_id"]
        current = self.act(
            page,
            BrowserAction(kind="navigate", url=entry),
            lambda: page.goto(entry, wait_until="commit"),
        )
        max_states = int(os.environ.get("SCOPELENS_BROWSER_MAX_STATES", "12"))
        max_actions = int(os.environ.get("SCOPELENS_BROWSER_MAX_ACTIONS", "24"))
        frontier = []
        visited_urls = {entry}
        depths = {entry: 0}
        while self.sequence < max_actions and len(self.seen) < max_states:
            self.seen.add(current)
            if self.sequence + 2 <= max_actions:
                searched = self.search_form(page, current)
                if searched:
                    current = searched
                    continue
            for link in page.locator("a[href]").all()[:100]:
                href = link.get_attribute("href")
                url = urljoin(page.url, href or "")
                depth = depths.get(page.url, 0) + 1
                if (
                    self.in_scope(url)
                    and url not in visited_urls
                    and not UNSAFE.search(url)
                    and depth <= self.config.max_depth
                ):
                    frontier.append(url)
                    visited_urls.add(url)
                    depths[url] = depth
            candidates = page.locator("button,[role=button],[role=tab],summary").all()
            selected = None
            for element in candidates[:100]:
                try:
                    if not element.is_visible():
                        continue
                    if element.evaluate("e => !!e.closest('form')"):
                        continue
                    label = (element.get_attribute("aria-label") or element.inner_text()).strip()[
                        :1000
                    ]
                    href = element.get_attribute("href")
                    url = urljoin(page.url, href) if href else page.url
                    key = (urlsplit(page.url).path, label, urlsplit(url).path)
                    if key in self.visited_controls:
                        continue
                    self.visited_controls.add(key)
                    kind = "navigate" if href else "click"
                    action = BrowserAction(kind=kind, url=url, label=label, state_hash=current)
                    if not self.in_scope(url) or action_reason(action):
                        continue
                    selected = (element, action)
                    break
                except PlaywrightError:
                    continue
            if selected is None:
                if not frontier:
                    interpreted = self.vision_fallback(page, current)
                    if interpreted:
                        current = interpreted
                        continue
                    break
                destination = frontier.pop(0)
                action = BrowserAction(kind="navigate", url=destination, state_hash=current)
                try:
                    current = self.act(
                        page,
                        action,
                        lambda destination=destination: page.goto(destination, wait_until="commit"),
                    )
                except PlaywrightError:
                    self.gaps.append(
                        {"url": redact_text(destination), "reason": "navigation_failed"}
                    )
                continue
            element, action = selected
            try:
                current = self.act(
                    page, action, lambda element=element: element.click(timeout=3000)
                )
            except (PlaywrightError, ActionDenied) as exc:
                self.gaps.append({"reason": type(exc).__name__, "url": redact_text(page.url)})
                if isinstance(exc, ActionDenied):
                    break
        if self.sequence >= max_actions or len(self.seen) >= max_states:
            self.gaps.append({"reason": "browser_state_or_action_cap"})
        from scopelens.browser.active import collect

        collect(self, page, current)
        self.command("close")


def main():
    config = config_from_env()
    owner = os.environ["SCOPELENS_BROWSER_OWNER"]
    browser_home = Path("/tmp/browser-home")
    db = browser_home / ".pki/nssdb"
    db.mkdir(parents=True, exist_ok=True)
    ca = browser_home / "proxy.pem"
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
    started = time.monotonic()
    ok = False
    with Bridge(os.environ["HTTP_PROXY"], os.environ["SCOPELENS_EGRESS_TOKEN"]) as proxy:
        controller = Controller(config, proxy, owner)
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    chromium_sandbox=True,
                    proxy={"server": proxy},
                    args=[
                        "--disable-quic",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                    ],
                )
                context = browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    service_workers="block",
                    accept_downloads=False,
                )
                context.route("**/*", controller.route)
                context.route_web_socket("**/*", lambda ws: ws.close())
                page = context.new_page()
                page.set_default_timeout(5000)
                page.set_default_navigation_timeout(15000)
                page.on("request", controller.request_started)
                page.on("requestfinished", controller.request_finished)
                page.on("requestfailed", controller.request_failed)
                page.on("dialog", lambda dialog: dialog.dismiss())
                page.on("popup", lambda popup: popup.close())
                page.on("download", lambda download: download.cancel())
                controller.explore(page)
                context.close()
                browser.close()
                ok = True
        except Exception as exc:  # noqa: BLE001 - preserve partial browser evidence
            controller.gaps.append(
                {"reason": type(exc).__name__, "detail": redact_text(str(exc))[:1500]}
            )
        finally:
            print(
                ARTIFACT
                + json.dumps(
                    {
                        "kind": "browser_summary",
                        "data": {
                            "states": len(controller.states),
                            "actions": controller.sequence,
                            "gaps": controller.gaps,
                            "service_workers": "blocked",
                            "popups": "closed",
                            "downloads": "cancelled",
                            "websockets": "blocked",
                        },
                    }
                ),
                flush=True,
            )
            print(
                RESULT
                + json.dumps(
                    {
                        "ok": ok,
                        "body_bytes": sum(r["body_bytes"] for r in controller.responses),
                        "duration_seconds": time.monotonic() - started,
                    }
                ),
                flush=True,
            )
            controller.http.close()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
