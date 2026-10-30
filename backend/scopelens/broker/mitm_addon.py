"""mitmproxy addon: the mandatory forward proxy's enforcement point (Build Plan §5.3).

**This file may import the standard library and `mitmproxy`, and nothing else.** It runs
inside the proxy container, which has its own dependency set (see
`docs/OPEN_QUESTIONS.md` Q-9: mitmproxy cannot coexist with bcrypt 5.x). A contract test
enforces the restriction, because an accidental `import scopelens` here would fail at
container start with no obvious cause.

The addon holds no policy of its own. For every connection and request it asks the policy
service to decide, and obeys.

WHY THERE ARE FOUR HOOKS AND NOT ONE
====================================

An earlier version hooked only ``request``. That left a hole large enough to drive the
whole product through, and it was found in review rather than by the tests:

    mitmproxy connects upstream *eagerly* on CONNECT, and a tunnel whose bytes are
    neither TLS nor HTTP is passed through as raw TCP. The ``request`` hook never fires,
    so the broker was never consulted. A worker could reach anything the proxy could
    reach — including unauthenticated Redis and PostgreSQL on the control network.

The fix is layered, and each layer is necessary:

* ``http_connect`` — the outermost gate. The egress token must be present *on the CONNECT
  request*, because after that point the bytes are inside a tunnel. Host and port are
  authorized before any upstream socket exists.
* ``connection_strategy=lazy`` — makes "before any upstream socket exists" true. With the
  default ``eager`` strategy mitmproxy opens the upstream connection on CONNECT, so a
  decision at that point would already be too late.
* ``rawtcp=false`` — the mechanism that actually stops raw TCP. It prevents the raw-TCP
  layer from being selected as a protocol at all, so a tunnel carrying non-TLS bytes has
  nowhere to go but into the HTTP layer, which rejects it.
* ``tcp_start`` / ``udp_start`` — kill and log any raw flow that still appears. Measured
  behaviour, stated plainly: **``flow.kill()`` here did not prevent the relay** — with it
  in place and ``rawtcp`` at its default, the payload still reached the target. These
  hooks are kept as detection and as a second answer if a future configuration enables
  ``tcp_hosts``, but they are not what makes the boundary hold, and they are not claimed
  to be.
* ``request`` — unchanged in spirit: every inner HTTP request is still authorized
  individually, on its own method, path and budget.

Failure mode is **deny** at every layer. If the policy service is unreachable, slow, or
answers something unparseable, the connection is refused. A broker that fails open is not
a broker.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from mitmproxy import ctx, http, tcp, udp

#: Where the scan's egress token is carried, on a CONNECT and on an inner request alike.
#: A dedicated header rather than ``Proxy-Authorization`` where the client can set one,
#: so the token is never confused with real proxy auth.
TOKEN_HEADER = "x-scopelens-egress"
ZAP_TASK_HEADER = "x-scopelens-zap-task"
ZAP_DECISION_HEADER = "x-scopelens-zap-decision"
PROBE_HEADER = "x-scopelens-reviewed-probe"

#: The header a client *can* set on CONNECT without special support, because it is the
#: standard proxy credential: httpx sends it from the proxy URL's userinfo
#: (``http://<token>:@proxy:8080``). Accepting both is what lets the worker authenticate
#: on CONNECT at all — the custom header is only settable by clients like curl that
#: expose proxy headers explicitly.
PROXY_AUTH_HEADER = "proxy-authorization"

DEFAULT_POLICY_URL = "http://policy:8000"
POLICY_TIMEOUT_SECONDS = 5.0


def extract_token(headers: Any) -> str:
    """Pull the egress token out of either accepted header. Returns "" if absent.

    ``Proxy-Authorization: Basic base64(token:password)`` carries the token in the
    username position, with an empty password. Anything else is treated as absent rather
    than guessed at.
    """
    token = headers.get(TOKEN_HEADER, "")
    if token:
        return str(token)

    raw = headers.get(PROXY_AUTH_HEADER, "")
    if not raw or not str(raw).lower().startswith("basic "):
        return ""
    try:
        decoded = base64.b64decode(str(raw)[6:].strip()).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return ""
    # "token" or "token:" — the username is the token either way.
    return decoded.split(":", 1)[0]


def strip_credentials(headers: Any) -> None:
    """Remove both credential headers before anything is forwarded upstream.

    The token is the proxy's business. Leaving it on the request would hand a live
    capability to the target, and into any log the target can read.
    """
    for name in (TOKEN_HEADER, PROXY_AUTH_HEADER, ZAP_TASK_HEADER, PROBE_HEADER):
        if name in headers:
            del headers[name]


class PolicyClient:
    """Thin client for the policy service. Denies on every failure."""

    def __init__(self, base_url: str, timeout: float = POLICY_TIMEOUT_SECONDS) -> None:
        self._url = base_url.rstrip("/") + "/internal/broker/authorize"
        self._timeout = timeout

    def assessment(self, payload):
        return self._post(payload, self._url.removesuffix("authorize") + "assessment")

    def callback_dispatch(self, payload):
        return self._post(payload, self._url.removesuffix("authorize") + "callback-dispatch")

    def vision(self, payload):
        return self._post(payload, self._url.removesuffix("authorize") + "vision")

    def browser(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post(payload, self._url.removesuffix("authorize") + "browser")

    def alive(self, token):
        return self._post(
            {"egress_token": token, "owner": "proxy-liveness-check", "operation": "open"},
            self._url.removesuffix("authorize") + "alive",
        )

    def authorize(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post(payload, self._url)

    def zap_task(self, payload):
        return self._post(payload, self._url.removesuffix("authorize") + "zap-task/authorize")

    def zap_alive(self, signed):
        return self._post(signed, self._url.removesuffix("authorize") + "zap-task/alive")

    def _post(self, payload: dict[str, Any], url: str) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        # URL is a fixed internal address, never target- or user-supplied.
        request = urllib.request.Request(
            url,
            data=body,
            headers={"content-type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                if response.status != 200:
                    return _deny("policy_unavailable", f"policy service returned {response.status}")
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return _deny("policy_unavailable", f"policy service HTTP {exc.code}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return _deny("policy_unavailable", f"policy service unreachable: {exc}")
        except (ValueError, json.JSONDecodeError) as exc:
            return _deny("policy_malformed", f"policy response unparseable: {exc}")


def _deny(reason: str, detail: str) -> dict[str, Any]:
    return {"allowed": False, "reason": reason, "detail": detail}


class ScopeEnforcer:
    """Decides every connection and request, and blocks anything not explicitly allowed."""

    def __init__(self) -> None:
        self.client = PolicyClient(os.environ.get("SCOPELENS_POLICY_URL", DEFAULT_POLICY_URL))
        self.denied = 0
        self.allowed = 0
        self.killed_raw_flows = 0
        global_limit = int(os.environ.get("SCOPELENS_PROXY_MAX_IN_FLIGHT", "8"))
        if global_limit < 1:
            raise ValueError("SCOPELENS_PROXY_MAX_IN_FLIGHT must be >= 1")
        self.scope_max_in_flight = int(os.environ.get("SCOPELENS_SCOPE_MAX_IN_FLIGHT", "8"))
        if self.scope_max_in_flight < 1:
            raise ValueError("SCOPELENS_SCOPE_MAX_IN_FLIGHT must be >= 1")
        self.slots = asyncio.Semaphore(global_limit)
        self.scan_slots = {}
        self.pins = {}
        self.routes = {}
        self.pending = {}

    def configure(self, updated: set[str]) -> None:
        """Force the two options the containment depends on, whatever the launch flags say.

        Without them an *authorized* CONNECT relays non-HTTP bytes as raw TCP (measured on
        mitmproxy 12.1.2). Enforced here so a different entrypoint — or ``--set
        rawtcp=true`` — cannot reopen that path. The guard avoids re-entering ``configure``.
        """
        if ctx.options.rawtcp or ctx.options.connection_strategy != "lazy":
            ctx.options.update(rawtcp=False, connection_strategy="lazy")

    def running(self) -> None:
        ctx.log.info(
            "ScopeLens broker active: CONNECT, raw TCP/UDP and every inner request are "
            "admitted only by the policy service"
        )

    # --- Layer 1: the tunnel itself ------------------------------------------------

    async def http_connect(self, flow: http.HTTPFlow) -> None:
        """Authorize a CONNECT tunnel before any upstream socket is opened.

        This runs before mitmproxy decides whether the tunnel carries TLS, HTTP or
        arbitrary bytes, which is exactly why it is the right place: the decision does not
        depend on what the client is about to send.
        """
        if ZAP_TASK_HEADER in flow.request.headers or PROBE_HEADER in flow.request.headers:
            strip_credentials(flow.request.headers)
            self._block_connect(flow, "invalid_zap_task", "native task transport forbids CONNECT")
            return
        token = extract_token(flow.request.headers)
        if not token:
            self._block_connect(
                flow,
                "missing_egress_token",
                f"no {TOKEN_HEADER} or Proxy-Authorization on the CONNECT request",
            )
            return

        decision = await asyncio.to_thread(
            self.client.authorize,
            {
                "egress_token": token,
                "method": "CONNECT",
                "scheme": "https",
                "host": flow.request.host,
                "port": flow.request.port,
                # A tunnel has no path of its own. The empty path is inside every allowed
                # prefix, which is correct: path scope is enforced per inner request.
                "path": "/",
            },
        )
        if not decision.get("allowed"):
            self._block_connect(
                flow,
                str(decision.get("reason", "denied")),
                str(decision.get("detail", "")),
            )
            return

        await asyncio.sleep(float(decision.get("limits", {}).get("wait_seconds", 0)))
        if not (await asyncio.to_thread(self.client.alive, token)).get("allowed"):
            self._block_connect(flow, "revoked_egress_token", "scan no longer live")
            return
        if not self._pin(flow, decision):
            self._block_connect(
                flow, "pinned_destination_changed", "restart proxy after reviewing changed address"
            )
            return
        self.allowed += 1
        # Both credential headers are removed so they cannot cross into the tunnel. The
        # inner request carries its own token, which is checked on its own merits.
        strip_credentials(flow.request.headers)

    def _block_connect(self, flow: http.HTTPFlow, reason: str, detail: str) -> None:
        self.denied += 1
        ctx.log.error(f"broker denied CONNECT {flow.request.host}: {reason}")
        flow.response = http.Response.make(
            403,
            json.dumps({"error": "scope_denied", "reason": reason, "detail": detail}).encode(),
            {"content-type": "application/json"},
        )

    # --- Layer 3: raw tunnels are never legitimate ---------------------------------

    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        """Kill a raw TCP tunnel.

        Reached only when a CONNECT was authorized and the payload then turned out to be
        neither TLS nor HTTP — which for a web assessment means either a bug or an
        attempt to use the proxy as a generic TCP relay. Both are answered the same way.
        """
        self.killed_raw_flows += 1
        ctx.log.warn(f"killing raw TCP flow to {flow.server_conn.address}: not a web protocol")
        flow.kill()

    def udp_start(self, flow: udp.UDPFlow) -> None:
        """Kill a UDP flow. UDP is not a web-assessment protocol and is never forwarded."""
        self.killed_raw_flows += 1
        ctx.log.warn(f"killing UDP flow to {flow.server_conn.address}")
        flow.kill()

    # --- Layer 4: every inner request ----------------------------------------------

    async def request(self, flow: http.HTTPFlow) -> None:
        # Internal browser/model commands have their own deadlines and never forward.
        if flow.request.host == "scopelens-broker.invalid":
            await self._request(flow)
            return
        self.pending[flow.id] = flow
        task = asyncio.current_task()
        flow.metadata["scopelens_request_task"] = task
        try:
            # Admission waiting is not upstream response time. A cancelled mitmproxy
            # request hook can otherwise strand queued parser assets indefinitely.
            await asyncio.wait_for(self._request(flow), timeout=120.0)
        except TimeoutError:
            flow.response = http.Response.make(
                504, b"broker admission deadline exceeded", {"content-type": "text/plain"}
            )
            self._release(flow)
        except asyncio.CancelledError:
            flow.response = http.Response.make(
                503, b"broker request cancelled", {"content-type": "text/plain"}
            )
            self._release(flow)
        except BaseException:
            self._release(flow)
            raise

    def _expire(self, flow):
        task = flow.metadata.get("scopelens_request_task")
        if task is not None and not task.done():
            task.cancel()
        if flow.killable:
            flow.kill()
        self._release(flow)

    def client_disconnected(self, client):
        for flow in list(self.pending.values()):
            if flow.client_conn.id == client.id:
                self._expire(flow)
        for key in list(self.pins):
            if key[0] == client.id:
                del self.pins[key]
        for key in list(self.routes):
            if key[0] == client.id:
                del self.routes[key]

    async def _request(self, flow: http.HTTPFlow) -> None:
        """Authorize one inner HTTP request on its own method, path and budget."""
        token = extract_token(flow.request.headers)
        raw_task = flow.request.headers.get(ZAP_TASK_HEADER)
        if raw_task is not None:
            flow.metadata["scopelens_native_request"] = True
        probe_task = flow.request.headers.get(PROBE_HEADER)
        if probe_task is not None and (
            not probe_task or len(probe_task) > 128 or raw_task is not None
        ):
            strip_credentials(flow.request.headers)
            self._block(flow, "invalid_probe_task", "invalid or conflicting task accounting header")
            return
        signed_task = None
        if raw_task is not None:
            try:
                if len(raw_task) > 16384:
                    raise ValueError("oversize task header")
                signed_task = json.loads(base64.b64decode(raw_task, validate=True))
                if not isinstance(signed_task, dict) or flow.request.scheme not in {
                    "http",
                    "https",
                }:
                    raise ValueError("HTTP(S)-only signed task transport")
                if flow.request.headers.get("authorization") or flow.request.headers.get("cookie"):
                    raise ValueError("anonymous task transport only")
            except (ValueError, TypeError):
                strip_credentials(flow.request.headers)
                self._block(flow, "invalid_zap_task", "malformed or unsupported task transport")
                return
        if not token:
            self._block(flow, "missing_egress_token", "no egress token on the request")
            return

        # A fixed local control endpoint. Never forward this hostname upstream.
        if flow.request.host == "scopelens-broker.invalid":
            if signed_task is not None or probe_task is not None:
                strip_credentials(flow.request.headers)
                self._block(flow, "invalid_zap_task", "task cannot invoke control commands")
                return
            if (
                flow.request.method != "POST"
                or flow.request.path not in {"/browser", "/vision", "/assessment"}
                or len(flow.request.content or b"")
                > (550000 if flow.request.path == "/vision" else 16384)
            ):
                self._block(flow, "invalid_browser_command", "invalid browser control request")
                return
            try:
                payload = json.loads(flow.request.content)
                payload["egress_token"] = token
                if flow.request.path == "/vision":
                    client = PolicyClient(
                        os.environ.get("SCOPELENS_POLICY_URL", DEFAULT_POLICY_URL), timeout=25
                    )
                    decision = await asyncio.to_thread(client.vision, payload)
                elif flow.request.path == "/assessment":
                    decision = await asyncio.to_thread(self.client.assessment, payload)
                else:
                    decision = await asyncio.to_thread(self.client.browser, payload)
            except (ValueError, TypeError):
                decision = _deny("invalid_browser_command", "malformed JSON")
            flow.response = http.Response.make(
                200, json.dumps(decision).encode(), {"content-type": "application/json"}
            )
            return

        try:
            authority = urllib.parse.urlsplit(
                flow.request.scheme + "://" + (flow.request.host_header or "")
            )
            authority_matches = (
                authority.hostname == flow.request.host.lower()
                and (authority.port or (443 if flow.request.scheme == "https" else 80))
                == flow.request.port
                and authority.username is None
                and not authority.path
                and not authority.query
                and not authority.fragment
            )
        except ValueError:
            authority_matches = False
        if not authority_matches:
            self._block(
                flow, "authority_mismatch", "HTTP authority differs from scoped destination"
            )
            return

        await self.slots.acquire()
        flow.metadata["scopelens_slot"] = True
        # The token is the proxy's business, not the target's.
        strip_credentials(flow.request.headers)

        task_started = time.monotonic()
        request_fields = {
            "egress_token": token,
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": flow.request.host,
            "port": flow.request.port,
            "path": flow.request.path,
        }
        if signed_task is None:
            if probe_task is not None:
                request_fields["probe_task"] = probe_task
            decision = await asyncio.to_thread(self.client.authorize, request_fields)
        else:
            decision = await asyncio.to_thread(
                self.client.zap_task,
                {
                    "signed": signed_task,
                    "egress_token": token,
                    "method": flow.request.method,
                    "url": flow.request.pretty_url,
                    "body_sha256": hashlib.sha256(flow.request.content or b"").hexdigest(),
                },
            )
        if not decision.get("allowed"):
            self._block(
                flow,
                str(decision.get("reason", "denied")),
                str(decision.get("detail", "")),
            )
            return

        limits = decision.get("limits", {})
        try:
            # Policy has already applied the scope override and its configured ceiling.
            # The isolated proxy applies the same deployment ceiling independently.
            scan_limit = min(self.scope_max_in_flight, int(limits.get("max_in_flight", 2)))
            if scan_limit < 1:
                raise ValueError("nonpositive concurrency")
        except (TypeError, ValueError):
            self._block(flow, "policy_malformed", "invalid max_in_flight limit")
            return
        scoped = self.scan_slots.setdefault(token, asyncio.Semaphore(scan_limit))
        await scoped.acquire()
        flow.metadata["scopelens_scan_slot"] = scoped
        await asyncio.sleep(float(limits.get("wait_seconds", 0)))
        if not (await asyncio.to_thread(self.client.alive, token)).get("allowed"):
            self._block(flow, "revoked_egress_token", "scan no longer live")
            return
        if signed_task is not None and not (
            await asyncio.to_thread(self.client.zap_alive, signed_task)
        ).get("allowed"):
            self._block(flow, "revoked_zap_task", "task closed, expired or cancelled")
            return
        flow.metadata["scopelens_body_cap"] = min(
            1048576, int(limits.get("max_response_bytes", 1048576))
        )
        flow.metadata["scopelens_token"] = token
        if signed_task is not None:
            flow.metadata["scopelens_zap_task"] = signed_task
        remaining = (
            10.0
            if signed_task is None
            else min(
                10.0,
                float(limits.get("task_remaining_seconds", "0"))
                - (time.monotonic() - task_started),
            )
        )
        if remaining <= 0:
            self._block(flow, "expired_zap_task", "task deadline exhausted before transmission")
            return
        flow.metadata["scopelens_deadline"] = asyncio.get_running_loop().call_later(
            remaining, self._expire, flow
        )
        if not self._pin(flow, decision):
            self._block(flow, "pinned_destination_changed", "missing or changed approved address")
            return
        host, port = flow.request.host, flow.request.port
        approved = self.pins[(flow.client_conn.id, host, port)]
        key = (flow.client_conn.id, approved, port)
        if self.routes.get(key, host) != host:
            self._block(flow, "virtual_host_changed", "one upstream identity per pinned connection")
            return
        self.routes[key] = host
        if limits.get("callback_capture") == "1":
            captured = await asyncio.to_thread(
                self.client.callback_dispatch,
                {
                    "operation": "begin",
                    "egress_token": token,
                    "method": flow.request.method,
                    "url": flow.request.url,
                    "body_sha256": hashlib.sha256(flow.request.raw_content or b"").hexdigest(),
                },
            )
            if not captured.get("allowed"):
                self._block(flow, "callback_capture_unavailable", "trusted capture unavailable")
                return
            if captured.get("dispatch_id"):
                flow.metadata["scopelens_callback_dispatch"] = captured["dispatch_id"]
        # GetHttpConnection keys its pool by request.host. Rewriting only at the
        # socket hook leaves five live, unmatchable connections and stalls request
        # six. Use the approved IP as the routing key, preserving HTTP Host and SNI.
        flow.metadata["scopelens_original_host"] = host
        host_header = flow.request.host_header
        flow.request.host = approved
        flow.request.host_header = host_header
        self.allowed += 1
        if flow.metadata.get("scopelens_native_request"):
            flow.metadata["scopelens_native_decision"] = "allow"
        # The address the policy service validated, recorded on the flow for evidence.
        # No marker header is added to the request: the authoritative record of admission
        # is the broker's own audit row, and a header would only reach the target.
        flow.metadata["scopelens_addresses"] = decision.get("addresses", [])

    def _pin(self, flow, decision):
        addresses = decision.get("addresses", [])
        if not addresses:
            return False
        key = (flow.client_conn.id, flow.request.host, flow.request.port)
        previous = self.pins.get(key)
        if previous and previous not in addresses:
            return False
        self.pins[key] = previous or addresses[0]
        return True

    def server_connect(self, data):
        # GetHttpConnection selects its own connection after the request hook. Pin at
        # the actual socket boundary, preserving the original HTTP Host and TLS SNI.
        address = data.server.address
        host = self.routes.get((data.client.id, *address))
        if host is None:
            data.server.error = "No approved upstream destination"
            return
        data.server.sni = host

    def responseheaders(self, flow):
        # Only the trusted proxy may stamp this verdict; upstream values are discarded.
        flow.response.headers.pop(ZAP_DECISION_HEADER, None)
        if flow.metadata.get("scopelens_native_request"):
            flow.response.headers[ZAP_DECISION_HEADER] = flow.metadata.get(
                "scopelens_native_decision", "unknown"
            )
        if "scopelens_token" not in flow.metadata:
            return
        if dispatch_id := flow.metadata.pop("scopelens_callback_dispatch", None):
            captured = self.client.callback_dispatch(
                {
                    "operation": "complete",
                    "egress_token": flow.metadata["scopelens_token"],
                    "dispatch_id": dispatch_id,
                    "response_status": flow.response.status_code,
                }
            )
            if not captured.get("allowed"):
                # No completed trusted record means the callback evaluator cannot
                # credit this request, even if a worker reports a successful status.
                flow.kill()
                self._release(flow)
                return
        cap = flow.metadata["scopelens_body_cap"]
        received = 0

        def bounded(chunk):
            nonlocal received
            received += len(chunk)
            task = flow.metadata.get("scopelens_zap_task")
            if (
                received > cap
                or not self.client.alive(flow.metadata["scopelens_token"]).get("allowed")
                or (task is not None and not self.client.zap_alive(task).get("allowed"))
            ):
                flow.kill()
                self._release(flow)
                return b""
            return chunk

        flow.response.stream = bounded

    def _release(self, flow):
        self.pending.pop(flow.id, None)
        deadline = flow.metadata.pop("scopelens_deadline", None)
        if deadline is not None:
            deadline.cancel()
        flow.metadata.pop("scopelens_request_task", None)
        if flow.metadata.pop("scopelens_slot", False):
            self.slots.release()
        scoped = flow.metadata.pop("scopelens_scan_slot", None)
        if scoped is not None:
            scoped.release()

    def response(self, flow):
        self._restore_host(flow)
        self._release(flow)

    def error(self, flow):
        self._restore_host(flow)
        self._release(flow)

    def _restore_host(self, flow):
        host = flow.metadata.pop("scopelens_original_host", None)
        if host is not None:
            host_header = flow.request.host_header
            flow.request.host = host
            flow.request.host_header = host_header

    def _block(self, flow: http.HTTPFlow, reason: str, detail: str) -> None:
        self._release(flow)
        self.denied += 1
        # Logged without the token, the full URL, or any request body.
        ctx.log.error(f"broker denied {flow.request.method} {flow.request.host}: {reason}")
        native = flow.metadata.get("scopelens_native_request")
        if native:
            flow.metadata["scopelens_native_decision"] = "deny"
        flow.response = http.Response.make(
            403,
            json.dumps({"error": "scope_denied", "reason": reason, "detail": detail}).encode(),
            {
                "content-type": "application/json",
                **({ZAP_DECISION_HEADER: "deny"} if native else {}),
            },
        )


def _build() -> ScopeEnforcer:
    return ScopeEnforcer()


addons = [_build()]


if __name__ == "__main__":  # pragma: no cover - manual invocation only
    print("This module is loaded by mitmdump via -s, not run directly.", file=sys.stderr)
    raise SystemExit(2)
