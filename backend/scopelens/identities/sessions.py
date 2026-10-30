"""Independent HTTP sessions. The factory must supply broker-bound clients.

This module deliberately cannot construct a network client. The owning execution service
binds each factory invocation to the scan, identity, broker token and common budget.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr

from scopelens.domain.identity import IdentityProfile, IdentityRequest
from scopelens.identities.probe import response_probe_value

_MISSING = object()


def pointer(document: Any, path: str) -> Any:
    if not path.startswith("/"):
        return _MISSING
    current = document
    try:
        for part in path[1:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            current = current[int(part)] if isinstance(current, list) else current[part]
        return current
    except (KeyError, IndexError, ValueError, TypeError):
        return _MISSING


def same_value(actual: Any, expected: Any) -> bool:
    """JSON booleans and numbers are distinct policy values."""
    return type(actual) is type(expected) and actual == expected


def response_value(response: httpx.Response, path: str) -> Any:
    try:
        return pointer(response.json(), path)
    except ValueError:
        return _MISSING


class SessionUnavailable(RuntimeError):
    pass


def transport_category(error):
    if isinstance(error, IdentityTransportError):
        return error.category
    return (
        "timeout"
        if isinstance(error, httpx.TimeoutException)
        else "proxy"
        if isinstance(error, httpx.ProxyError)
        else "connect"
        if isinstance(error, httpx.ConnectError)
        else "protocol"
        if isinstance(error, httpx.ProtocolError)
        else "decoding"
        if isinstance(error, httpx.DecodingError)
        else "http_transport"
    )


def transport_phase(error, response_status=None, phase=None):
    if isinstance(error, IdentityTransportError):
        return error.phase
    # Decoding can fail before Client.stream yields its Response. It still means
    # that a response body was received, even when no status was retained.
    if isinstance(error, httpx.DecodingError):
        return "response_body_decode"
    if phase is not None:
        return phase
    if response_status is not None:
        return "response_body"
    if isinstance(error, (httpx.WriteError, httpx.WriteTimeout)):
        return "request_send"
    if isinstance(error, httpx.PoolTimeout):
        return "connection_pool"
    # ConnectError includes TLS failures; ReadError can occur on headers or body.
    # Without a trace or returned Response, their exact phase is unavailable.
    return "unknown"


class _TransportProgress:
    """Retain fixed phase labels and an HTTP status, never trace payloads."""

    def __init__(self):
        self.phase = None
        self.response_status = None
        self.target_headers = False

    def trace(self, event, info):
        parts = event.split(".")
        if len(parts) != 3:
            return
        protocol, operation, state = parts
        phases = {
            "connect_tcp": "connect",
            "connect_unix_socket": "connect",
            "start_tls": "tls",
            "send_connection_init": "request_send",
            "send_request_headers": "request_send",
            "send_request_body": "request_send",
            "receive_response_headers": "response_headers",
            "receive_response": "response_headers",
            "receive_response_body": "response_body",
        }
        if operation in phases and state in {"started", "failed"}:
            self.phase = phases[operation]
        if operation == "send_request_headers" and state == "started":
            # A successful broker CONNECT is not the target's HTTP response.
            method = getattr(info.get("request"), "method", None)
            self.target_headers = method is not None and method not in {b"CONNECT", "CONNECT"}
        if self.target_headers and operation == "receive_response_headers" and state == "complete":
            value = info.get("return_value")
            index = 1 if protocol == "http11" else 0 if protocol == "http2" else None
            if index is not None and isinstance(value, tuple) and len(value) > index:
                status = value[index]
                if type(status) is int and 100 <= status <= 599:
                    self.response_status = status


class IdentityTransportError(httpx.HTTPError):
    """Fixed diagnostics without upstream exception text, headers or body."""

    def __init__(self, error, response_status, phase=None):
        self.category = transport_category(error)
        self.response_status = response_status
        self.phase = transport_phase(error, response_status, phase)
        super().__init__("identity transport unavailable")


class IdentitySessions:
    def __init__(
        self,
        profiles: tuple[IdentityProfile, ...],
        secret_resolver: Callable[[str], SecretStr],
        client_factory: Callable[[str], httpx.Client],
        *,
        cancelled: Callable[[], bool] = lambda: False,
        response_observer: Callable[[str, IdentityRequest, httpx.Response], None] | None = None,
    ):
        self.profiles = {p.id: p for p in profiles}
        if len(self.profiles) != len(profiles):
            raise ValueError("duplicate identity ids")
        self.secret_resolver = secret_resolver
        self.client_factory = client_factory
        self.cancelled = cancelled
        self.response_observer = response_observer
        self.clients: dict[str, httpx.Client] = {}
        self.initialized: set[str] = set()

    def client(self, identity_id: str) -> httpx.Client:
        if identity_id not in self.profiles:
            raise SessionUnavailable("unknown identity")
        if identity_id not in self.clients:
            client = self.client_factory(identity_id)
            if any(
                client is existing or client.cookies is existing.cookies
                for existing in self.clients.values()
            ):
                raise SessionUnavailable("identity client/cookie jar was reused")
            self.clients[identity_id] = client
        return self.clients[identity_id]

    def request(self, identity_id: str, request: IdentityRequest) -> httpx.Response:
        if self.cancelled():
            raise SessionUnavailable("assessment cancelled")
        profile = self.profiles.get(identity_id)
        if profile is None or (profile.expires_at and profile.expires_at <= datetime.now(UTC)):
            raise SessionUnavailable("identity unavailable or supplied session expired")

        def origin(url):
            parsed = urlsplit(url)
            return (
                parsed.scheme,
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
            )

        if profile.probe and origin(request.url) != origin(profile.probe.request.url):
            raise SessionUnavailable("identity credential origin mismatch")
        headers = {
            name: self.secret_resolver(ref).get_secret_value()
            for name, ref in profile.supplied_headers.items()
        }
        headers.update(
            {
                name: self.secret_resolver(ref).get_secret_value()
                for name, ref in request.secret_headers.items()
            }
        )
        # These bounded identity reads need exact decoded bytes, not compression.
        # Some legacy application filters advertise gzip but send an invalid body.
        # Explicit identity negotiation avoids that failure without replaying a read,
        # changing TLS policy or accepting an incomplete response as identity proof.
        headers = {
            name: value for name, value in headers.items() if name.lower() != "accept-encoding"
        }
        headers["Accept-Encoding"] = "identity"
        body = dict(request.json_body)
        body.update(
            {
                name: self.secret_resolver(ref).get_secret_value()
                for name, ref in request.secret_fields.items()
            }
        )
        # Never follow a login redirect and mistake its 200 response for access.
        kwargs = {"headers": headers, "follow_redirects": False}
        if body:
            kwargs["data" if request.body_encoding == "form" else "json"] = body
        progress = _TransportProgress()
        kwargs["extensions"] = {"trace": progress.trace}
        try:
            with self.client(identity_id).stream(request.method, request.url, **kwargs) as response:
                progress.response_status = response.status_code
                progress.phase = "response_body"
                chunks = []
                size = 0
                for chunk in response.iter_bytes():
                    if self.cancelled():
                        raise SessionUnavailable("assessment cancelled")
                    size += len(chunk)
                    if size > 1_048_576:
                        raise SessionUnavailable("identity response exceeds evidence cap")
                    chunks.append(chunk)
                result = httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    content=b"".join(chunks),
                    request=response.request,
                )
                if self.response_observer:
                    self.response_observer(identity_id, request, result)
                return result
        except httpx.HTTPError as error:
            raise IdentityTransportError(error, progress.response_status, progress.phase) from None

    def verify(self, identity_id: str, *, allow_login: bool = True) -> bool:
        profile = self.profiles.get(identity_id)
        if profile is None:
            raise SessionUnavailable("unknown identity")
        if profile.anonymous:
            self.client(identity_id)
            return True
        if identity_id not in self.initialized:
            if allow_login and profile.login:
                response = self.request(identity_id, profile.login.request)
                if response.status_code not in profile.login.success_statuses:
                    raise SessionUnavailable("login recipe failed")
            self.initialized.add(identity_id)
        probe = profile.probe
        assert probe is not None
        response = self.request(identity_id, probe.request)
        return (
            response.status_code == 200
            and response_probe_value(response, probe) == probe.expected_identity
        )

    def close(self):
        for client in self.clients.values():
            client.cookies.clear()
            client.close()
        self.clients.clear()
        self.initialized.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
