"""Role-separated Playwright contexts supplied by the trusted browser controller.

The controller creates contexts with mandatory proxy, route admission, bounded response
capture and service-worker restrictions before giving them to this class. This module never
launches browsers or imports state from another role. It never writes storage_state to disk.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from pydantic import SecretStr

from scopelens.domain.identity import IdentityProfile, IdentityRequest
from scopelens.identities.probe import html_content_type, parse_probe_document
from scopelens.identities.sessions import SessionUnavailable, pointer


class BrowserIdentitySessions:
    def __init__(
        self,
        profiles: tuple[IdentityProfile, ...],
        secret_resolver: Callable[[str], SecretStr],
        context_factory: Callable[[str], Any],
        *,
        cancelled: Callable[[], bool] = lambda: False,
        response_observer: Callable | None = None,
    ):
        self.profiles = {p.id: p for p in profiles}
        if len(self.profiles) != len(profiles):
            raise ValueError("duplicate identity ids")
        self.secret_resolver = secret_resolver
        self.context_factory = context_factory
        self.cancelled = cancelled
        self.response_observer = response_observer
        self.contexts: dict[str, Any] = {}
        self.initialized: set[str] = set()
        self.owners: dict[str, str] = {}

    def context(self, identity_id: str, *, action_owner: str):
        if identity_id not in self.profiles or not action_owner:
            raise SessionUnavailable("unknown identity or missing browser owner")
        if identity_id in self.owners and self.owners[identity_id] != action_owner:
            raise SessionUnavailable("browser identity already leased to another controller")
        if identity_id not in self.contexts:
            context = self.context_factory(identity_id)
            if any(context is existing for existing in self.contexts.values()):
                raise SessionUnavailable("browser context reused across identities")
            if context.cookies():
                context.close()
                raise SessionUnavailable("browser identity context must start with empty cookies")
            self.contexts[identity_id] = context
        self.owners[identity_id] = action_owner
        return self.contexts[identity_id]

    def request(self, identity_id: str, request: IdentityRequest, *, action_owner: str):
        profile = self.profiles[identity_id]
        if self.cancelled() or (profile.expires_at and profile.expires_at <= datetime.now(UTC)):
            raise SessionUnavailable("browser session expired or cancelled")
        if profile.probe:

            def origin(url):
                p = urlsplit(url)
                return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)

            if origin(request.url) != origin(profile.probe.request.url):
                raise SessionUnavailable("browser credential origin mismatch")
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
        body = dict(request.json_body)
        body.update(
            {
                name: self.secret_resolver(ref).get_secret_value()
                for name, ref in request.secret_fields.items()
            }
        )
        body_argument = (
            {"form" if request.body_encoding == "form" else "data": body} if body else {}
        )
        response = self.context(identity_id, action_owner=action_owner).request.fetch(
            request.url,
            method=request.method,
            headers=headers,
            **body_argument,
            max_redirects=0,
            max_retries=0,
            timeout=10_000,
        )
        try:
            content = response.body()
            if len(content) > 1_048_576:
                raise SessionUnavailable("browser identity response exceeds evidence cap")
            if (
                profile.probe
                and request == profile.probe.request
                and profile.probe.response_format == "html"
            ):
                value = (
                    parse_probe_document(profile.probe, content)
                    if html_content_type(response.headers.get("content-type", ""))
                    else None
                )
            else:
                try:
                    value = response.json()
                except ValueError:
                    value = None
            if self.response_observer:
                self.response_observer(identity_id, request, response.status, value)
            return response.status, value
        finally:
            response.dispose()

    def verify(self, identity_id: str, *, action_owner: str) -> bool:
        profile = self.profiles[identity_id]
        if profile.anonymous:
            self.context(identity_id, action_owner=action_owner)
            return True
        if identity_id not in self.initialized:
            if profile.login:
                status, _ = self.request(
                    identity_id, profile.login.request, action_owner=action_owner
                )
                if status not in profile.login.success_statuses:
                    raise SessionUnavailable("browser login recipe failed")
            self.initialized.add(identity_id)
        probe = profile.probe
        assert probe is not None
        status, value = self.request(identity_id, probe.request, action_owner=action_owner)
        return status == 200 and pointer(value, probe.identity_pointer) == probe.expected_identity

    def release(self, identity_id: str, *, action_owner: str):
        if self.owners.get(identity_id) != action_owner:
            raise SessionUnavailable("browser controller lease mismatch")
        context = self.contexts.pop(identity_id)
        try:
            context.clear_cookies()
        finally:
            context.close()
            self.owners.pop(identity_id, None)
            self.initialized.discard(identity_id)

    def close(self):
        for identity_id, owner in tuple(self.owners.items()):
            self.release(identity_id, action_owner=owner)
