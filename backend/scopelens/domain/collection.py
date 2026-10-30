"""Collected responses: the raw material the deterministic checks operate on.

Build Plan §5.8 defines config/exposure checks as *"pure functions over collected data +
broker/TLS-lane results"*. This module is that collected data. Keeping it a plain record
with no I/O is what makes every check testable without a network, and what lets the whole
scoring path be reproducible from a stored artifact.

Two things are deliberately narrow:

* **Headers are kept as a lowercased mapping.** Header names are case-insensitive, and a
  check that had to remember to lowercase would eventually forget.
* **Bodies are excerpts, not bodies.** Capped at capture, with ``truncated`` recording the
  fact. Spec §13 requires truncation to be disclosed because it can make a check
  inconclusive; a check that silently analysed half a page would be guessing.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CollectedResponse(BaseModel):
    """One HTTP exchange, as observed through the broker."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str
    route: str
    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    header_values: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    content_type: str | None = None
    body_excerpt: str = ""
    body_bytes: int = 0
    truncated: bool = False
    #: Every Set-Cookie header, in order. Kept separately because a mapping cannot hold
    #: repeated headers, and a response that sets three cookies would otherwise look like
    #: one — which is exactly the case a cookie-flag check must not miss.
    set_cookie: tuple[str, ...] = ()
    redirect_chain: tuple[str, ...] = ()
    elapsed_ms: int = 0
    #: True only when the response came back through the policy broker. A response the
    #: broker did not admit cannot be evidence, so this is checked rather than assumed.
    via_proxy: bool = False

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def has_header(self, name: str) -> bool:
        return name.lower() in self.headers

    @property
    def is_html(self) -> bool:
        return bool(self.content_type and "html" in self.content_type.lower())

    @property
    def is_javascript(self) -> bool:
        lowered = (self.content_type or "").lower()
        return "javascript" in lowered or "ecmascript" in lowered


class TLSMeasurement(BaseModel):
    """Facts from the constrained TLS lane (Build Plan §5.3).

    A separate record from ``CollectedResponse`` because it comes from a different lane: the
    proxy intercepts the assessment lane, so a certificate read through it would be the
    proxy's own. Anything describing the *real* upstream transport comes from here.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str
    port: int
    reachable: bool
    protocol_version: str | None = None
    cipher: str | None = None
    certificate_subject: dict[str, str] = Field(default_factory=dict)
    certificate_issuer: dict[str, str] = Field(default_factory=dict)
    not_before: str | None = None
    not_after: str | None = None
    serial_number: str | None = None
    subject_alt_names: tuple[str, ...] = ()
    self_signed: bool | None = None
    error: str | None = None
    measured_at: str | None = None
    certificate_verified: bool | None = None
    verification_error: str | None = None
    legacy_protocols: dict[str, str] = Field(default_factory=dict)

    @property
    def describes_a_certificate(self) -> bool:
        """Whether there is a certificate to make a claim about.

        An unreachable TLS lane is **not** a finding and **not** a pass — it is an
        unassessable transport, which Spec §9.7 keeps out of both.
        """
        return self.reachable and bool(self.not_after)


class CollectedData(BaseModel):
    """Everything the checks may read. Assembled once per scan, then read-only."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    origin: str
    scheme: str
    host: str
    port: int
    responses: tuple[CollectedResponse, ...] = ()
    tls: TLSMeasurement | None = None
    #: HTTP→HTTPS behaviour, when the scope authorized a cleartext origin for that purpose
    #: (Spec §12). None means the check was not run, which is unassessable rather than clean.
    cleartext_probe: CollectedResponse | None = None
    #: Routes the crawl could not reach, and why. Kept so a blocked route is visible as a
    #: coverage gap instead of quietly reducing the denominator.
    unreachable: dict[str, str] = Field(default_factory=dict)
    transport_http_authorized: bool = False

    def by_route(self, route: str) -> CollectedResponse | None:
        for response in self.responses:
            if response.route == route:
                return response
        return None

    def with_header(self, name: str) -> list[CollectedResponse]:
        return [r for r in self.responses if r.has_header(name)]

    def all_headers(self) -> dict[str, str]:
        """Union of headers across responses, first observation winning.

        Used by checks that ask "does the origin send this anywhere", where one response
        carrying it is the answer. A check that needs a *specific* response uses
        :meth:`by_route` instead.
        """
        merged: dict[str, str] = {}
        for response in self.responses:
            for key, value in response.headers.items():
                merged.setdefault(key, value)
        return merged

    @property
    def primary(self) -> CollectedResponse | None:
        """The origin's own root response, if the crawl reached it."""
        return self.by_route("/")


def headers_from(raw: dict[str, Any]) -> dict[str, str]:
    """Normalise a raw header mapping to lowercase string keys and values."""
    return {str(k).lower(): str(v) for k, v in raw.items()}
