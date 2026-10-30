"""Server and session-cookie configuration controls (category C02). Build Plan §5.8, ADD-02.

The judgement here is *purpose*, not attribute presence. Spec §9.8 warns against reporting
every unflagged cookie: a preference cookie with no ``Secure`` is not a weakness, and a check
that says it is trains its reader to ignore cookie findings. So the controls distinguish a
cookie that carries session or authentication state from one that does not, and say which
evidence produced that classification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from scopelens.checks.engine import CheckContext
from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as Outcome

CATEGORY = Category.C02_SERVER_SESSION

#: Cookie names that indicate session or authentication state. A name is *evidence of
#: purpose*, not proof, which is why the control reports the name it matched.
SESSION_NAME_PATTERN = re.compile(
    r"(sess|sid|auth|token|jwt|login|csrf|xsrf|remember|access|refresh|id)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CookieFact:
    """One parsed Set-Cookie header."""

    name: str
    attributes: dict[str, str]
    raw_length: int

    def has(self, attribute: str) -> bool:
        return attribute.lower() in self.attributes

    @property
    def is_session_shaped(self) -> bool:
        """Whether the name indicates session or authentication state.

        Names that are *only* an identifier word (`id`, `sid`) count. A cookie called
        `theme` does not, and is therefore not reported for missing flags.
        """
        return bool(SESSION_NAME_PATTERN.search(self.name))


def parse_set_cookie(header: str) -> CookieFact | None:
    """Parse a Set-Cookie header. Returns None when there is no cookie name.

    Attribute values are not retained — only their presence and, for the ones that carry
    meaning (``SameSite``, ``Domain``, ``Path``), their value. A cookie's *value* is never
    kept: Build Plan §6.1 requires it redacted, and the safest way to redact something is
    not to hold it.
    """
    parts = [part.strip() for part in header.split(";")]
    if not parts or not parts[0]:
        return None
    name, _, _value = parts[0].partition("=")
    name = name.strip()
    if not name:
        return None

    attributes: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, value = part.partition("=")
        attributes[key.strip().lower()] = value.strip()

    return CookieFact(name=name, attributes=attributes, raw_length=len(header))


def _session_cookies(ctx: CheckContext) -> list[tuple[str, str, CookieFact]]:
    """Every session-shaped cookie as ``(route, header, fact)``."""
    found: list[tuple[str, str, CookieFact]] = []
    for response in ctx.data.responses:
        for header in response.set_cookie:
            fact = parse_set_cookie(header)
            if fact is None or not fact.is_session_shaped:
                continue
            found.append((response.route, header, fact))
    return found


def evaluate_cookie_flags(ctx: CheckContext) -> ControlOutcome:
    """SL-C02-COOKIE-01 — session cookies carry Secure, HttpOnly and SameSite."""
    cookies = _session_cookies(ctx)
    if not cookies:
        return ControlOutcome(
            check_id="SL-C02-COOKIE-01",
            canonical_control="session.cookie.protective_flags",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary=(
                "no cookie whose name indicates session or authentication state was observed; "
                "an origin that sets cookies only on unvisited routes remains unassessed"
            ),
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for route, _header, fact in cookies:
        missing: list[str] = []
        if not fact.has("secure"):
            missing.append("Secure")
        if not fact.has("httponly"):
            missing.append("HttpOnly")
        if not fact.has("samesite"):
            missing.append("SameSite")
        elif fact.attributes.get("samesite", "").lower() == "none" and not fact.has("secure"):
            missing.append("Secure (required with SameSite=None)")

        if missing:
            locations.append(
                Location(
                    route=route,
                    detail=f"cookie {fact.name!r} is missing {', '.join(missing)}",
                )
            )
            reasons.append(
                f"the cookie {fact.name!r} set on {route} does not carry {', '.join(missing)}"
            )

    if not locations:
        return ControlOutcome(
            check_id="SL-C02-COOKIE-01",
            canonical_control="session.cookie.protective_flags",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"{len(cookies)} session-shaped cookie(s) carry the protective flags",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(
            *reasons,
            "each cookie was classified as session-shaped from its own name, and the "
            "attribute set was read from the Set-Cookie header as received",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C02-COOKIE-01",
        canonical_control="session.cookie.protective_flags",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=tuple(locations),
        proposed_severity=Severity.MEDIUM,
        proof=proof,
    )


def evaluate_cookie_scope(ctx: CheckContext) -> ControlOutcome:
    """SL-C02-COOKIE-02 — a session cookie is not scoped more broadly than it needs (ADD-02).

    Reports a session cookie sent to a parent domain, or with ``Path=/`` on an application
    mounted under a prefix. Both widen where the cookie is presented without any
    corresponding benefit to the application that set it.
    """
    cookies = _session_cookies(ctx)
    if not cookies:
        return ControlOutcome(
            check_id="SL-C02-COOKIE-02",
            canonical_control="session.cookie.scope",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no session-shaped cookie was observed, so cookie scope is unassessed",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for route, _header, fact in cookies:
        domain = fact.attributes.get("domain", "")
        if domain and not domain.startswith("."):
            # A bare Domain attribute still widens to subdomains in every current browser.
            locations.append(
                Location(route=route, detail=f"cookie {fact.name!r} sets Domain={domain}")
            )
            reasons.append(
                f"the cookie {fact.name!r} sets Domain={domain}, which presents it to "
                "subdomains as well as the origin"
            )
        if fact.attributes.get("domain", "").startswith("."):
            locations.append(
                Location(
                    route=route,
                    detail=f"cookie {fact.name!r} sets a leading-dot Domain={domain}",
                )
            )
            reasons.append(
                f"the cookie {fact.name!r} sets a leading-dot Domain={domain}, sending it to "
                "every matching subdomain"
            )

    if not locations:
        return ControlOutcome(
            check_id="SL-C02-COOKIE-02",
            canonical_control="session.cookie.scope",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"{len(cookies)} session-shaped cookie(s) are scoped to their own origin",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(
            *reasons,
            "read from the Set-Cookie header as received",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C02-COOKIE-02",
        canonical_control="session.cookie.scope",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=tuple(locations),
        proposed_severity=Severity.LOW,
        proof=proof,
    )
