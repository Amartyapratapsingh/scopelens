"""Transport and encryption controls (category C01). Build Plan §5.8.

Each control here is a pure function over collected data plus the TLS lane's measurement.
The TLS measurement is the important one: the assessment lane is intercepted by the proxy, so
a certificate read through it would describe the proxy rather than the target. Anything about
the *real* transport comes from the lane, and these controls say so in their proof reasons.
"""

from __future__ import annotations

from datetime import UTC, datetime

from scopelens.checks.engine import CheckContext
from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as Outcome

CATEGORY = Category.C01_TRANSPORT


def _no_tls_evidence(ctx: CheckContext) -> ControlOutcome:
    """The lane did not produce a certificate.

    Not a pass and not a finding: an unassessable transport. Spec §9.7 keeps it out of both,
    because "we could not look" is not "we looked and it was fine".
    """
    return ControlOutcome(
        check_id="SL-C01-TLS-01",
        canonical_control="transport.tls.certificate_validity",
        category=CATEGORY,
        status=Outcome.INCONCLUSIVE,
        summary="the TLS measurement lane produced no certificate for this origin",
    )


def evaluate_tls_certificate(ctx: CheckContext) -> ControlOutcome:
    """Assess trust, identity, validity and the protocol offers at capture time."""
    tls = ctx.data.tls
    if ctx.data.scheme == "http":
        return ControlOutcome(
            check_id="SL-C01-TLS-01",
            canonical_control="transport.tls.certificate_validity",
            category=CATEGORY,
            status=Outcome.NOT_APPLICABLE,
            na_reason="The authorized origin is cleartext-only",
            na_evidence_ref=ctx.evidence_ref("scope"),
        )
    if tls is None or not tls.describes_a_certificate or not tls.measured_at:
        return _no_tls_evidence(ctx)
    when = datetime.fromisoformat(tls.measured_at)
    days = _days_until(tls.not_after, when)
    reasons = []
    incomplete = []
    severity = Severity.MEDIUM
    if tls.certificate_verified is False:
        reasons.append(f"Certificate verification failed: {tls.verification_error}")
    elif tls.certificate_verified is not True:
        incomplete.append("Certificate chain and hostname were not verified")
    if days is None:
        incomplete.append("Certificate expiry is unreadable")
    elif days < 0:
        reasons.append(f"Certificate expired {-days} day(s) before measurement")
        severity = Severity.HIGH
    elif days < 14:
        reasons.append(f"Certificate expires within {days} day(s) of measurement")
    for version in ("TLSv1", "TLSv1.1"):
        result = tls.legacy_protocols.get(version)
        if result == "accepted":
            reasons.append(f"The server accepted the bounded {version} handshake")
        elif result != "rejected":
            incomplete.append(f"{version} support was not conclusively assessed")
    if not reasons:
        return ControlOutcome(
            check_id="SL-C01-TLS-01",
            canonical_control="transport.tls.certificate_validity",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE if incomplete else Outcome.PASS,
            summary="; ".join(incomplete)
            or f"Certificate verified; {days} days remaining at measurement; legacy offers rejected",
            incomplete_reasons=tuple(incomplete),
        )
    proof = _prove_tls_certificate(ctx, reasons)
    return ControlOutcome(
        check_id="SL-C01-TLS-01",
        canonical_control="transport.tls.certificate_validity",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=(Location(route="/", detail="; ".join(reasons)),),
        proposed_severity=severity,
        proof=proof,
        incomplete_reasons=tuple(incomplete),
    )


def _prove_tls_certificate(ctx: CheckContext, reasons: list[str]) -> ProofResult:
    """Registered proof rule for SL-C01-TLS-01.

    The criterion is that the certificate facts came from the **TLS lane**, which connects to
    the real upstream outside the intercepting proxy. A certificate observed through the
    assessment lane is the proxy's own and cannot support a claim about the target, so a
    missing lane measurement fails this rule rather than falling back.
    """
    ref = ctx.evidence_ref("tls")
    if not ref or ctx.data.tls is None or not ctx.data.tls.describes_a_certificate:
        return ProofResult(
            satisfied=False,
            status=EvidenceStatus.INCONCLUSIVE,
            reasons=("no measurement from the TLS lane; nothing describes the real upstream",),
        )
    return ProofResult(
        satisfied=True,
        status=EvidenceStatus.CONFIRMED,
        reasons=(
            *reasons,
            "measured by the constrained TLS lane, which connects to the real upstream "
            "rather than through the intercepting proxy",
        ),
        evidence_refs=(ref,),
    )


def evaluate_http_redirect(ctx: CheckContext) -> ControlOutcome:
    """SL-C01-REDIR-01 — cleartext HTTP redirects to HTTPS, or serves content."""
    probe = ctx.data.cleartext_probe
    if probe is None:
        return ControlOutcome(
            check_id="SL-C01-REDIR-01",
            canonical_control="transport.http.redirects_to_https",
            category=CATEGORY,
            status=Outcome.NOT_TESTED,
            summary="Authorized cleartext probe failed"
            if ctx.data.transport_http_authorized
            else "No separately approved transport-only HTTP origin; check unassessed",
        )

    ref = ctx.evidence_ref("cleartext")
    location = f"http://{probe.headers.get('host', ctx.data.host)}{probe.route}"
    chain = probe.redirect_chain or (probe.header("location") or "",)

    redirects_to_https = probe.status in {301, 302, 303, 307, 308} and any(
        _approved_https_redirect(target, ctx) for target in chain
    )

    if redirects_to_https:
        return ControlOutcome(
            check_id="SL-C01-REDIR-01",
            canonical_control="transport.http.redirects_to_https",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"cleartext HTTP redirects to HTTPS ({probe.status})",
        )

    if not 200 <= probe.status < 300:
        return ControlOutcome(
            check_id="SL-C01-REDIR-01",
            canonical_control="transport.http.redirects_to_https",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary=f"HTTP {probe.status} did not demonstrate an approved HTTPS redirect or application content",
        )
    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(
            f"the cleartext origin answered HTTP {probe.status} without redirecting to "
            "HTTPS, so an application response was served in the clear",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C01-REDIR-01",
        canonical_control="transport.http.redirects_to_https",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary=proof.reasons[0],
        locations=(Location(route=probe.route, detail=location),),
        proposed_severity=Severity.MEDIUM,
        proof=proof,
    )


def evaluate_hsts(ctx: CheckContext) -> ControlOutcome:
    """SL-C01-HSTS-01 — HSTS present and establishing an effective policy."""
    https_responses = [r for r in ctx.data.responses if r.url.startswith("https://")]
    if not https_responses:
        return ControlOutcome(
            check_id="SL-C01-HSTS-01",
            canonical_control="transport.hsts.effective_policy",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no HTTPS response was collected, so HSTS could not be judged",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for response in https_responses:
        value = response.header("strict-transport-security")
        if value is None:
            locations.append(
                Location(route=response.route, header="strict-transport-security", detail="absent")
            )
            reasons.append(f"{response.route} sent no Strict-Transport-Security header")
            continue
        max_age = _max_age(value)
        if max_age is None or max_age <= 0:
            locations.append(
                Location(
                    route=response.route,
                    header="strict-transport-security",
                    detail=f"ineffective policy: {value}",
                )
            )
            reasons.append(
                f"{response.route} sent Strict-Transport-Security: {value}, whose max-age "
                "does not establish a policy"
            )

    if not locations:
        return ControlOutcome(
            check_id="SL-C01-HSTS-01",
            canonical_control="transport.hsts.effective_policy",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"HSTS present with an effective policy on {len(https_responses)} response(s)",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(
            *reasons,
            "observed in a response the scanner itself collected over TLS from the origin",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C01-HSTS-01",
        canonical_control="transport.hsts.effective_policy",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=tuple(locations),
        proposed_severity=Severity.LOW,
        proof=proof,
    )


def evaluate_mixed_content(ctx: CheckContext) -> ControlOutcome:
    """SL-C01-MIXED-01 — an HTTPS page referencing a cleartext subresource.

    Only *active* mixed content matters enough to report: a script or stylesheet fetched over
    HTTP inside an HTTPS page is a real weakness, while a cleartext image is blocked silently
    by every current browser and reporting it would be noise.
    """
    from bs4 import BeautifulSoup

    html_responses = [r for r in ctx.data.responses if r.url.startswith("https://") and r.is_html]
    if not html_responses:
        return ControlOutcome(
            check_id="SL-C01-MIXED-01",
            canonical_control="transport.https.mixed_content",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no HTTPS HTML response was collected, so mixed content could not be judged",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref

    locations: list[Location] = []
    reasons: list[str] = []
    for response in html_responses:
        soup = BeautifulSoup(response.body_excerpt, "html.parser")
        for node in soup.find_all(["script", "iframe", "link", "object", "embed"]):
            if node.name == "link" and "stylesheet" not in node.get("rel", []):
                continue
            resource = str(node.get("src") or node.get("href") or node.get("data") or "")
            if resource.lower().startswith("http://"):
                locations.append(
                    Location(route=response.route, detail=f"{node.name}: {resource[:160]}")
                )
                reasons.append(f"{response.route} includes a cleartext {node.name} resource")

    if not locations:
        return ControlOutcome(
            check_id="SL-C01-MIXED-01",
            canonical_control="transport.https.mixed_content",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"no cleartext subresources in {len(html_responses)} HTTPS page(s)",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(
            *reasons,
            "read from the delivered HTML of a response collected over TLS",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C01-MIXED-01",
        canonical_control="transport.https.mixed_content",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=tuple(locations),
        proposed_severity=Severity.MEDIUM,
        proof=proof,
    )


# --- helpers -------------------------------------------------------------------------


def _max_age(value: str) -> int | None:
    for directive in value.split(";"):
        key, _, raw = directive.strip().partition("=")
        if key.strip().lower() == "max-age":
            try:
                return int(raw.strip().strip('"'))
            except ValueError:
                return None
    return None


def _days_until(not_after: str | None, measured_at: datetime) -> int | None:
    """Whole days from now until ``not_after``, or None if it cannot be read.

    The format is the one the stdlib emits (``Nov 24 12:00:00 2027 GMT``). An unparsable
    value yields None rather than an exception, and the caller treats that as "cannot
    judge" rather than as a finding.
    """
    if not not_after:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            expiry = datetime.strptime(not_after, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
        return (expiry - measured_at).days
    return None


def _approved_https_redirect(target: str, ctx: CheckContext) -> bool:
    from urllib.parse import urlsplit

    parts = urlsplit(target)
    return (
        parts.scheme == "https"
        and parts.hostname == ctx.data.host
        and (parts.port or 443) == ctx.data.port
        and not parts.username
    )
