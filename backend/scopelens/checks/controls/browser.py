"""Browser and cross-origin security controls (category C04). Build Plan §5.8, Spec §10.1.

These evaluate the *effective* policy a browser would apply, not the presence of a header.
ADD-01 is explicit that a header whose rules do not deliver the intended protection is the
finding, and Spec §9.8 requires equivalent protections to be charged once — which is why
frame protection accepts either mechanism and reports a single weakness.
"""

from __future__ import annotations

from scopelens.checks.engine import CheckContext
from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as Outcome

CATEGORY = Category.C04_BROWSER_CROSS_ORIGIN


def _https_html(ctx: CheckContext) -> list:  # type: ignore[type-arg]
    return [r for r in ctx.data.responses if r.url.startswith("https://") and r.is_html]


def _csp_directives(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        directives.setdefault(tokens[0].lower(), tokens[1:])
    return directives


def evaluate_csp(ctx: CheckContext) -> ControlOutcome:
    """SL-C04-CSP-01 — a Content-Security-Policy that establishes a real policy."""
    pages = _https_html(ctx)
    if not pages:
        return ControlOutcome(
            check_id="SL-C04-CSP-01",
            canonical_control="browser.content_security_policy.effective",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no HTTPS HTML response was collected, so a CSP could not be judged",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for response in pages:
        policy = response.header("content-security-policy")
        if policy is None:
            if response.header("content-security-policy-report-only") is not None:
                reasons.append(
                    f"{response.route} sends CSP in report-only mode, which enforces nothing"
                )
                locations.append(
                    Location(
                        route=response.route, header="content-security-policy", detail="report-only"
                    )
                )
                continue
            locations.append(
                Location(route=response.route, header="content-security-policy", detail="absent")
            )
            reasons.append(f"{response.route} sends no Content-Security-Policy header")
            continue

        policies = _policies(response)
        if not _scripts_restricted(policies):
            locations.append(
                Location(
                    route=response.route,
                    header="content-security-policy",
                    detail="Effective policy permits broad sources or unrestricted inline scripts",
                )
            )
            reasons.append(
                f"{response.route} does not constrain both script sources and inline execution"
            )

    if not locations:
        return ControlOutcome(
            check_id="SL-C04-CSP-01",
            canonical_control="browser.content_security_policy.effective",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"an enforcing CSP is present on {len(pages)} page(s)",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(
            *reasons,
            "read from a response the scanner collected over TLS from the origin",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C04-CSP-01",
        canonical_control="browser.content_security_policy.effective",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=tuple(locations),
        proposed_severity=Severity.LOW,
        proof=proof,
    )


def evaluate_frame_protection(ctx: CheckContext) -> ControlOutcome:
    """SL-C04-FRAME-01 — the page cannot be framed by another origin.

    Two mechanisms satisfy this, and Spec §9.8 says equivalent protections are not charged
    twice: a CSP with ``frame-ancestors``, or an ``X-Frame-Options`` header. A page that has
    both is one pass, not two, and a page that has neither is one finding.
    """
    pages = _https_html(ctx)
    if not pages:
        return ControlOutcome(
            check_id="SL-C04-FRAME-01",
            canonical_control="browser.frame_protection.effective",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no HTTPS HTML response was collected, so frame protection could not be judged",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []
    mechanisms: list[str] = []

    for response in pages:
        policies = _policies(response)
        ancestor_lists = [p["frame-ancestors"] for p in policies if "frame-ancestors" in p]
        xfo = (response.header("x-frame-options") or "").strip().upper()
        if ancestor_lists:
            # Enforced frame-ancestors supersedes XFO. Multiple policies intersect.
            if any(
                not any(source in {"*", "http:", "https:"} for source in sources)
                for sources in ancestor_lists
            ):
                mechanisms.append("csp-frame-ancestors")
                continue
        elif xfo in {"DENY", "SAMEORIGIN"}:
            mechanisms.append("x-frame-options")
            continue

        locations.append(
            Location(
                route=response.route,
                detail="neither CSP frame-ancestors nor X-Frame-Options is present",
            )
        )
        reasons.append(
            f"{response.route} provides neither CSP frame-ancestors nor X-Frame-Options, so "
            "a browser will allow it to be framed by any origin"
        )

    if not locations:
        return ControlOutcome(
            check_id="SL-C04-FRAME-01",
            canonical_control="browser.frame_protection.effective",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"frame protection present via {sorted(set(mechanisms))}",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(
            *reasons,
            "equivalent mechanisms are counted once: frame-ancestors and X-Frame-Options "
            "are alternatives, not two separate weaknesses",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C04-FRAME-01",
        canonical_control="browser.frame_protection.effective",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=tuple(locations),
        proposed_severity=Severity.LOW,
        proof=proof,
    )


def evaluate_xcto(ctx: CheckContext) -> ControlOutcome:
    """SL-C04-XCTO-01 — X-Content-Type-Options is nosniff where sniffing could matter."""
    responses = [r for r in ctx.data.responses if r.status < 400]
    if not responses:
        return ControlOutcome(
            check_id="SL-C04-XCTO-01",
            canonical_control="browser.content_type_sniffing.prevented",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no successful response was collected",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for response in responses:
        value = response.header("x-content-type-options")
        if value is not None and value.strip().lower() == "nosniff":
            continue
        # Only responses a browser might reinterpret. A response whose type is already
        # unambiguous is not reported: charging it would inflate the count without
        # describing anything exploitable.
        if not _reinterpretable(response):
            continue
        locations.append(
            Location(
                route=response.route,
                header="x-content-type-options",
                detail=f"absent or not nosniff (value: {value!r})",
            )
        )
        reasons.append(
            f"{response.route} returns {response.content_type!r} without nosniff, so a browser "
            "may reinterpret its content type"
        )

    if not locations:
        return ControlOutcome(
            check_id="SL-C04-XCTO-01",
            canonical_control="browser.content_type_sniffing.prevented",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"nosniff present where it matters across {len(responses)} response(s)",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(
            *reasons,
            "each reported response was observed by the scanner with the header absent",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C04-XCTO-01",
        canonical_control="browser.content_type_sniffing.prevented",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join((locations and reasons) or []),
        locations=tuple(locations),
        proposed_severity=Severity.LOW,
        proof=proof,
    )


def evaluate_referrer_policy(ctx: CheckContext) -> ControlOutcome:
    """SL-C04-REFERRER-01 — a Referrer-Policy that limits cross-origin leakage."""
    pages = _https_html(ctx)
    if not pages:
        return ControlOutcome(
            check_id="SL-C04-REFERRER-01",
            canonical_control="browser.referrer_policy.present",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no HTTPS HTML response was collected",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for response in pages:
        value = response.header("referrer-policy")
        if not value or value.split(",")[-1].strip().lower() not in {
            "no-referrer",
            "same-origin",
            "strict-origin",
            "strict-origin-when-cross-origin",
            "origin",
            "origin-when-cross-origin",
            "no-referrer-when-downgrade",
        }:
            locations.append(
                Location(
                    route=response.route, header="referrer-policy", detail="missing or ineffective"
                )
            )
            reasons.append(
                f"{response.route} sends no Referrer-Policy header, so the browser default "
                "decides what leaves the origin in the Referer header"
            )

    if not locations:
        return ControlOutcome(
            check_id="SL-C04-REFERRER-01",
            canonical_control="browser.referrer_policy.present",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"Referrer-Policy present on {len(pages)} page(s)",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(
            *reasons,
            "observed absent in responses the scanner collected",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C04-REFERRER-01",
        canonical_control="browser.referrer_policy.present",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=tuple(locations),
        proposed_severity=Severity.LOW,
        proof=proof,
    )


def _reinterpretable(response) -> bool:  # type: ignore[no-untyped-def]
    """Whether a browser might sniff this response into something else.

    Deliberately narrow. Images, fonts and video are not on the list because reporting them
    would produce findings nobody can act on, and a finding nobody can act on is noise that
    makes the real ones easier to miss.
    """
    content_type = (response.content_type or "").split(";")[0].strip().lower()
    if not content_type:
        return True
    return content_type in {
        "text/html",
        "text/plain",
        "application/octet-stream",
        "application/json",
        "text/xml",
        "application/xml",
        "",
    }


def _policies(response) -> list[dict[str, list[str]]]:
    """CSP serialized policy lists intersect; within one policy the first directive wins.

    Reference: https://www.w3.org/TR/CSP/#parse-serialized-policy
    """
    values = response.header_values.get("content-security-policy", ())
    if not values:
        values = (response.header("content-security-policy") or "",)
    return [
        _csp_directives(policy) for value in values for policy in value.split(",") if policy.strip()
    ]


def _scripts_restricted(policies: list[dict[str, list[str]]]) -> bool:
    external = inline = False
    for policy in policies:
        sources = policy.get("script-src-elem", policy.get("script-src", policy.get("default-src")))
        if sources is None:
            continue
        nonce_or_hash = any(
            s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) and s.endswith("'")
            for s in sources
        )
        external |= not any(s in {"*", "http:", "https:", "data:"} for s in sources)
        if nonce_or_hash and "'strict-dynamic'" in sources:
            external = True
        inline |= "'unsafe-inline'" not in sources or nonce_or_hash
    return external and inline
