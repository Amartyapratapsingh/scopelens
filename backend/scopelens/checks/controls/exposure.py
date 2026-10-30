"""Data exposure and privacy controls (category C05). Build Plan §5.8, Spec §10.5.

The exposed-file and directory-listing controls are the ones where restraint matters most.
Spec §10.3 permits collecting *"only the minimum capped excerpt needed to classify exposure"*
and prohibits repository reconstruction, bulk download and use of any discovered credential.
So these controls record **that** a path is exposed, with the response metadata that proves it
— not the file's contents. What was downloaded is never reproduced into a report, and the
excerpt that does reach evidence is capped at capture and redacted at intake.
"""

from __future__ import annotations

import re

from scopelens.checks.engine import CheckContext
from scopelens.domain.check import (
    ControlOutcome,
    Location,
    ProofResult,
    potential,
)
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as Outcome

CATEGORY = Category.C05_DATA_EXPOSURE

#: Paths whose exposure is a finding, with the severity each warrants. Bounded and explicit:
#: a wordlist that grew at runtime would be a content-discovery tool, which this is not.
SENSITIVE_PATHS: dict[str, Severity] = {
    "/.env": Severity.HIGH,
    "/backup.sql": Severity.MEDIUM,
    "/.git/config": Severity.HIGH,
}

#: Signatures of a thrown error rendered into a response body. Each is a shape that appears
#: in framework error pages and not in ordinary content.
STACK_TRACE_SIGNATURES: tuple[tuple[str, str], ...] = (
    (r"Traceback \(most recent call last\)", "a Python traceback"),
    (r"\bat [a-zA-Z0-9_.$]+\([A-Za-z0-9_.$]+\.java:\d+\)", "a Java stack frame"),
    (r"Notice:\s+Undefined (variable|index)", "a PHP notice"),
    (r"Warning:\s+mysql_(connect|query)", "a PHP database warning"),
    (r"<b>Fatal error</b>:", "a PHP fatal error"),
    (r"System\.Web\.HttpException|Server Error in '/' Application", "an ASP.NET error page"),
    (r"django\.core\.exceptions\.|django\.db\.", "a Django exception"),
    (r"ActiveRecord::[A-Za-z]+Error", "a Rails exception"),
    (r"at Object\.<anonymous> \([^)]+:\d+:\d+\)", "a Node.js stack frame"),
)

#: Signatures of an autoindex page. Matched narrowly so an ordinary page listing file names
#: in prose is not reported as a directory listing.
DIRECTORY_LISTING_SIGNATURES = (
    re.compile(r"<title>\s*Index of /", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of /", re.IGNORECASE),
    re.compile(r"\[To Parent Directory\]", re.IGNORECASE),
    re.compile(r"<a href=\"\?C=N;O=D\">Name</a>", re.IGNORECASE),  # Apache autoindex
)

#: Values that are shaped like a private credential in delivered content.
PRIVATE_SECRET_SHAPES: tuple[tuple[str, str], ...] = (
    (r"\bsk-[A-Za-z0-9_-]{20,}", "an OpenAI-style secret key"),
    (r"\bAKIA[0-9A-Z]{16}\b", "an AWS access key id"),
    (r"\bgh[pousr]_[A-Za-z0-9]{20,}", "a GitHub token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "a private key block"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "a JSON Web Token"),
)

#: Values that look like a credential but are meant to be public. Recognising these is what
#: keeps the control from reporting every analytics key as a leak.
PUBLIC_IDENTIFIER_SHAPES: tuple[tuple[str, str], ...] = (
    (r"\bpk_(live|test)_[A-Za-z0-9]{10,}", "a publishable key"),
    (r"\bAIza[0-9A-Za-z_-]{30,}", "a Google API browser key"),
    (r"\bGTM-[A-Z0-9]{4,}", "a tag-manager container id"),
    (r"\bG-[A-Z0-9]{6,}", "an analytics measurement id"),
)


def evaluate_verbose_errors(ctx: CheckContext) -> ControlOutcome:
    """SL-C05-ERRORS-01 — a response body discloses a stack trace or framework error."""
    responses = [r for r in ctx.data.responses if r.body_excerpt]
    if not responses:
        return ControlOutcome(
            check_id="SL-C05-ERRORS-01",
            canonical_control="exposure.verbose_error_disclosure",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no response body was collected, so error disclosure could not be judged",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for response in responses:
        for pattern, description in STACK_TRACE_SIGNATURES:
            if re.search(pattern, response.body_excerpt, re.IGNORECASE):
                locations.append(
                    Location(
                        route=response.route,
                        detail=f"response body contains {description}",
                    )
                )
                reasons.append(
                    f"{response.route} returns a body containing {description}, which "
                    "discloses internal implementation detail to any visitor"
                )
                break

    if not locations:
        return ControlOutcome(
            check_id="SL-C05-ERRORS-01",
            canonical_control="exposure.verbose_error_disclosure",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"no stack-trace signature in {len(responses)} response body(ies)",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(*reasons, "the signature was matched in the body the scanner collected"),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C05-ERRORS-01",
        canonical_control="exposure.verbose_error_disclosure",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=tuple(locations),
        proposed_severity=Severity.MEDIUM,
        proof=proof,
    )


def evaluate_directory_listing(ctx: CheckContext) -> ControlOutcome:
    """SL-C05-LISTING-01 — a directory renders an index of its contents (F34)."""
    responses = [r for r in ctx.data.responses if r.status == 200 and r.is_html]
    if not responses:
        return ControlOutcome(
            check_id="SL-C05-LISTING-01",
            canonical_control="exposure.directory_listing",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no successful HTML response was collected, so listing could not be judged",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for response in responses:
        for signature in DIRECTORY_LISTING_SIGNATURES:
            if signature.search(response.body_excerpt):
                locations.append(
                    Location(route=response.route, detail="the response renders a directory index")
                )
                reasons.append(
                    f"{response.route} renders an index of the directory rather than an "
                    "application page, so its contents are enumerable by any visitor"
                )
                break

    if not locations:
        return ControlOutcome(
            check_id="SL-C05-LISTING-01",
            canonical_control="exposure.directory_listing",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"no directory index in {len(responses)} HTML response(s)",
        )

    proof = ProofResult(
        satisfied=bool(ref),
        status=EvidenceStatus.CONFIRMED if ref else EvidenceStatus.INCONCLUSIVE,
        reasons=(*reasons, "the index markup was read from the response the scanner collected"),
        evidence_refs=(ref,) if ref else (),
    )
    return ControlOutcome(
        check_id="SL-C05-LISTING-01",
        canonical_control="exposure.directory_listing",
        category=CATEGORY,
        status=Outcome.CONFIRMED_ISSUE if proof.satisfied else Outcome.INCONCLUSIVE,
        summary="; ".join(reasons),
        locations=tuple(locations),
        proposed_severity=Severity.MEDIUM,
        proof=proof,
    )


def evaluate_exposed_files(ctx: CheckContext) -> ControlOutcome:
    """Require file-specific content and an independently fetched fallback control."""
    ref = ctx.evidence_ref("crawl")
    baseline = ctx.data.by_route("/.scopelens-not-found-control")
    locations = []
    incomplete = []
    completed = []
    severity = Severity.LOW
    patterns = {
        "/.env": r"(?m)^(?:export\s+)?(?:DATABASE_URL|API_KEY|SESSION_SECRET|DB_PASSWORD|SECRET_KEY)\s*=.+$",
        "/.git/config": r"(?m)^\[core\]\s*$",
        "/backup.sql": r"(?im)^\s*(?:CREATE TABLE|INSERT INTO|COPY [^ ]+|-- (?:PostgreSQL|MySQL))\b",
    }
    for path, risk in SENSITIVE_PATHS.items():
        response = ctx.data.by_route(path)
        if response is None:
            incomplete.append(f"{path}: {ctx.data.unreachable.get(path, 'not reached')}")
            continue
        if response.status in {404, 410}:
            completed.append(path)
            continue
        if response.status != 200:
            incomplete.append(f"{path}: HTTP {response.status}, exposure not established")
            continue
        if baseline is None or baseline.truncated or baseline.status not in {200, 404, 410}:
            incomplete.append(f"{path}: no conclusive fallback control")
            continue
        same_fallback = baseline.status == 200 and response.body_excerpt == baseline.body_excerpt
        file_shape = not response.is_html and re.search(patterns[path], response.body_excerpt)
        if response.body_bytes and file_shape and not same_fallback:
            locations.append(
                Location(
                    route=path,
                    detail="Capped excerpt matches file structure; differs from fallback response",
                )
            )
            severity = max(severity, risk, key=lambda item: item.deduction)
            completed.append(path)
        elif response.truncated or not response.body_bytes:
            incomplete.append(f"{path}: insufficient content to classify")
        elif same_fallback or response.is_html:
            completed.append(path)
        else:
            incomplete.append(f"{path}: content could not be classified")
    proof = ProofResult(
        satisfied=bool(locations and ref),
        status=EvidenceStatus.CONFIRMED if locations and ref else EvidenceStatus.INCONCLUSIVE,
        reasons=("File-specific content differs from the negative control; values omitted",),
        evidence_refs=(ref,) if ref else (),
    )
    status = (
        Outcome.CONFIRMED_ISSUE
        if proof.is_confirmed
        else (Outcome.INCONCLUSIVE if incomplete or locations else Outcome.PASS)
    )
    return ControlOutcome(
        check_id="SL-C05-FILES-01",
        canonical_control="exposure.sensitive_files",
        category=CATEGORY,
        status=status,
        summary=f"{len(completed)}/{len(SENSITIVE_PATHS)} sensitive paths assessed",
        locations=tuple(locations),
        proposed_severity=severity if locations else None,
        proof=proof if locations else None,
        required_instances=tuple(SENSITIVE_PATHS),
        completed_instances=tuple(completed),
        incomplete_reasons=tuple(incomplete),
    )


def evaluate_client_secrets(ctx: CheckContext) -> ControlOutcome:
    """SL-C05-SECRETS-01 — a private credential is delivered to the browser (F37).

    Stance is **FLAG** (Spec §10.5): the control classifies and reports, and never
    authenticates with what it found. Spec §10.2 also requires distinguishing a public client
    identifier from private material, so a publishable key is not reported as a leak — and the
    result is a *candidate*, which is why it returns ``potential`` rather than a confirmation.
    """
    scripts = [r for r in ctx.data.responses if r.body_excerpt and (r.is_javascript or r.is_html)]
    if not scripts:
        return ControlOutcome(
            check_id="SL-C05-SECRETS-01",
            canonical_control="exposure.client_side_secret_candidates",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="no delivered script or HTML was collected, so this was not assessed",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for response in scripts:
        for pattern, description in PRIVATE_SECRET_SHAPES:
            if not re.search(pattern, response.body_excerpt):
                continue
            locations.append(
                Location(
                    route=response.route,
                    detail=f"delivered content contains a value shaped like {description}",
                )
            )
            reasons.append(
                f"{response.route} delivers a value shaped like {description} to every visitor"
            )

    if not locations and not reasons:
        return ControlOutcome(
            check_id="SL-C05-SECRETS-01",
            canonical_control="exposure.client_side_secret_candidates",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"no private-credential shape in {len(scripts)} delivered document(s)",
        )

    proof = ProofResult(
        satisfied=False,
        status=EvidenceStatus.POTENTIAL,
        reasons=(
            *reasons,
            "shape matching cannot separate a live secret from a revoked or example value, "
            "and Spec §10.2 forbids authenticating with a discovered credential to find out",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return potential(
        check_id="SL-C05-SECRETS-01",
        canonical_control="exposure.client_side_secret_candidates",
        category=CATEGORY,
        summary="; ".join(reasons),
        proof=proof,
        locations=tuple(locations),
        severity=Severity.HIGH if locations else Severity.LOW,
    )
