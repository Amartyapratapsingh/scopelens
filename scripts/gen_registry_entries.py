#!/usr/bin/env python3
"""Generate the M2 check-registry entries.

Run once to author the YAML; the files are committed and are the source of truth from then
on. This exists so fourteen entries share one shape and none is missing a field, not so the
content can be regenerated — the per-control prose below is the reviewable part.

Standards mapping provenance: every WSTG v4.2 and CWE identifier below was checked against
the standard itself (wstg.owasp.org/v4.2 section indexes). ASVS 5.0.0 and OWASP Top 10:2025
identifiers are **left empty**, because they were not verified for this pass and a guessed
identifier in a security control catalogue is a fabricated claim.
"""

from __future__ import annotations

import pathlib

import yaml

OUT = pathlib.Path("checks_registry/controls")

COMMON_OWNER = "Aditya Pratap Singh"

#: Fields every entry shares. Per-control values override these.
BASE_APPLICABILITY_EVIDENCE = "A response captured by the scanner from the scope origin."


def entry(
    *,
    check_id: str,
    title: str,
    canonical: str,
    root_cause: str,
    category: str,
    wstg: list[str],
    cwe: list[str],
    stance: str,
    family: str,
    signal: str,
    confirmation: str,
    negatives: list[str],
    false_positives: list[str],
    vulnerable: str,
    fixed: str,
    applicability: str,
    not_applicable_when: str,
    evidence_required: str = BASE_APPLICABILITY_EVIDENCE,
    max_requests: int = 0,
    mandatory: bool = True,
    expectations: str = "none — reads responses already collected during recon",
    stop_conditions: list[str] | None = None,
    prerequisites: str = "none",
) -> dict:
    return {
        "id": check_id,
        "title": title,
        "canonical_control": canonical,
        "root_cause": root_cause,
        "category": category,
        "standards": {
            "wstg_v42": wstg,
            "cwe": cwe,
            "owasp_top10_2025": [],
            "asvs_500": [],
            "api_top10_2023": [],
            "mapping_review": "reviewed",
        },
        "availability": {
            "profiles": ["external-configuration", "external-dast"],
            "phase": "M2",
            "stance": stance,
            "family": family,
        },
        "applicability": {
            "description": applicability,
            "evidence_required": evidence_required,
            "not_applicable_when": not_applicable_when,
        },
        "prerequisites": {
            "credentials": prerequisites,
            "fixtures": "labs-bad (vulnerable) and labs-good (fixed)",
            "notes": "",
        },
        "allowed_action": {
            "destinations": "scope origin only",
            "methods": ["GET", "HEAD"],
            "max_requests": max_requests,
            "max_response_bytes": 1048576,
            "timeout_seconds": 10.0,
        },
        "side_effects": {
            "expectation": expectations,
            "cleanup": "none required",
            "stop_conditions": stop_conditions
            or [
                "the scope origin is unreachable",
                "the authorization for this scope has expired",
            ],
        },
        "detection": {
            "signal": signal,
            "negative_controls": negatives,
            "confirmation_criteria": confirmation,
            "false_positive_considerations": false_positives,
        },
        "fixtures": {"vulnerable": vulnerable, "fixed": fixed, "verified": True},
        "tool_version": "not applicable — implemented directly in Python",
        "mandatory": mandatory,
        "coverage_weight": 1,
        "review_state": "enabled",
        "owner": COMMON_OWNER,
        "last_reviewed": "2026-09-25",
    }


ENTRIES = [
    entry(
        check_id="SL-C01-TLS-01",
        title="TLS certificate is self-signed, expired or negotiates an obsolete protocol",
        canonical="transport.tls.certificate_validity",
        root_cause="tls-certificate-not-usable",
        category="C01",
        wstg=["WSTG-CRYP-01"],
        cwe=["CWE-295", "CWE-327"],
        stance="OBSERVE",
        family="F41",
        signal="The TLS lane's measurement of the real upstream certificate reports a notAfter in the past, subject equal to issuer, or a negotiated protocol no current browser accepts.",
        confirmation=(
            "Confirmed when the constrained TLS lane — which connects to the real upstream "
            "outside the intercepting proxy — reports the condition. A certificate read "
            "through the assessment lane is the proxy's own and cannot support this claim, so "
            "a missing lane measurement makes the control inconclusive rather than clean."
        ),
        negatives=[
            "labs-good presents a CA-signed certificate with a future notAfter, which must produce no finding",
            "the proxy's own intercepting certificate must never be the artifact this control reads",
        ],
        false_positives=[
            "A short remaining validity is not necessarily a defect; the control reports the window and lets the reader judge.",
            "Certificate chain trust is NOT assessed: neither lab fixture is in a system trust store, so 'not self-signed' is not 'trusted'.",
            "A CDN or terminating load balancer presents its own certificate; the finding describes what the origin serves.",
        ],
        vulnerable="labs-bad serves a self-signed certificate (issuer equals subject)",
        fixed="labs-good serves a certificate signed by the fixture CA (issuer differs from subject)",
        applicability="Applies to any scope whose scheme is https and whose port accepts a TLS handshake.",
        not_applicable_when="The scope declares a cleartext-only origin. Recorded with the reason; an unreachable TLS listener is inconclusive, not N/A.",
        evidence_required="A TLS measurement from the constrained lane for the scope host and port.",
    ),
    entry(
        check_id="SL-C01-REDIR-01",
        title="Cleartext HTTP serves an application response instead of redirecting to HTTPS",
        canonical="transport.http.redirects_to_https",
        root_cause="cleartext-origin-serves-content",
        category="C01",
        wstg=["WSTG-CRYP-03"],
        cwe=["CWE-319"],
        stance="OBSERVE",
        family="F41",
        signal="The authorized cleartext origin answers with a success status rather than a redirect whose target is https.",
        confirmation=(
            "Confirmed when the scanner observed the cleartext origin return a 2xx response, "
            "rather than a 3xx to an https target, on the transport-only origin the scope "
            "explicitly authorizes for this check."
        ),
        negatives=[
            "labs-good answers HTTP with 301 to HTTPS and must produce no finding",
            "the check must not follow a redirect into an unapproved origin",
        ],
        false_positives=[
            "A redirect to HTTPS that is not observed because the probe was not authorized is inconclusive, never a pass.",
            "Spec §12 requires a separately approved transport-only HTTP origin; without one the control is N/A with a recorded reason.",
        ],
        vulnerable="labs-bad serves content over cleartext HTTP with no redirect",
        fixed="labs-good answers cleartext HTTP with 301 to HTTPS",
        applicability="Applies when the scope declares a transport-only cleartext origin for this check.",
        not_applicable_when="No cleartext origin is authorized for the scope. Spec §12 requires that to be recorded rather than assumed clean.",
        max_requests=1,
    ),
    entry(
        check_id="SL-C01-HSTS-01",
        title="HTTP Strict Transport Security is missing or does not establish an effective policy",
        canonical="transport.hsts.effective_policy",
        root_cause="hsts-not-enforced",
        category="C01",
        wstg=["WSTG-CONF-07"],
        cwe=["CWE-319"],
        stance="OBSERVE",
        family="F33",
        signal="An HTTPS response from the origin carries no Strict-Transport-Security header, or carries one whose max-age does not establish a policy.",
        confirmation=(
            "Confirmed when a header is absent from a response the scanner observed over TLS "
            "from the scope origin, or when a present header fails the effective-policy "
            "criteria. The captured response must be stored as evidence."
        ),
        negatives=[
            "labs-good sends max-age=63072000; includeSubDomains and must produce no finding",
            "a response captured over cleartext HTTP must not be used to judge HSTS",
        ],
        false_positives=[
            "HSTS is ignored by browsers over cleartext HTTP, so a missing header on an HTTP response is not this finding.",
            "A short max-age may be a deliberate rollout choice; the observed value is reported and intent treated as unverified.",
            "Preload status is not observable from a response and must not be asserted.",
        ],
        vulnerable="labs-bad sends no Strict-Transport-Security header",
        fixed="labs-good sends max-age=63072000; includeSubDomains",
        applicability="Applies to any HTTPS origin in scope that returns a successful response.",
        not_applicable_when="The scope origin is cleartext HTTP only, recorded with the evidence that no HTTPS listener exists.",
    ),
    entry(
        check_id="SL-C01-MIXED-01",
        title="An HTTPS page loads an active subresource over cleartext HTTP",
        canonical="transport.https.mixed_content",
        root_cause="mixed-active-content",
        category="C01",
        wstg=["WSTG-CRYP-03"],
        cwe=["CWE-311"],
        stance="OBSERVE",
        family="F41",
        signal="Delivered HTML from an HTTPS origin contains a src or href attribute whose scheme is http.",
        confirmation=(
            "Confirmed when the cleartext reference is read from the delivered HTML of a "
            "response the scanner collected over TLS from the scope origin."
        ),
        negatives=[
            "labs-good's only HTML page contains no cleartext subresource and must produce no finding",
            "a cleartext reference in a page served over cleartext HTTP is a different finding (SL-C01-REDIR-01), not this one",
        ],
        false_positives=[
            "Passive mixed content (images, media) is blocked silently by current browsers and is not reported; only active subresources are.",
            "A URL in body text that looks like a link but is not a src or href attribute is not a subresource.",
        ],
        vulnerable="labs-bad serves /error-debug.html with a cleartext script src",
        fixed="labs-good serves no page with a cleartext subresource",
        applicability="Applies to HTML responses collected from an HTTPS origin.",
        not_applicable_when="No HTTPS HTML response was collected. A page that was never reached is inconclusive, not N/A.",
    ),
    entry(
        check_id="SL-C02-COOKIE-01",
        title="Session cookie is set without Secure, HttpOnly or SameSite protections",
        canonical="session.cookie.protective_flags",
        root_cause="session-cookie-missing-protective-flags",
        category="C02",
        wstg=["WSTG-SESS-02"],
        cwe=["CWE-614", "CWE-1004", "CWE-1275"],
        stance="OBSERVE",
        family="F40",
        signal="A cookie whose name indicates session or authentication state is set without Secure, HttpOnly or SameSite, or with SameSite=None and no Secure.",
        confirmation=(
            "Confirmed when a cookie the scanner observed the origin setting, and whose name "
            "indicates session or authentication state, lacks the specific attribute being "
            "reported. The evidence is the Set-Cookie attribute set as received, with the "
            "cookie value redacted before storage."
        ),
        negatives=[
            "labs-good sets sessionid with Secure; HttpOnly; SameSite=Strict and must produce no finding",
            "a non-session cookie such as a theme preference must not be reported for missing flags",
        ],
        false_positives=[
            "Cookie values are never stored: they are redacted to [redacted] before the artifact is written.",
            "A missing Secure flag on a cleartext-only origin is a different, larger finding; it is not double-counted here.",
            "Non-session cookies may legitimately omit flags. Reporting every unflagged cookie is treated as a false positive.",
        ],
        vulnerable="labs-bad sets sessionid with no Secure, HttpOnly or SameSite",
        fixed="labs-good sets sessionid with Secure; HttpOnly; SameSite=Strict",
        applicability="Applies to cookies the origin sets that carry session or authentication state, judged from the cookie's own name.",
        not_applicable_when="The origin sets no cookies on any assessed response, recorded with the responses observed and the routes covered.",
    ),
    entry(
        check_id="SL-C02-COOKIE-02",
        title="Session cookie is scoped more broadly than the application that set it",
        canonical="session.cookie.scope",
        root_cause="session-cookie-over-broad-scope",
        category="C02",
        wstg=["WSTG-SESS-02"],
        cwe=["CWE-668"],
        stance="OBSERVE",
        family="F40",
        signal="A session-shaped cookie carries a Domain attribute, presenting it to subdomains as well as the origin that set it.",
        confirmation=(
            "Confirmed when a session-shaped cookie's Set-Cookie header, as received, contains "
            "a Domain attribute. A host-only cookie — no Domain attribute at all — is the "
            "correct configuration and produces no finding."
        ),
        negatives=[
            "labs-good sets no Domain attribute and must produce no finding",
            "a cookie scoped to an unrelated domain is not this finding; the browser would reject it",
        ],
        false_positives=[
            "A multi-application deployment may intend a shared cookie. The finding states the scope and treats intent as unverified.",
            "An explicit Domain that happens to match the origin's own host still widens the cookie to subdomains, which is the reported behaviour.",
        ],
        vulnerable="labs-bad sets sessionid with an explicit Domain attribute",
        fixed="labs-good sets sessionid with no Domain attribute (host-only)",
        applicability="Applies to session-shaped cookies observed being set by the origin.",
        not_applicable_when="No session-shaped cookie was observed, in which case scope is unassessed rather than clean.",
    ),
    entry(
        check_id="SL-C04-CSP-01",
        title="Content-Security-Policy is missing or does not restrict script execution",
        canonical="browser.content_security_policy.effective",
        root_cause="csp-absent-or-ineffective",
        category="C04",
        wstg=[],
        cwe=["CWE-693"],
        stance="OBSERVE",
        family="F33",
        signal="An HTTPS HTML response carries no Content-Security-Policy header, carries it only in report-only mode, or carries a policy restricting neither default-src nor script-src.",
        confirmation=(
            "Confirmed when the policy is absent, report-only, or restricts neither "
            "default-src nor script-src, read from a response the scanner collected over TLS "
            "from the origin."
        ),
        negatives=[
            "labs-good sets default-src 'self'; frame-ancestors 'none'; object-src 'none' and must produce no finding",
            "a report-only policy enforces nothing and is treated as absent, not as present",
        ],
        false_positives=[
            "ADD-01 asks for effective-policy evaluation, not presence. A policy that exists but constrains nothing is the finding.",
            "unsafe-inline and unsafe-eval are extremely common and context-dependent; this control does not judge them.",
        ],
        vulnerable="labs-bad sends no Content-Security-Policy header",
        fixed="labs-good sends a policy enforcing default-src 'self'",
        applicability="Applies to HTML responses collected over TLS from the scope origin.",
        not_applicable_when="No HTTPS HTML response was collected, which is unassessed rather than clean.",
    ),
    entry(
        check_id="SL-C04-FRAME-01",
        title="Page can be framed by another origin: neither CSP frame-ancestors nor X-Frame-Options is set",
        canonical="browser.frame_protection.effective",
        root_cause="frame-protection-absent",
        category="C04",
        wstg=[],
        cwe=["CWE-1021"],
        stance="OBSERVE",
        family="F26",
        signal="An HTTPS HTML response provides neither a CSP frame-ancestors directive nor an X-Frame-Options header.",
        confirmation=(
            "Confirmed when both mechanisms are absent from a response the scanner collected "
            "over TLS from the origin. Equivalent protections are counted once: a page with "
            "either mechanism passes, and a page with both is still one pass."
        ),
        negatives=[
            "labs-good sets CSP frame-ancestors 'none' and must produce no finding",
            "a page protected by X-Frame-Options alone must pass, not be reported as missing a CSP",
        ],
        false_positives=[
            "Spec §9.8 requires equivalent protections to be charged once; reporting frame-ancestors and X-Frame-Options as two weaknesses would double-count one gap.",
            "The control evaluates the effective policy, not which header carries it.",
        ],
        vulnerable="labs-bad sends neither frame-ancestors nor X-Frame-Options",
        fixed="labs-good sends Content-Security-Policy with frame-ancestors 'none'",
        applicability="Applies to HTML responses collected over TLS from the scope origin.",
        not_applicable_when="No HTTPS HTML response was collected, which is unassessed rather than clean.",
    ),
    entry(
        check_id="SL-C04-XCTO-01",
        title="X-Content-Type-Options is missing, so responses may be MIME-sniffed",
        canonical="browser.content_type_sniffing.prevented",
        root_cause="content-type-sniffing-not-disabled",
        category="C04",
        wstg=[],
        cwe=["CWE-693", "CWE-436"],
        stance="OBSERVE",
        family="F33",
        signal="A response whose content type a browser could reinterpret is served without X-Content-Type-Options: nosniff.",
        confirmation=(
            "Confirmed when the scanner observed a response from the scope origin that lacks "
            "the header or sends a value other than nosniff, and whose content type is one a "
            "browser may reinterpret."
        ),
        negatives=[
            "labs-good sends X-Content-Type-Options: nosniff and must produce no finding",
            "an image or font response is not reported, because a browser will not reinterpret it",
        ],
        false_positives=[
            "Responses whose content type browsers do not sniff are skipped; reporting them would inflate the count without describing anything exploitable.",
            "Presence alone is not the test: the value must establish the policy.",
            "This is a defence-in-depth gap, not a demonstrated exploit; severity reflects a missing protection.",
        ],
        vulnerable="labs-bad returns HTML and JSON without X-Content-Type-Options",
        fixed="labs-good sends X-Content-Type-Options: nosniff",
        applicability="Applies to successful responses whose content type a browser might reinterpret.",
        not_applicable_when="No successful response was collected, which is unassessed rather than clean.",
    ),
    entry(
        check_id="SL-C04-REFERRER-01",
        title="Referrer-Policy is missing, so the browser default decides cross-origin leakage",
        canonical="browser.referrer_policy.present",
        root_cause="referrer-policy-absent",
        category="C04",
        wstg=[],
        cwe=["CWE-200"],
        stance="OBSERVE",
        family="F33",
        signal="An HTTPS HTML response carries no Referrer-Policy header.",
        confirmation=(
            "Confirmed when the header is absent from a response the scanner collected over "
            "TLS from the origin and stored as evidence."
        ),
        negatives=[
            "labs-good sends Referrer-Policy: no-referrer and must produce no finding",
            "the check does not follow a link to observe a Referer header; it reads the policy",
        ],
        false_positives=[
            "A policy may legitimately be set by a reverse proxy rather than the application; the finding describes the observed response.",
            "Some policies leak more than others; this control reports absence and does not rank the values.",
        ],
        vulnerable="labs-bad sends no Referrer-Policy header",
        fixed="labs-good sends Referrer-Policy: no-referrer",
        applicability="Applies to HTML responses collected over TLS from the scope origin.",
        not_applicable_when="No HTTPS HTML response was collected, which is unassessed rather than clean.",
    ),
    entry(
        check_id="SL-C05-ERRORS-01",
        title="A response body discloses a stack trace or framework error page",
        canonical="exposure.verbose_error_disclosure",
        root_cause="verbose-error-disclosure",
        category="C05",
        wstg=["WSTG-ERRH-01", "WSTG-ERRH-02"],
        cwe=["CWE-209", "CWE-211"],
        stance="OBSERVE",
        family="F35",
        signal="A collected response body contains a signature of a thrown error or stack trace: a Python traceback, a Java stack frame, a PHP notice, a framework exception page.",
        confirmation=(
            "Confirmed when a signature is matched in the body of a response the scanner "
            "collected and stored as evidence. The finding reports that internal detail is "
            "disclosed, not an inferred exploit."
        ),
        negatives=[
            "labs-bad serves a fabricated traceback at /error-debug.html, which must be found",
            "labs-good serves no such page, and its 404 body must not match any signature",
        ],
        false_positives=[
            "Documentation that legitimately quotes a stack trace is a false positive; the signatures are framework-shaped rather than generic.",
            "Generating an unusual error to provoke a traceback is a reviewed check, not part of this OBSERVE control.",
        ],
        vulnerable="labs-bad serves /error-debug.html containing a fabricated Python traceback",
        fixed="labs-good returns 404 for that path and discloses no internal detail",
        applicability="Applies to every response body collected during the crawl.",
        not_applicable_when="No response body was collected, which is unassessed rather than clean.",
    ),
    entry(
        check_id="SL-C05-LISTING-01",
        title="A directory renders an index of its contents",
        canonical="exposure.directory_listing",
        root_cause="directory-listing-enabled",
        category="C05",
        wstg=["WSTG-CONF-02"],
        cwe=["CWE-548"],
        stance="OBSERVE",
        family="F34",
        signal="A successful HTML response renders a directory index: an 'Index of /' title or heading, Apache's autoindex table, or an IIS directory listing.",
        confirmation=(
            "Confirmed when index markup is matched in the body of a 200 response the scanner "
            "collected. No recursive download is performed: the finding is that the directory "
            "is listable, not an inventory of what is in it."
        ),
        negatives=[
            "labs-bad serves a listable /files/ and must be found",
            "labs-good returns 404 for /files/ and must produce no finding",
        ],
        false_positives=[
            "A page that merely lists file names in prose is not an autoindex; the signatures are specific to generated listings.",
            "Recursive enumeration of a listed directory is prohibited by Spec §10.3 and is not performed.",
        ],
        vulnerable="labs-bad enables autoindex on /files/",
        fixed="labs-good disables autoindex and returns 404",
        applicability="Applies to successful HTML responses collected during the crawl.",
        not_applicable_when="No successful HTML response was collected, which is unassessed rather than clean.",
    ),
    entry(
        check_id="SL-C05-FILES-01",
        title="A well-known sensitive path is served to any visitor",
        canonical="exposure.sensitive_files",
        root_cause="sensitive-file-exposed",
        category="C05",
        wstg=["WSTG-CONF-03", "WSTG-CONF-04"],
        cwe=["CWE-538", "CWE-552"],
        stance="ACTIVE",
        family="F36",
        signal="One of a fixed, bounded set of sensitive paths (/.env, /backup.sql, /.git/config) returns 200 with a body where it should return 404.",
        confirmation=(
            "Confirmed when a path in the bounded set answers 200 with a body. The evidence is "
            "the response metadata — status, size, content type — and never the file's "
            "contents: Spec §10.3 prohibits repository reconstruction, bulk download and use "
            "of any discovered credential."
        ),
        negatives=[
            "labs-bad serves /.env, /backup.sql and /.git/config and all three must be found",
            "labs-good returns 404 for each of them and must produce no finding",
        ],
        false_positives=[
            "A path that returns a styled 404 page with status 200 would be a false positive; the recorded evidence lets a reviewer see the status and size.",
            "The probe set is fixed and small. It is a bounded check, not content discovery, and a path absent from it is not evidence of anything.",
        ],
        vulnerable="labs-bad serves /.env, /backup.sql and /.git/config with HTTP 200",
        fixed="labs-good returns 404 for all three",
        applicability="Applies to any scope origin; the paths are probed once each during the crawl.",
        not_applicable_when="None of the bounded probes produced a response, which is unassessed rather than clean.",
        max_requests=3,
        expectations="three GET requests to fixed well-known paths; no state change",
    ),
    entry(
        check_id="SL-C05-SECRETS-01",
        title="Delivered client-side content contains a value shaped like a private credential",
        canonical="exposure.client_side_secret_candidates",
        root_cause="client-side-secret-candidate",
        category="C05",
        wstg=["WSTG-INFO-05"],
        cwe=["CWE-540", "CWE-798"],
        stance="FLAG",
        family="F37",
        signal="Delivered JavaScript or HTML contains a value shaped like a private credential: an OpenAI-style key, an AWS access key id, a GitHub token, a private key block or a JWT.",
        confirmation=(
            "Never confirmed by this profile. Spec §10.5 gives this family the FLAG stance, and "
            "Spec §10.2 requires distinguishing a public client identifier from private "
            "material. The control therefore reports a candidate and holds the overall score "
            "at Verification pending rather than asserting a leak."
        ),
        negatives=[
            "labs-bad delivers a value shaped like a private key, which must appear as a candidate",
            "labs-good delivers only a publishable key, which must produce no finding at all",
        ],
        false_positives=[
            "A revoked, example or test key has the same shape as a live one; shape matching cannot tell them apart.",
            "Spec §10.2 forbids authenticating with a discovered credential, so the ambiguity is reported rather than resolved.",
            "A document containing a recognised public identifier alongside a private-shaped one is treated as possibly a key pair and reported at low confidence.",
        ],
        vulnerable="labs-bad delivers fixture-files/app-secrets.js containing an sk-shaped value",
        fixed="labs-good delivers app-config.js containing only a publishable pk_test_ key",
        applicability="Applies to delivered JavaScript and HTML collected during the crawl.",
        not_applicable_when="No delivered script or HTML was collected, which is unassessed rather than clean.",
    ),
    entry(
        check_id="SL-C06-COMPONENT-01",
        title="The origin discloses exact component versions to every visitor",
        canonical="components.version_disclosure",
        root_cause="component-version-disclosed",
        category="C06",
        wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
        cwe=["CWE-200"],
        stance="OBSERVE",
        family="F43",
        signal="A fingerprinted component carries an exact version in a Server or X-Powered-By header, or in a body signature.",
        confirmation=(
            "Never confirmed: this profile has no vulnerability data source, so CVE "
            "applicability cannot be corroborated. The control reports an informational "
            "candidate — that a version is disclosed — and Spec §10.2 forbids confirming "
            "applicability from a banner alone."
        ),
        negatives=[
            "labs-bad sends Server: nginx/1.27.5, which must produce a candidate",
            "labs-good sends Server: nginx with no version, which must produce no finding",
        ],
        false_positives=[
            "A disclosed version is not a vulnerable version. Reporting it as one would be the single easiest way to fabricate a finding.",
            "Vendor backports mean even an exact version match would not establish applicability without an advisory source.",
        ],
        vulnerable="labs-bad discloses nginx/1.27.5 in the Server header",
        fixed="labs-good discloses no version in the Server header",
        applicability="Applies to every response collected during the crawl.",
        not_applicable_when="No component could be fingerprinted from the collected responses.",
        mandatory=False,
    ),
    entry(
        check_id="SL-C07-METHODS-01",
        title="The origin advertises HTTP methods beyond those an ordinary page needs",
        canonical="api.http_method_exposure",
        root_cause="unusual-http-methods-advertised",
        category="C07",
        wstg=["WSTG-CONF-06"],
        cwe=["CWE-200"],
        stance="OBSERVE",
        family="F39",
        signal="A response's Allow header advertises a method outside GET, HEAD, OPTIONS and POST.",
        confirmation=(
            "Never confirmed. Spec §10.2 and F39 are explicit that an advertised method is not "
            "a flaw: proving support would mean invoking it, and destructive verbs are not "
            "invoked to see whether they work. The control reports an informational candidate."
        ),
        negatives=[
            "labs-bad advertises PUT, DELETE and OPTIONS, which must appear as a candidate",
            "labs-good advertises only GET and HEAD, which must produce no finding",
        ],
        false_positives=[
            "PUT and DELETE are legitimate API methods; their advertisement is inventory, not a weakness.",
            "No destructive verb is ever sent: the control reads the advertised list and stops.",
        ],
        vulnerable="labs-bad sends Allow: GET, HEAD, PUT, DELETE, OPTIONS",
        fixed="labs-good sends Allow: GET, HEAD",
        applicability="Applies to any collected response carrying an Allow header.",
        not_applicable_when="No response advertised an Allow header, in which case the control passes with that stated basis.",
        mandatory=False,
    ),
    entry(
        check_id="SL-C07-INVENTORY-01",
        title="Same-origin API surface is enumerated and recorded as inventory",
        canonical="api.same_origin_inventory",
        root_cause="api-surface-not-enumerated",
        category="C07",
        wstg=["WSTG-INFO-07"],
        cwe=[],
        stance="OBSERVE",
        family="F16",
        signal="The crawl enumerated the same-origin routes, and the API-shaped subset is recorded.",
        confirmation=(
            "This control's claim is about coverage, not weakness. It passes when the "
            "same-origin route set was enumerated and recorded — a verifiable statement about "
            "what was looked at. It raises nothing, and its summary says so, because an "
            "unevaluated API is not a secure one."
        ),
        negatives=[
            "both fixtures serve /api, so both must enumerate at least one API-shaped route",
            "a crawl that enumerated no routes must be inconclusive, not a pass",
        ],
        false_positives=[
            "Discovering an API route is not finding a broken authorization check, and this unauthenticated profile has no identity with which to test one.",
            "The route list belongs in the endpoint inventory; turning discovery into a finding is the conflation Spec §10.2 warns about.",
        ],
        vulnerable="labs-bad serves /api, which must appear in the inventory",
        fixed="labs-good serves /api, which must appear in the inventory",
        applicability="Applies whenever the crawl enumerated at least one route.",
        not_applicable_when="The crawl enumerated no routes, in which case the API surface is unknown rather than clean.",
        max_requests=0,
    ),
]


# Reviewed corrections from the M2 audit. These overrides are part of the generated contract.
for control in ENTRIES:
    cid = control["id"]
    if cid == "SL-C01-TLS-01":
        control["title"] = "TLS certificate validation, expiry and legacy protocol support"
        control["detection"]["signal"] = (
            "The trusted TLS lane verifies chain, host and validity at capture time, and separately offers TLS 1.0 and 1.1."
        )
        control["detection"]["confirmation_criteria"] = (
            "Recorded verification failure, expiry/near-expiry, or an accepted legacy handshake. Missing measurements remain unassessed."
        )
        control["detection"]["false_positive_considerations"] = [
            "Lab measurements use the explicit fixture CA; production uses the system trust store.",
            "An inconclusive legacy handshake cannot prove rejection.",
        ]
        control["fixtures"]["vulnerable"] += (
            "; tests/unit/test_m2_tls.py covers expired, future and wrong-host certificates"
        )
    elif cid == "SL-C01-REDIR-01":
        control["applicability"]["not_applicable_when"] = (
            "Missing HTTP authorization is NOT_TESTED, never N/A. A separately approved transport_http_port permits one GET /, without following redirects."
        )
        control["detection"]["false_positive_considerations"] = [
            "Only a redirect to the approved HTTPS host and port passes. Errors and unrelated redirects are inconclusive."
        ]
        control["allowed_action"]["destinations"] = (
            "Separately approved transport-only HTTP port on the same host"
        )
    elif cid == "SL-C05-FILES-01":
        control["detection"]["confirmation_criteria"] = (
            "Nonempty non-HTML file-specific content at a reviewed path, distinct from the captured negative-control response. Record each required path; missing, blocked or truncated instances cannot complete coverage."
        )
        control["detection"]["negative_controls"] += [
            "tests/unit/test_m2_controls.py: empty 200, HTML soft 404, missing and blocked paths"
        ]
    elif cid == "SL-C04-CSP-01":
        control["detection"]["confirmation_criteria"] = (
            "Effective enforcing policies must restrict script source and inline execution. Evaluate repeated policies as intersections and first duplicate directive wins; report-only is insufficient."
        )
    elif cid == "SL-C04-FRAME-01":
        control["detection"]["confirmation_criteria"] = (
            "Restrictive enforcing frame-ancestors, or valid DENY/SAMEORIGIN XFO when no enforcing frame-ancestors overrides it. Wildcard ancestors are not protection."
        )
    elif cid == "SL-C06-COMPONENT-01":
        control["title"] = "Observed component version matches an advisory candidate"
        control["detection"]["signal"] = (
            "Fingerprint version matches a record in the operator-configured, hashed OSV snapshot."
        )
        control["detection"]["confirmation_criteria"] = (
            "Never confirmed from a banner. An advisory match remains Potential until exact build and applicability are corroborated. No bundle, unknown version or unsupported range means unassessed."
        )
        control["detection"]["negative_controls"] = [
            "tests/unit/test_m2_advisories.py: affected and fixed versions, absent feed, unknown version, unsupported range"
        ]
        control["fixtures"] = {
            "vulnerable": "tests/unit/test_m2_advisories.py synthetic affected-version snapshot",
            "fixed": "tests/unit/test_m2_advisories.py fixed-version counterpart; synthetic IDs never represent real CVEs",
            "verified": True,
        }
        control["applicability"]["not_applicable_when"] = (
            "Unknown component/version or unavailable advisory corpus remains unassessed."
        )
        control["prerequisites"]["notes"] = (
            "SCOPELENS_ADVISORY_BUNDLE_FILE; snapshot version, source, records and hash frozen per scan"
        )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for data in ENTRIES:
        path = OUT / f"{data['id']}.yaml"
        header = (
            "# Check registry entry generated by scripts/gen_registry_entries.py.\n"
            "# Edit the generator or this file, but keep the two in step: the registry is\n"
            "# validated on load and an entry that drifts from its implementation fails a test.\n"
        )
        path.write_text(
            header + yaml.safe_dump(data, sort_keys=False, default_flow_style=False, width=100),
            encoding="utf-8",
        )
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
