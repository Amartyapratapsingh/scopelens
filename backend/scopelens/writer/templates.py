"""Static report text per control (Build Plan §5.16).

    Text fields (title/what/why/fix/references) come from a static template per control
    **always**; if a model is configured, it may rephrase into plainer English ... The model
    can never change severity, control, locations, coverage or scores.

This module is that static template. It is the source of the report's prose for every control,
which means the report is complete and correct with no model configured at all — the M4
addition can only rephrase what is already here.

Two rules from the specification are applied in the writing itself:

* Spec §2.1: no weaponized payloads. The text explains *what* is wrong and *how to fix it*;
  it never contains a copy-pasteable exploit string.
* Spec §9.2: the finding schema is what a non-specialist reads, so `why` is written in
  business terms and `fix` is concrete rather than a restatement of the weakness.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ControlText:
    what: str
    why: str
    fix: str
    references: tuple[str, ...] = ()


#: Keyed by check id. Every id in the registry must appear here — a test asserts it, because a
#: missing template would render an empty finding rather than an error.
CONTROL_TEXT: dict[str, ControlText] = {
    "SL-C01-TLS-01": ControlText(
        what=(
            "The certificate the site presents over HTTPS is not one a browser would accept: "
            "it is self-signed, has expired or is close to expiring, or the connection "
            "negotiated a protocol version that current browsers have removed."
        ),
        why=(
            "Visitors see a full-page security warning before they reach the site, and many "
            "will leave rather than click through. Where the connection is still usable, the "
            "traffic is protected by a weaker mechanism than the site appears to offer."
        ),
        fix=(
            "Install a certificate from a publicly trusted certificate authority covering "
            "every hostname the site serves, renew it automatically, and disable protocol "
            "versions below TLS 1.2."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C01-REDIR-01": ControlText(
        what=(
            "The site answers requests made over plain HTTP with a normal page instead of "
            "redirecting the visitor to the secure HTTPS address."
        ),
        why=(
            "Anything a visitor sends on that first request — including a password or a "
            "session cookie — travels unencrypted and can be read or altered by anyone on "
            "the same network."
        ),
        fix=(
            "Redirect every HTTP request to its HTTPS equivalent with a permanent redirect, "
            "and make sure the address the site advertises in links and emails is the HTTPS one."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C01-HSTS-01": ControlText(
        what=(
            "The site does not send the Strict-Transport-Security header, or sends one whose "
            "policy does not take effect."
        ),
        why=(
            "Without it, a visitor's first request in a session can be intercepted and "
            "downgraded to plain HTTP. The protection the redirect provides can be bypassed "
            "on that first request."
        ),
        fix=(
            "Send Strict-Transport-Security with a long max-age — a year is typical — and "
            "includeSubDomains once every subdomain is served over HTTPS."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C01-MIXED-01": ControlText(
        what=(
            "An HTTPS page loads a script or stylesheet over plain HTTP, so part of the page "
            "is fetched insecurely."
        ),
        why=(
            "The insecure resource can be replaced in transit by anyone on the same network, "
            "and it runs as part of the page. The padlock tells the visitor the whole page "
            "is protected, which is no longer true."
        ),
        fix=(
            "Load every subresource over HTTPS, or from the site's own origin. Where a third "
            "party only offers HTTP, replace it or serve it from the site."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C02-COOKIE-01": ControlText(
        what=(
            "A cookie that identifies a session or signs a visitor in is set without the "
            "Secure, HttpOnly or SameSite protections."
        ),
        why=(
            "Without Secure the cookie can travel over an unencrypted request. Without "
            "HttpOnly a script on the page can read it. Without SameSite the browser sends it "
            "on requests started by another site. Each of these is a route to taking over a "
            "signed-in session."
        ),
        fix=(
            "Set Secure, HttpOnly and SameSite=Lax — or Strict where the flow allows — on "
            "every session cookie. If SameSite=None is required, Secure must be set as well."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C02-COOKIE-02": ControlText(
        what=(
            "A session cookie is sent to a wider set of hosts than the application that set "
            "it, because the cookie carries a Domain attribute."
        ),
        why=(
            "Every subdomain receives the cookie, so a weakness in any one of them — an old "
            "staging host, a marketing site, a service that does not need it — becomes a "
            "route to the session on the main application."
        ),
        fix=(
            "Remove the Domain attribute so the cookie is host-only, unless several "
            "applications genuinely share the session and every one of them is equally "
            "trusted."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C04-CSP-01": ControlText(
        what=(
            "The site does not send a Content-Security-Policy, or sends one that does not "
            "restrict where scripts may come from."
        ),
        why=(
            "The policy is the browser-level backstop against injected script. Without an "
            "effective one, a single injection anywhere on the site has a clear path to "
            "running in a visitor's browser."
        ),
        fix=(
            "Send a policy that restricts script and default sources to the site's own "
            "origin, and tighten it from there. Start in report-only mode if needed, then "
            "enforce."
        ),
        references=("https://owasp.org/www-project-secure-headers/",),
    ),
    "SL-C04-FRAME-01": ControlText(
        what=(
            "The page can be embedded in a frame on another site: neither a frame-ancestors "
            "policy nor an X-Frame-Options header is present."
        ),
        why=(
            "An attacker can lay an invisible copy of the page over their own content, so a "
            "visitor's clicks land on the real site without them realising. This is how "
            "clickjacking turns a signed-in visitor into an unwitting participant."
        ),
        fix=(
            "Send Content-Security-Policy with frame-ancestors 'none', or X-Frame-Options: "
            "DENY. Either is sufficient; sending both is fine but is one control, not two."
        ),
        references=("https://owasp.org/www-project-secure-headers/",),
    ),
    "SL-C04-XCTO-01": ControlText(
        what=(
            "A response that a browser could reinterpret is served without "
            "X-Content-Type-Options: nosniff."
        ),
        why=(
            "A browser may decide a file is a different kind than the server declared. A file "
            "uploaded as an image, for example, can end up being executed as a script in the "
            "site's own origin."
        ),
        fix="Send X-Content-Type-Options: nosniff on every response.",
        references=("https://owasp.org/www-project-secure-headers/",),
    ),
    "SL-C04-REFERRER-01": ControlText(
        what="The site does not send a Referrer-Policy, so the browser default decides what is shared.",
        why=(
            "The address of the page a visitor came from is sent to the next site they visit. "
            "Where addresses contain identifiers, tokens or search terms, that information "
            "leaves the site."
        ),
        fix=(
            "Send Referrer-Policy: strict-origin-when-cross-origin, or no-referrer where no "
            "referral information is needed."
        ),
        references=("https://owasp.org/www-project-secure-headers/",),
    ),
    "SL-C05-ERRORS-01": ControlText(
        what=(
            "An error the site returns includes internal detail: a stack trace, a framework "
            "exception page, or a database error message."
        ),
        why=(
            "The detail shows how the site is built — frameworks, file paths, sometimes "
            "credentials or internal addresses. It shortens the work needed to find a way in, "
            "and it is visible to any visitor who can trigger the error."
        ),
        fix=(
            "Serve a generic error page to visitors and log the detail server-side. Turn off "
            "framework debug modes in every environment that is reachable from the internet."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C05-LISTING-01": ControlText(
        what="A directory on the site returns a browsable index of the files it contains.",
        why=(
            "Files that were never linked are listed for anyone who finds the address — "
            "backups, configuration, documents that were meant to be private. The listing "
            "does the discovery work for an attacker."
        ),
        fix="Turn directory listing off and serve an explicit index page, or return 404.",
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C05-FILES-01": ControlText(
        what=(
            "A file that should never be reachable is served to any visitor — a configuration "
            "file, a database backup or a repository control file."
        ),
        why=(
            "Files like these typically contain exactly what an attacker needs next: database "
            "credentials, API keys, or the full source history. They are often the single "
            "shortest route from outside the site to its data."
        ),
        fix=(
            "Remove the files from the web root. If they must live there, deny access to them "
            "at the web server and confirm the denial returns 404 rather than a page."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C05-SECRETS-01": ControlText(
        what=(
            "Code delivered to the browser contains a value shaped like a private credential — "
            "an API secret key or similar."
        ),
        why=(
            "Anything sent to a browser is readable by every visitor. If the value is live, it "
            "can be used to act as the site until it is revoked. This is reported as a "
            "candidate because a revoked or example key looks identical to a live one."
        ),
        fix=(
            "Confirm what the value is and revoke it if it is live. Move privileged calls "
            "behind the server so the browser only ever holds a publishable identifier."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C06-COMPONENT-01": ControlText(
        what="An observed component version matches an advisory in the configured snapshot.",
        why="The version is a candidate match. Banners may be inaccurate, and vendor backports can change applicability. This is not a confirmed vulnerability.",
        fix="Check the exact deployed build against the cited advisory and vendor fixes. Update the affected component when applicability is confirmed.",
        references=("https://ossf.github.io/osv-schema/",),
    ),
    "SL-C07-METHODS-01": ControlText(
        what=(
            "The server advertises HTTP methods beyond the ones an ordinary page needs, such "
            "as PUT or DELETE."
        ),
        why=(
            "Advertising a method is not the same as accepting it, and this report does not "
            "claim it is. The observation is listed because an endpoint that genuinely accepts "
            "write methods is worth a deliberate review."
        ),
        fix=(
            "Review whether each advertised method is needed. Disable those that are not, and "
            "confirm that any that remain are protected by authorization."
        ),
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
    "SL-C07-INVENTORY-01": ControlText(
        what=(
            "This entry records the same-origin API surface found during the crawl. It is "
            "inventory, not a finding."
        ),
        why=(
            "Knowing which API routes exist is what makes an authorization review possible. "
            "This profile does not assess authorization, because it holds no test identities, "
            "so nothing here should be read as saying the API is safe."
        ),
        fix="No action. Review the route list and confirm each endpoint is intended to be public.",
        references=("https://owasp.org/www-project-web-security-testing-guide/v42/",),
    ),
}


def text_for(check_id: str) -> ControlText:
    """The template for a control, or a placeholder that says the template is missing.

    The fallback is deliberately loud rather than silent: a finding rendered with no
    explanation would look finished, and a missing template is a defect worth seeing.
    """
    template = CONTROL_TEXT.get(check_id)
    if template is None:
        return ControlText(
            what="No report template is registered for this control.",
            why="The template is missing, so the finding cannot be explained in plain English.",
            fix="Add an entry to writer/templates.py for this control.",
        )
    return template


# Conditional active controls. These descriptions never contain executable inputs.
CONTROL_TEXT.update(
    {
        "SL-C03-XSS-01": ControlText(
            "A reflected input executed a harmless marker in the scanner-owned browser.",
            "Unescaped input in this context can let a visitor's browser run attacker-controlled script.",
            "Use context-aware output encoding, avoid unsafe HTML insertion, and enforce a restrictive CSP.",
            ("https://cwe.mitre.org/data/definitions/79.html",),
        ),
        "SL-C03-HTML-01": ControlText(
            "Reflected input created a new HTML element in the scanner-owned page.",
            "An attacker could alter page content shown to someone who opens a crafted link.",
            "Render untrusted input as text. Use an allowlist HTML sanitizer only where markup is required.",
            ("https://cwe.mitre.org/data/definitions/79.html",),
        ),
        "SL-C03-SQL-01": ControlText(
            "Two repeated true/false input comparisons matched the baseline and negative control, indicating SQL predicate evaluation.",
            "Unsafe query construction can allow an input to alter a database query. No records were extracted and no login bypass was attempted.",
            "Use parameterized queries for every input and avoid string concatenation in SQL.",
            ("https://cwe.mitre.org/data/definitions/89.html",),
        ),
        "SL-C04-REDIRECT-01": ControlText(
            "The endpoint redirected to two externally supplied marker destinations. Neither destination was followed.",
            "A crafted link could redirect a visitor from a trusted site to an attacker-selected destination.",
            "Use local relative destinations or a strict allowlist of canonical destinations.",
            ("https://cwe.mitre.org/data/definitions/601.html",),
        ),
        "SL-C04-CORS-01": ControlText(
            "The endpoint reflected two foreign Origin headers while allowing credentials.",
            "This configuration may expose credentialed responses. Protected-data exposure was not assessed in this unauthenticated scan.",
            "Allow only explicitly trusted origins and enable credentials only when the endpoint needs them.",
            ("https://cwe.mitre.org/data/definitions/942.html",),
        ),
    }
)
