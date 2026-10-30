"""The M1 read-only HTTP check, executed inside an isolated worker.

This module runs **in the worker container**, which is why it is written to a strict
rule: it reads everything it needs from the environment, writes one JSON result to its
scratch directory, and has no database, Redis or control-plane access at all. If it were
to import `scopelens.persistence` it would fail at runtime — and that is the point.

What it does: fetch the scan's target origin once, following no redirects itself, and
report what came back. What it does **not** do:

* it does not decide scope — the forward proxy does, and this process cannot bypass it
  because it has no route to the target other than the proxy
* it does not label anything confirmed — Build Plan §5.14; the output here is an
  observation, and the supervisor records it as such
* it does not retry — a retry that duplicates a target request is the caller's decision,
  made with the budget in hand

This is deliberately the *smallest* thing that exercises the whole path end to end.
ZAP, Nuclei and the crawler are M2/M3 and are not stubbed in here.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

#: Must match execution/supervisor.py::RESULT_MARKER. Duplicated rather than imported
#: because this module runs in the worker, which has no control-plane imports.
RESULT_MARKER = "SCOPELENS_RESULT "

#: The header the proxy reads to identify the scan. Must match
#: broker/mitm_addon.py::TOKEN_HEADER; duplicated because the worker cannot import from
#: the proxy's environment, and asserted equal by a contract test.
EGRESS_TOKEN_HEADER = "x-scopelens-egress"

#: Response headers worth keeping. An allowlist rather than a denylist: a header nobody
#: listed is dropped, so a target cannot smuggle a large or sensitive header into
#: evidence by inventing a name.
KEPT_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "server",
        "strict-transport-security",
        "x-content-type-options",
        "content-security-policy",
        "x-frame-options",
        "referrer-policy",
        "set-cookie",
        "location",
        "cache-control",
    }
)

#: Body excerpt kept for evidence. The full body is not needed to prove a bounded fetch
#: happened, and keeping less is the safer default.
MAX_BODY_EXCERPT = 4096


@dataclass
class FetchOutcome:
    """What the worker observed. Serialised straight to the scratch result file."""

    ok: bool
    url: str
    status_code: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_excerpt: str = ""
    body_bytes: int = 0
    truncated: bool = False
    elapsed_ms: int = 0
    error: str | None = None
    via_proxy: bool = False


def _proxy_url() -> str | None:
    return os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or None


def proxy_url_with_token(token: str) -> str | None:
    """The proxy URL with the egress token as its credential.

    The token must reach the proxy on the **CONNECT** request, not only on the inner one,
    because the proxy has to decide whether to open a tunnel *before* any bytes are sent —
    the inner headers do not exist yet, and a tunnel carrying raw TCP would never produce
    an inner request at all. `Proxy-Authorization` is the only header a client can set on
    CONNECT without special support: httpx derives it from the proxy URL's userinfo.

    Built here rather than read from `HTTPS_PROXY` so the token is not also sitting in the
    environment, where it would be visible to anything that can read the process
    environment and would appear in proxy URLs echoed by error messages.
    """
    from urllib.parse import quote, urlsplit, urlunsplit

    base = _proxy_url()
    if not base:
        return None
    parts = urlsplit(base if "://" in base else f"http://{base}")
    if not parts.hostname:
        return None
    netloc = f"{quote(token, safe='')}:@{parts.hostname}"
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme or "http", netloc, "", "", ""))


def scrub(text: str, secret: str) -> str:
    """Remove a secret from a string that may be logged or stored as evidence.

    httpx and httpcore include the proxy URL in some error messages, and that URL carries
    the token. Evidence is stored and shown to a human, so an unscrubbed error would put a
    live capability into the very artifact the product is built to keep clean.
    """
    if secret and secret in text:
        return text.replace(secret, "[redacted]")
    return text


def _ca_bundle() -> str | bool:
    """Where the proxy's CA lives, from the worker's point of view.

    The certificate arrives as PEM content in the environment and is written into this
    container's own tmpfs. The worker has a read-only root filesystem and no host mounts,
    so there is nowhere else to put it — and writing it locally is preferable to trusting
    the system store, because only the proxy's identity should be trusted here.
    """
    pem = os.environ.get("SCOPELENS_PROXY_CA_PEM", "")
    if pem:
        target = Path("/tmp/proxy-ca.pem")
        target.write_text(pem, encoding="utf-8")
        return str(target)

    path = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    return path if path and Path(path).exists() else True


def run_fetch(url: str, *, timeout: float, max_redirects: int = 5) -> FetchOutcome:
    """Perform one bounded, read-only GET through the mandatory proxy."""
    import httpx

    token = os.environ.get("SCOPELENS_EGRESS_TOKEN", "")
    if not token:
        # Fail closed and say why. Without the token the proxy denies every request, so
        # proceeding would produce a confusing 403 that looks like a policy decision.
        return FetchOutcome(
            ok=False,
            url=url,
            reason="no_egress_token",
            error=(
                "SCOPELENS_EGRESS_TOKEN is not set; the broker admits only identified "
                "scans, so no request was attempted"
            ),
        )

    proxy = proxy_url_with_token(token)
    if proxy is None:
        # Fail closed. Without a proxy there is no policy broker, and a worker that
        # silently falls back to a direct connection has bypassed the scope boundary.
        return FetchOutcome(
            ok=False,
            url=url,
            reason="no_proxy_configured",
            error=(
                "HTTP(S)_PROXY is not set in the worker environment; refusing to make a "
                "direct connection to a target"
            ),
        )

    import time

    started = time.monotonic()
    try:
        with httpx.Client(
            proxy=proxy,
            verify=_ca_bundle(),
            timeout=timeout,
            follow_redirects=False,
            headers={
                "user-agent": "ScopeLens/0.2 (+authorized assessment)",
                # Identifies the scan to the broker. Without it the proxy denies the
                # request, which is the intended behaviour rather than a bug.
                EGRESS_TOKEN_HEADER: token,
            },
        ) as client:
            response = client.get(url)
    except httpx.HTTPError as exc:
        return FetchOutcome(
            ok=False,
            url=url,
            reason="transport_error",
            error=scrub(f"{exc.__class__.__name__}: {exc}", token),
            elapsed_ms=int((time.monotonic() - started) * 1000),
            via_proxy=True,
        )

    raw = response.content
    excerpt = raw[:MAX_BODY_EXCERPT]

    return FetchOutcome(
        ok=200 <= response.status_code < 400,
        url=str(response.url),
        status_code=response.status_code,
        reason="fetched",
        headers={
            key.lower(): value
            for key, value in response.headers.items()
            if key.lower() in KEPT_HEADERS
        },
        body_excerpt=excerpt.decode("utf-8", "replace"),
        body_bytes=len(raw),
        truncated=len(raw) > MAX_BODY_EXCERPT,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        via_proxy=True,
    )


def emit_result(outcome: FetchOutcome) -> None:
    """Print the result on a marked line the supervisor parses.

    Exactly one such line is printed, and it goes to stdout because that is the only
    channel the supervisor can read back from a container without sharing a filesystem.
    The marker lets the supervisor tell the declared result apart from any other output,
    which it records separately as an untrusted observation.
    """
    print(RESULT_MARKER + json.dumps(asdict(outcome), sort_keys=True), flush=True)


def main(argv: list[str] | None = None) -> int:
    del argv

    url = os.environ.get("SCOPELENS_TARGET_URL", "")
    timeout = float(os.environ.get("SCOPELENS_TASK_TIMEOUT", "10"))

    if not url:
        emit_result(FetchOutcome(ok=False, url="", reason="no_target_url"))
        print("worker: SCOPELENS_TARGET_URL is not set", file=sys.stderr)
        return 2

    outcome = run_fetch(url, timeout=timeout)
    emit_result(outcome)
    return 0 if outcome.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
