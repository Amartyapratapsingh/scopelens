"""Scoped breadth-first HTTP crawler (Build Plan §5.7).

Runs **inside the worker container**, which is why it reads its configuration from the
environment and holds no database or control-plane access. Every request it makes goes
through the mandatory forward proxy, so the broker decides each one individually — the
crawler's own scope filtering is an efficiency measure, not the enforcement point, and it is
written so that being wrong about scope costs requests rather than violating anything.

What it collects: endpoints, forms, form inputs, query parameters, cookies and headers, plus
a bounded well-known-file probe. It is bounded in pages, depth, body size and wall clock, and
it records **which limit stopped it** rather than reporting a truncated crawl as complete.

What it deliberately does not do:

* **No form submission.** Spec §12 blocks unapproved state changes, and v1 is the
  unauthenticated profile. Forms are recorded as surface, never exercised.
* **No disallowed-only paths.** Paths seen only inside a ``Disallow`` directive are recorded
  as inventory and never fetched (§5.7). Paths from the well-known wordlist *are* fetched,
  because that probe is a reviewed bounded check rather than opportunistic crawling.
* **No cross-origin fetches.** A discovered host is inventoried and reported as a coverage
  gap, never requested (Spec §7.2).
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlsplit

from scopelens.domain.collection import CollectedResponse
from scopelens.domain.surface import (
    AttackSurfaceMap,
    Classification,
    CrawlStats,
    EndpointRecord,
    FormInputRecord,
    FormRecord,
    HostRecord,
    ParameterRecord,
    TechFingerprint,
    normalize_route,
)

#: Bounded well-known-file probe (§7.1). Small on purpose: this surfaces unlinked content,
#: it is not a content-discovery wordlist, and every entry is a request spent.
WELL_KNOWN_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.env",
    "/backup.sql",
    "/.git/config",
    "/admin",
    "/debug",
    "/api",
    "/openapi.json",
    "/swagger.json",
    "/graphql",
)

#: Content types whose body is worth keeping an excerpt of. Anything else (images, fonts,
#: media) is recorded by status and headers only — collecting it would spend the body budget
#: on bytes no check reads.
TEXTUAL_CONTENT_MARKERS = ("text/", "json", "javascript", "xml", "ecmascript")

#: Header allowlist, matching the worker's existing convention: an unlisted header is
#: dropped, so a target cannot smuggle something large or sensitive into evidence by
#: inventing a name.
KEPT_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "server",
        "x-powered-by",
        "strict-transport-security",
        "x-content-type-options",
        "content-security-policy",
        "content-security-policy-report-only",
        "x-frame-options",
        "referrer-policy",
        "set-cookie",
        "location",
        "cache-control",
        "pragma",
        "permissions-policy",
        "x-aspnet-version",
        "x-generator",
        "via",
        "x-cache",
        "cf-cache-status",
        "x-served-by",
        "allow",
        "access-control-allow-origin",
    }
)

#: Values that look like an inline secret in delivered JavaScript. Classification is a
#: candidate only: Spec §10.2 requires distinguishing a public client identifier from private
#: material, and this list exists to *find candidates*, never to authenticate with one.
SECRET_NAME_HINTS = (
    "api_key",
    "apikey",
    "api-key",
    "secret",
    "token",
    "password",
    "passwd",
    "private_key",
    "access_key",
    "client_secret",
)


@dataclass
class CrawlConfig:
    """Everything the crawl needs, read from the environment by :func:`config_from_env`."""

    origin: str
    scheme: str
    host: str
    port: int
    max_pages: int
    max_depth: int
    timeout: float
    max_body_bytes: int
    user_agent: str
    allowed_path_prefixes: tuple[str, ...] = ("/",)
    excluded_paths: tuple[str, ...] = ()
    transport_http_port: int | None = None
    max_redirects: int = 5
    retest_routes: tuple[str, ...] = ()
    max_duration_seconds: float = 120.0
    hard_duration_seconds: float | None = None
    entry_path: str = "/"

    def entry_url(self) -> str:
        """Choose a canonical seed inside the declared application scope."""
        from scopelens.scope.paths import canonical_path

        prefixes = tuple(canonical_path(path) for path in self.allowed_path_prefixes)
        excluded = tuple(canonical_path(path) for path in self.excluded_paths)

        def under(path, prefix):
            return path == prefix or path.startswith(prefix.rstrip("/") + "/")

        for candidate in (self.entry_path, "/", *sorted(prefixes, key=lambda p: (len(p), p))):
            path = canonical_path(candidate)
            if any(under(path, prefix) for prefix in prefixes) and not any(
                under(path, prefix) for prefix in excluded
            ):
                return self.origin + path
        raise ValueError("scope has no permitted entry path")


@dataclass
class CrawlResult:
    surface: AttackSurfaceMap
    responses: list[CollectedResponse] = field(default_factory=list)
    unreachable: dict[str, str] = field(default_factory=dict)
    cleartext_probe: CollectedResponse | None = None


@dataclass
class _FrontierItem:
    url: str
    depth: int
    via: str
    source: str | None


def config_from_env() -> CrawlConfig:
    """Build a config from the worker environment. Raises if the target is missing."""
    target = os.environ.get("SCOPELENS_TARGET_URL", "")
    if not target:
        raise RuntimeError("SCOPELENS_TARGET_URL is not set")

    parts = urlsplit(target)
    return CrawlConfig(
        origin=f"{parts.scheme}://{parts.netloc}",
        entry_path=parts.path or "/",
        scheme=parts.scheme,
        host=parts.hostname or "",
        port=parts.port or (443 if parts.scheme == "https" else 80),
        max_pages=int(os.environ.get("SCOPELENS_MAX_PAGES", "300")),
        max_depth=int(os.environ.get("SCOPELENS_MAX_DEPTH", "4")),
        timeout=float(os.environ.get("SCOPELENS_TASK_TIMEOUT", "10")),
        max_duration_seconds=float(os.environ.get("SCOPELENS_CRAWL_TIMEOUT", "120")),
        hard_duration_seconds=float(os.environ["SCOPELENS_COLLECTION_TIMEOUT"]) * 0.7
        if os.environ.get("SCOPELENS_COLLECTION_TIMEOUT")
        else None,
        max_body_bytes=int(os.environ.get("SCOPELENS_MAX_BODY_BYTES", str(1024 * 1024))),
        user_agent=os.environ.get("SCOPELENS_USER_AGENT", "ScopeLens/0.2 (+authorized assessment)"),
        allowed_path_prefixes=tuple(
            p for p in os.environ.get("SCOPELENS_ALLOWED_PREFIXES", "/").split(",") if p
        ),
        excluded_paths=tuple(
            p for p in os.environ.get("SCOPELENS_EXCLUDED_PATHS", "").split(",") if p
        ),
        transport_http_port=int(os.environ["SCOPELENS_TRANSPORT_HTTP_PORT"])
        if os.environ.get("SCOPELENS_TRANSPORT_HTTP_PORT")
        else None,
        retest_routes=tuple(json.loads(os.environ.get("SCOPELENS_RETEST_ROUTES", "[]"))),
    )


class Crawler:
    """A bounded, same-origin BFS crawl."""

    def __init__(self, config: CrawlConfig, *, client=None) -> None:  # type: ignore[no-untyped-def]
        self.config = config
        self._client = client
        self._visited: set[str] = set()
        self._responses: list[CollectedResponse] = []
        self._unreachable: dict[str, str] = {}
        self._endpoints: list[EndpointRecord] = []
        self._parameters: list[ParameterRecord] = []
        self._forms: list[FormRecord] = []
        self._tech: list[TechFingerprint] = []
        self._hosts: dict[str, HostRecord] = {}
        self._classification = Classification()
        self._disallowed_only: set[str] = set()
        self._robots_entries: list[str] = []
        self._stats = CrawlStats()
        self._started = time.monotonic()
        self._duration = config.max_duration_seconds
        self._extensions = 0

    def _remaining_time(self) -> float:
        elapsed = time.monotonic() - self._started
        hard = self.config.hard_duration_seconds or self.config.max_duration_seconds
        # Continue the existing frontier in small slices, without repeating visited
        # URLs. This cannot extend the process/scan cap or authorize another request.
        if elapsed >= self._duration and self._duration < hard and self._stats.errors < 3:
            self._duration = min(hard, max(elapsed, self._duration) + 30)
            self._extensions += 1
        return min(self._duration, hard) - elapsed

    # --- HTTP ------------------------------------------------------------------------

    def _http(self):  # type: ignore[no-untyped-def]
        if self._client is None:
            import httpx

            from scopelens.checks.fetch_origin import EGRESS_TOKEN_HEADER

            token = os.environ.get("SCOPELENS_EGRESS_TOKEN", "")
            if not token:
                raise RuntimeError("SCOPELENS_EGRESS_TOKEN is not set; refusing to crawl")

            self._client = httpx.Client(
                proxy=self._proxy_url(),
                verify=self._ca_bundle(),
                timeout=self.config.timeout,
                follow_redirects=False,
                headers={
                    "user-agent": self.config.user_agent,
                    # The proxy reads this on the CONNECT *and* on every inner request. The
                    # CONNECT token identifies the scan; this one is what authorizes each
                    # individual request on its own method, path and budget. Sending only the
                    # former means every request is denied with `missing_egress_token`.
                    EGRESS_TOKEN_HEADER: token,
                },
            )
        return self._client

    def _proxy_url(self) -> str:  # pragma: no cover - exercised in the container
        from scopelens.checks.fetch_origin import proxy_url_with_token

        token = os.environ.get("SCOPELENS_EGRESS_TOKEN", "")
        proxy = proxy_url_with_token(token)
        if proxy is None:
            raise RuntimeError("no proxy configured; refusing to crawl a target directly")
        return proxy

    def _ca_bundle(self) -> str | bool:  # pragma: no cover - exercised in the container
        from scopelens.checks.fetch_origin import _ca_bundle

        return _ca_bundle()

    def fetch(
        self, url: str, *, route: str | None = None, follow_redirects: bool = True
    ) -> CollectedResponse | None:
        """Follow bounded same-scope redirects; each hop is separately brokered."""
        initial_route = route or normalize_route(urlsplit(url).path)
        chain: list[str] = []
        seen: set[str] = set()
        for _ in range(self.config.max_redirects + 1):
            if not self._in_scope(url) or self._excluded(urlsplit(url).path or "/"):
                self._unreachable[initial_route] = "redirect or request outside scope"
                self._record_host(url, "redirect destination")
                return None
            if url in seen:
                self._unreachable[initial_route] = "redirect loop"
                return None
            seen.add(url)
            response = self._fetch_once(url)
            if response is None:
                self._unreachable.setdefault(initial_route, "redirect destination unreachable")
                return None
            if not follow_redirects or response.status not in {301, 302, 303, 307, 308}:
                return response.model_copy(update={"redirect_chain": tuple(chain)})
            location = response.header("location")
            if not location:
                self._unreachable[initial_route] = "redirect missing Location"
                return None
            url = urljoin(url, location)
            chain.append(url)
        self._unreachable[initial_route] = "redirect limit reached"
        return None

    def _fetch_once(self, url: str, *, route: str | None = None) -> CollectedResponse | None:
        """One GET through the broker. Returns None when the request could not be made.

        A refusal is recorded rather than retried: the broker's answer is the answer, and
        retrying a denied path would be an attempt to get around the scope boundary.
        """
        import httpx

        remaining = self._remaining_time()
        if remaining <= 0:
            self._unreachable[route or normalize_route(urlparse(url).path)] = (
                "crawl time budget exhausted"
            )
            return None
        try:
            with self._http().stream(
                "GET", url, follow_redirects=False, timeout=min(self.config.timeout, remaining)
            ) as response:
                chunks = bytearray()
                for chunk in response.iter_bytes():
                    if self._remaining_time() <= 0:
                        self._unreachable[route or normalize_route(urlparse(url).path)] = (
                            "crawl time budget exhausted during response"
                        )
                        return None
                    chunks.extend(chunk[: self.config.max_body_bytes + 1 - len(chunks)])
                    if len(chunks) > self.config.max_body_bytes:
                        break
                body = bytes(chunks)
        except httpx.HTTPError as exc:
            self._unreachable[route or normalize_route(urlparse(url).path)] = (
                f"transport error: {exc.__class__.__name__}"
            )
            self._stats = self._stats.model_copy(update={"errors": self._stats.errors + 1})
            return None

        self._stats = self._stats.model_copy(
            update={"requests_made": self._stats.requests_made + 1}
        )

        if response.status_code == 403 and self._looks_like_broker_denial(body):
            self._unreachable[route or normalize_route(urlparse(url).path)] = (
                "refused by the policy broker"
            )
            return None

        excerpt, truncated = _excerpt(body, self.config.max_body_bytes)

        recorded = CollectedResponse(
            url=str(response.url),
            route=route or normalize_route(urlparse(str(response.url)).path),
            status=response.status_code,
            headers={
                key.lower(): value
                for key, value in response.headers.items()
                if key.lower() in KEPT_HEADERS
            },
            header_values={
                key: tuple(response.headers.get_list(key))
                for key in KEPT_HEADERS
                if key != "set-cookie"
            },
            content_type=response.headers.get("content-type"),
            set_cookie=tuple(response.headers.get_list("set-cookie")),
            body_excerpt=excerpt,
            body_bytes=len(body),
            truncated=truncated,
            via_proxy=True,
        )
        self._responses.append(recorded)
        return recorded

    @staticmethod
    def _looks_like_broker_denial(body: bytes) -> bool:
        """Distinguish a scope denial from a target's own 403.

        The broker returns a JSON body with a known shape. Without this check a target that
        legitimately answers 403 would be recorded as a policy refusal — and, worse, a
        policy refusal could be mistaken for an application behaviour worth reporting.
        """
        try:
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False
        return isinstance(payload, dict) and payload.get("error") == "scope_denied"

    # --- Scope -----------------------------------------------------------------------

    def _in_scope(self, url: str) -> bool:
        parts = urlsplit(url)
        if (parts.scheme, parts.hostname, parts.port or _default_port(parts.scheme)) != (
            self.config.scheme,
            self.config.host,
            self.config.port,
        ):
            return False
        path = parts.path or "/"
        return any(
            path == prefix or path.startswith(prefix.rstrip("/") + "/")
            for prefix in self.config.allowed_path_prefixes
        )

    def _excluded(self, path: str) -> bool:
        return any(
            path == excluded or path.startswith(excluded.rstrip("/") + "/")
            for excluded in self.config.excluded_paths
        )

    def _record_host(self, url: str, evidence: str) -> None:
        """Inventory a non-primary host. Never fetched (Spec §7.2)."""
        host = urlsplit(url).hostname
        if not host or host == self.config.host or host in self._hosts:
            return
        self._hosts[host] = HostRecord(host=host, role="inventory_only", evidence=evidence)

    # --- Extraction ------------------------------------------------------------------

    def _extract(self, response: CollectedResponse) -> list[_FrontierItem]:
        """Links, forms and parameters from one response."""
        found: list[_FrontierItem] = []
        base = response.url

        for parameter in _query_parameters(base):
            self._parameters.append(
                ParameterRecord(
                    name=parameter,
                    location="query",
                    route=response.route,
                    sample=None,
                )
            )

        self._fingerprint_from_headers(response)

        if not response.is_html:
            self._classify(None, response)
            if response.is_javascript:
                self._fingerprint_from_body(response)
                self._observe_secrets(response)
            return found

        try:
            from bs4 import BeautifulSoup
        except ImportError:  # pragma: no cover - dependency is pinned
            return found

        soup = BeautifulSoup(response.body_excerpt, "html.parser")

        for anchor in soup.find_all("a", href=True):
            href = str(anchor["href"]).strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = urljoin(base, href)
            if urlsplit(absolute).hostname != self.config.host:
                self._record_host(absolute, f"linked from {response.route}")
                continue
            found.append(_FrontierItem(url=absolute, depth=0, via="link", source=response.route))

        for link in soup.find_all("link", href=True):
            absolute = urljoin(base, str(link["href"]))
            if urlsplit(absolute).hostname != self.config.host:
                self._record_host(absolute, f"subresource on {response.route}")
            elif _same_route(absolute, base) is False:
                found.append(
                    _FrontierItem(url=absolute, depth=0, via="link", source=response.route)
                )

        for script in soup.find_all("script", src=True):
            absolute = urljoin(base, str(script["src"]))
            if urlsplit(absolute).hostname != self.config.host:
                self._record_host(absolute, f"script on {response.route}")
            else:
                found.append(
                    _FrontierItem(url=absolute, depth=0, via="link", source=response.route)
                )

        for iframe in soup.find_all("iframe", src=True):
            absolute = urljoin(base, str(iframe["src"]))
            if urlsplit(absolute).hostname != self.config.host:
                self._record_host(absolute, f"iframe on {response.route}")

        for form in soup.find_all("form"):
            action = urljoin(base, str(form.get("action") or response.route))
            inputs = tuple(
                FormInputRecord(
                    name=str(field.get("name") or ""),
                    input_type=str(field.get("type") or "text"),
                    required=field.has_attr("required"),
                )
                for field in form.find_all(["input", "textarea", "select"])
                if field.get("name")
            )
            self._forms.append(
                FormRecord(
                    action=action,
                    method=str(form.get("method") or "GET").upper(),
                    inputs=inputs,
                    source_route=response.route,
                )
            )
            for form_input in inputs:
                self._parameters.append(
                    ParameterRecord(
                        name=form_input.name,
                        location="form",
                        route=normalize_route(urlparse(action).path),
                        sample=None,
                    )
                )

        self._fingerprint_from_headers(response)
        self._fingerprint_from_body(response)
        self._classify(soup, response)
        self._observe_secrets(response)
        return found

    def _fingerprint_from_headers(self, response: CollectedResponse) -> None:
        server = response.header("server")
        if server:
            self._tech.append(
                TechFingerprint(
                    name=server.split("/")[0].strip() or server,
                    version=_version_in(server),
                    evidence=f"Server header on {response.route}: {server}",
                    source="header",
                )
            )
        powered_by = response.header("x-powered-by")
        if powered_by:
            self._tech.append(
                TechFingerprint(
                    name=powered_by.split("/")[0].strip() or powered_by,
                    version=_version_in(powered_by),
                    evidence=f"X-Powered-By header on {response.route}: {powered_by}",
                    source="header",
                )
            )

    def _fingerprint_from_body(self, response: CollectedResponse) -> None:
        body = response.body_excerpt.lower()
        # Version candidates require a library's delivered banner or runtime
        # attribute. Filenames and a bare mention never establish a version.
        version_patterns = {
            "jquery": r"jquery(?: javascript library)?\s+v?(\d+\.\d+\.\d+(?:-[\w.-]+)?)",
            "bootstrap": r"bootstrap\s+v(\d+\.\d+\.\d+(?:-[\w.-]+)?)",
            "vue": r"vue(?:\.js)?\s+v(\d+\.\d+\.\d+(?:-[\w.-]+)?)",
            "ng-version": r"ng-version=[\"\'](\d+\.\d+\.\d+(?:-[\w.-]+)?)[\"\']",
        }
        signatures = {
            "react": "react",
            "vue.js": "vue",
            "angular": "ng-version",
            "jquery": "jquery",
            "bootstrap": "bootstrap",
            "next.js": "__next_data__",
            "nuxt": "__nuxt__",
        }
        for name, marker in signatures.items():
            if marker in body:
                match = (
                    re.search(version_patterns[marker], body)
                    if marker in version_patterns
                    else None
                )
                self._tech.append(
                    TechFingerprint(
                        name=name,
                        version=match.group(1) if match else None,
                        evidence=f"marker {marker!r} in the body of {response.route}",
                        source="body",
                    )
                )

    def _observe_secrets(self, response: CollectedResponse) -> None:
        """Note that delivered script mentions credential-shaped names.

        Only a *candidate*. Spec §10.2 requires distinguishing a public client identifier
        from private material, and forbids exercising any discovered credential — so this
        records the mention and nothing else.
        """
        lowered = response.body_excerpt.lower()
        for hint in SECRET_NAME_HINTS:
            if hint in lowered:
                self._tech.append(
                    TechFingerprint(
                        name=f"credential-name-mention:{hint}",
                        version=None,
                        evidence=f"{hint!r} appears in delivered script at {response.route}",
                        source="body",
                    )
                )
                break

    def _classify(self, soup, response: CollectedResponse) -> None:  # type: ignore[no-untyped-def]
        if not 200 <= response.status < 300:
            return
        evidence = list(self._classification.evidence)
        is_spa = self._classification.is_spa
        has_rest = self._classification.has_rest_api

        if (
            soup is not None and (soup.find(id="root") or soup.find(id="app"))
        ) or "__NEXT_DATA__" in response.body_excerpt:
            is_spa = True
            evidence.append(f"SPA mount point in {response.route}")
        if response.content_type and "json" in response.content_type.lower():
            has_rest = True
            evidence.append(f"JSON response at {response.route}")
        try:
            document = json.loads(response.body_excerpt)
        except ValueError:
            document = None
        has_openapi = self._classification.has_openapi or (
            isinstance(document, dict)
            and isinstance(document.get("openapi", document.get("swagger")), str)
            and isinstance(document.get("paths"), dict)
        )
        has_graphql = self._classification.has_graphql or (
            response.route == "/graphql"
            and isinstance(document, dict)
            and ("data" in document or "__schema" in document)
        )

        self._classification = Classification(
            is_spa=is_spa,
            has_rest_api=has_rest,
            has_openapi=has_openapi,
            has_graphql=has_graphql,
            evidence=tuple(dict.fromkeys(evidence)),
        )

    # --- robots and sitemap ----------------------------------------------------------

    def _load_robots(self) -> None:
        """Record robots.txt, and remember Disallow-only paths as inventory.

        §5.7: paths seen only in a Disallow directive are listed and never fetched. The
        distinction matters — robots is a politeness signal and an inventory source, not a
        list of interesting things to request.
        """
        response = self.fetch(f"{self.config.origin}/robots.txt", route="/robots.txt")
        if response is None or response.status != 200:
            return

        for line in response.body_excerpt.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            directive, _, value = line.partition(":")
            key = directive.strip().lower()
            target = value.strip()
            if not target:
                continue
            if key == "disallow" and target != "/":
                self._disallowed_only.add(target)
                self._robots_entries.append(f"Disallow {target}")
            elif key == "allow":
                self._robots_entries.append(f"Allow {target}")
            elif key == "sitemap":
                self._robots_entries.append(f"Sitemap {target}")
                if target.startswith(("http://", "https://")) and (
                    urlsplit(target).hostname != self.config.host
                ):
                    self._record_host(target, "declared in robots.txt")

        if self._robots_entries:
            self._tech.append(
                TechFingerprint(
                    name="robots-directives",
                    version=None,
                    evidence="; ".join(self._robots_entries[:10]),
                    source="body",
                )
            )

    def _load_sitemap(self) -> list[_FrontierItem]:
        response = self.fetch(f"{self.config.origin}/sitemap.xml", route="/sitemap.xml")
        if response is None or response.status != 200:
            return []

        found: list[_FrontierItem] = []
        try:
            from xml.etree import ElementTree

            root = ElementTree.fromstring(response.body_excerpt)
            for loc in root.iter():
                if loc.tag.rsplit("}", 1)[-1] != "loc":
                    continue
                url = (loc.text or "").strip()
                if not url or not self._in_scope(url):
                    if url:
                        self._record_host(url, "listed in sitemap.xml")
                    continue
                found.append(_FrontierItem(url=url, depth=1, via="sitemap", source="/sitemap.xml"))
        except Exception:  # noqa: BLE001 - a malformed sitemap is a coverage gap, not an error
            self._unreachable["/sitemap.xml"] = "sitemap could not be parsed"
        return found

    # --- The crawl --------------------------------------------------------------------

    def run(self) -> CrawlResult:
        """Breadth-first from the origin, bounded, same-origin only."""
        entry = self.config.entry_url()
        cleartext = None
        if self.config.transport_http_port is not None:
            host = f"[{self.config.host}]" if ":" in self.config.host else self.config.host
            # This exception is exactly one initial GET. It never follows a redirect or
            # supplies URLs to the crawl frontier; the broker separately enforces it.
            cleartext = self._fetch_once(
                f"http://{host}:{self.config.transport_http_port}/", route="transport-http:/"
            )
        self._load_robots()
        frontier: list[_FrontierItem] = list(self._load_sitemap())

        for path in (*WELL_KNOWN_PATHS, "/.scopelens-not-found-control"):
            url = f"{self.config.origin}{path}"
            if path in {"/robots.txt", "/sitemap.xml"}:
                continue  # already fetched, with their own handling
            if path in self._disallowed_only:
                continue
            frontier.append(_FrontierItem(url=url, depth=1, via="well-known", source=None))

        frontier.insert(0, _FrontierItem(url=entry, depth=0, via="seed", source=None))
        for route in reversed(self.config.retest_routes):
            if route.startswith("/") and "{id}" not in route:
                frontier.insert(
                    0,
                    _FrontierItem(url=self.config.origin + route, depth=0, via="seed", source=None),
                )

        stopped_by: str | None = None
        reached_depth = 0

        while frontier:
            item = frontier.pop(0)
            canonical = _canonical(item.url)

            if canonical in self._visited:
                continue
            path = urlparse(item.url).path or "/"
            if not self._in_scope(item.url):
                self._stats = self._stats.model_copy(
                    update={"skipped_out_of_scope": self._stats.skipped_out_of_scope + 1}
                )
                continue
            if self._excluded(path):
                self._stats = self._stats.model_copy(
                    update={"skipped_excluded": self._stats.skipped_excluded + 1}
                )
                continue
            if path in self._disallowed_only:
                # Inventory only: recorded in the surface map by the caller, never fetched.
                self._visited.add(canonical)
                continue
            if self._stats.pages_fetched >= self.config.max_pages:
                stopped_by = f"page cap reached ({self.config.max_pages})"
                break
            if item.depth > self.config.max_depth:
                stopped_by = f"depth cap reached ({self.config.max_depth})"
                continue
            if self._remaining_time() <= 0:
                stopped_by = f"crawl time budget reached ({self._duration:g}s)"
                break

            self._visited.add(canonical)
            route = normalize_route(path)
            response = self.fetch(
                item.url,
                route=route,
                follow_redirects=path not in {"/.env", "/backup.sql", "/.git/config"},
            )
            self._stats = self._stats.model_copy(
                update={"pages_fetched": self._stats.pages_fetched + 1}
            )
            reached_depth = max(reached_depth, item.depth)

            if response is None:
                continue

            self._endpoints.append(
                EndpointRecord(
                    url=response.url,
                    route=response.route,
                    status=response.status,
                    content_type=response.content_type,
                    discovered_via=item.via,  # type: ignore[arg-type]
                    depth=item.depth,
                    discovered_from=item.source,
                )
            )

            if item.depth >= self.config.max_depth:
                continue

            for child in self._extract(response):
                child.depth = item.depth + 1
                frontier.append(child)

        if self._remaining_time() <= 0:
            stopped_by = f"crawl time budget reached ({self._duration:g}s)"
        self._stats = self._stats.model_copy(
            update={
                "max_depth_reached": reached_depth,
                "stopped_by": stopped_by,
                "time_allowance_seconds": self._duration,
                "budget_extensions": self._extensions,
                "elapsed_seconds": round(time.monotonic() - self._started, 3),
                "pending_frontier": len(frontier) + int(stopped_by is not None),
            }
        )

        return CrawlResult(
            surface=AttackSurfaceMap(
                origin=self.config.origin,
                endpoints=tuple(self._endpoints),
                parameters=tuple(self._parameters),
                forms=tuple(self._forms),
                tech=tuple(dict.fromkeys(self._tech)),
                hosts=tuple(self._hosts.values()),
                classification=self._classification,
                stats=self._stats,
            ),
            responses=list(self._responses),
            unreachable=dict(self._unreachable),
            cleartext_probe=cleartext,
        )


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _canonical(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    return f"{parts.scheme}://{parts.netloc}{path}" + (f"?{parts.query}" if parts.query else "")


def _same_route(left: str, right: str) -> bool:
    return normalize_route(urlparse(left).path) == normalize_route(urlparse(right).path)


def _query_parameters(url: str) -> list[str]:
    query = urlsplit(url).query
    if not query:
        return []
    return [pair.split("=", 1)[0] for pair in query.split("&") if pair]


def _version_in(value: str) -> str | None:
    """The first dotted-number run in a header value, if any."""
    import re

    match = re.search(r"\d+(?:\.\d+)+", value)
    return match.group(0) if match else None


def _excerpt(body: bytes, limit: int) -> tuple[str, bool]:
    if not body:
        return "", False
    truncated = len(body) > limit
    return body[:limit].decode("utf-8", "replace"), truncated


def main() -> int:
    """Entry point. Emits the surface map and every response as artifact lines."""
    from scopelens.checks.fetch_origin import RESULT_MARKER

    artifact_marker = os.environ.get("SCOPELENS_ARTIFACT_MARKER", "SCOPELENS_ARTIFACT ")
    try:
        config = config_from_env()
    except RuntimeError as exc:
        print(
            f"{RESULT_MARKER}{json.dumps({'ok': False, 'reason': 'no_target_url', 'error': str(exc)})}"
        )
        return 2

    crawler = Crawler(config)
    try:
        result = crawler.run()
    except RuntimeError as exc:
        # No proxy is a fail-closed condition, not a crash: say so and stop.
        print(
            f"{RESULT_MARKER}{json.dumps({'ok': False, 'reason': 'no_proxy', 'error': str(exc)})}"
        )
        return 2

    print(
        f"{RESULT_MARKER}"
        + json.dumps(
            {
                "body_bytes": sum(r.body_bytes for r in result.responses),
                "ok": True,
                "reason": "crawled",
                "origin": config.origin,
                "stats": result.surface.stats.model_dump(),
                "endpoints": len(result.surface.endpoints),
                "forms": len(result.surface.forms),
                "parameters": len(result.surface.parameters),
            },
            sort_keys=True,
        ),
        flush=True,
    )

    print(
        f"{artifact_marker}{json.dumps({'kind': 'surface', 'data': result.surface.model_dump()}, default=str, sort_keys=True)}",
        flush=True,
    )
    for response in result.responses:
        print(
            f"{artifact_marker}"
            + json.dumps(
                {"kind": "response", "data": response.model_dump()}, default=str, sort_keys=True
            ),
            flush=True,
        )
    if result.cleartext_probe is not None:
        print(
            f"{artifact_marker}"
            + json.dumps({"kind": "cleartext", "data": result.cleartext_probe.model_dump()}),
            flush=True,
        )
    print(
        f"{artifact_marker}"
        + json.dumps(
            {"kind": "unreachable", "data": result.unreachable}, default=str, sort_keys=True
        ),
        flush=True,
    )
    from scopelens.checks.active import http_probes

    for capture in http_probes(config):
        print(artifact_marker + json.dumps(capture), flush=True)
    if os.environ.get("SCOPELENS_SCANNER_TOOLS_ENABLED") == "true":
        # Flush each finished tool before starting the next one; a later timeout must
        # not erase earlier scanner results.
        from itertools import chain

        from scopelens.adapters.runner import run_tools
        from scopelens.checks.conditional import collect

        if os.environ.get("SCOPELENS_COLLECTION_TIMEOUT"):
            # Continuations borrow only from the collection process's existing
            # allowance. Reserve 20% for the final network check and artifact flush.
            remaining = float(os.environ["SCOPELENS_COLLECTION_TIMEOUT"]) * 0.8 - (
                time.monotonic() - crawler._started
            )
            os.environ["SCOPELENS_ZAP_TIMEOUT"] = str(
                max(0, min(float(os.environ.get("SCOPELENS_ZAP_TIMEOUT", "120")), remaining))
            )
        for tool in chain(run_tools(config, result), (collect(config) for _ in range(1))):
            print(
                artifact_marker + json.dumps({"kind": "scanner_result", "data": tool.model_dump()}),
                flush=True,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
