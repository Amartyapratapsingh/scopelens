# ScopeLens — Phase 1 MVP Build Spec (URL in → report out)

**Version:** 1.0 · 24 September 2026
**Audience:** the coding agent building Phase 1. Follow this document literally.
**Relationship to other docs:** `ScopeLens_Project_Specification.md` and `ScopeLens_Implementation_Plan.md` describe the full product (M0–M7). **For Phase 1, this document wins wherever they differ.** Do not implement anything from those documents that is not listed here.

---

## 0. Rules for the implementer (read first, obey always)

1. Build only what this document lists. If something seems missing, write it in `OPEN_QUESTIONS.md` and continue with the next task. Do not invent features.
2. **Do not add** Celery, Redis, PostgreSQL, LangGraph, Kali images, MCP servers, Playwright/browser automation, Nuclei, ZAP, a React frontend, multi-tenancy or authentication. They belong to later phases.
3. The scanner only sends **GET and HEAD** requests. It never submits forms, never sends request bodies, never follows `javascript:` or `mailto:` links, and never logs in.
4. Every outbound request goes through the single function `scopelens/http.py::fetch()`. No other module may import `httpx`, `requests`, `urllib.request` or `socket` to reach the target. Tests enforce this (see §9).
5. A target must be in `targets.yaml` (§3). This is the one "validation" kept in the MVP. It is the only thing stopping the tool from being pointed at a site you don't own. Do not remove it or add a bypass flag.
6. A finding is `Confirmed` only if the rule in §6 for that check says so. Anything else is `Potential`. Never mark something Confirmed because a regex "probably" matched.
7. Scores come only from `scoring.py` (§7). No model or template may change a score, severity or finding.
8. Each task in §10 has a **Done when** line. Do not start the next task until the current one is done and its tests pass.
9. Pin every dependency to an exact version in `pyproject.toml`.

---

## 1. What Phase 1 does

```
scopelens scan https://staging.example-owned.dev
  → checks targets.yaml
  → crawls the same origin (GET only, bounded)
  → runs the 15 checks in §6 against what it fetched
  → scores 4 categories + overall (§7)
  → writes runs/<scan_id>/report.html, report.json, audit.jsonl
```

That is the whole product for Phase 1. There is no server and no database. The output is a self-contained HTML report plus JSON.

**Profile name (shown in the report):** `External configuration assessment — MVP (pilot score, uncalibrated)`.
This is the configuration-only profile that spec §10.3 describes. It does **not** include the conditional active pack (XSS/SQLi/HTML injection/open redirect). So Injection (C03) is always shown as `Not assessed in this profile`.

---

## 2. Tech stack (exact)

| Need | Use | Notes |
|---|---|---|
| Language | Python 3.12 | |
| HTTP | `httpx` (sync client) | `follow_redirects=False`; redirects handled manually in `fetch()` |
| HTML parsing | `selectolax` | links, forms, scripts, iframes, img |
| TLS info | stdlib `ssl` + `socket` | **only** inside `scopelens/tls.py`, which is the one allowed exception to rule 4 and still calls `scope.assert_allowed()` |
| Config | `pyyaml` | `targets.yaml` |
| Models | `pydantic` v2 | all records in §5 |
| Report | `jinja2` with `autoescape=True` | one template |
| CLI | stdlib `argparse` | |
| Tests | `pytest` | |
| Lab fixtures | Docker Compose + `nginx:alpine` | §9 |
| Optional LLM summary | `openai` SDK with configurable `base_url` | Works for OpenAI, OpenRouter and OpenAI-compatible open-model endpoints. Off by default (§8). |

---

## 3. Target allowlist — `targets.yaml`

```yaml
targets:
  - origin: "https://staging.mysite.dev"      # scheme://host[:port], no path
    http_origin: "http://staging.mysite.dev"  # optional; only used for the HTTP→HTTPS redirect check (TLS-03)
    owner: "Aditya Pratap Singh"
    authorized_until: "2026-12-31"            # scan refuses after this date
    notes: "Owned staging site"
lab_mode: false   # true only when scanning the local docker fixtures (§9)
```

`scope.py` must implement:

- `load_targets(path) -> list[Target]`
- `resolve_target(url) -> Target`. Normalize the URL to `scheme://host:port` (lowercase host, default ports removed) and look for an exact origin match. Raise `ScopeError` if there is no match or `authorized_until` has passed.
- `assert_allowed(url, target)`. Raise `ScopeError` unless **all** of these hold:
  - scheme+host+port equals `target.origin` exactly, or equals `target.http_origin` **and** the caller passed `purpose="https_redirect_check"`;
  - the host resolves (IPv4 and IPv6) only to public addresses. Reject loopback, private (RFC1918, fc00::/7), link-local (169.254.0.0/16, fe80::/10), CGNAT (100.64.0.0/10), multicast, unspecified and 169.254.169.254. Use `ipaddress.ip_address(x).is_global`. If `lab_mode: true`, allow only the hostnames defined in `labs/docker-compose.yml`;
  - the host is not an IP literal, unless `lab_mode`.

`# ponytail: DNS is checked before each request, but httpx re-resolves on connect (small rebinding window). The full plan's egress proxy closes this. Acceptable only because targets are owned sites.`

---

## 4. Limits (from spec §12, hard-coded in `config.py`)

| Limit | Value |
|---|---|
| Requests per second (global) | 2 |
| Concurrent requests | 1 (sequential client; simplest way to honour "2 in flight") |
| Max pages crawled | 300 |
| Max crawl depth | 4 |
| Max total requests | 5,000 (redirect hops count) |
| Wall clock | 45 minutes |
| Per-request timeout | 10 s |
| Max body read | 1 MiB (truncate; record `truncated=true`) |
| Max redirects per fetch | 5 |
| Stop on | 10 consecutive 5xx/timeouts, or any 429 (after one wait for `Retry-After` up to 30 s) |

Hitting any limit ends the scan with status `completed_partial` and a stated reason. It is never treated as an error.

`User-Agent: ScopeLens/0.1 (+authorized assessment; contact <owner from targets.yaml>)`.

---

## 5. Data model (`scopelens/models.py`)

```python
class Fetched(BaseModel):          # one HTTP exchange, written to evidence
    id: str                        # uuid4
    url