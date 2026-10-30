import httpx

from scopelens.checks.crawl import CrawlConfig, Crawler


def crawler(handler, **overrides):
    cfg = dict(
        origin="https://example.test",
        scheme="https",
        host="example.test",
        port=443,
        max_pages=40,
        max_depth=4,
        timeout=1,
        max_body_bytes=10000,
        user_agent="test",
    )
    cfg.update(overrides)
    return Crawler(CrawlConfig(**cfg), client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_redirect_and_sitemap_discover_real_routes_and_forms():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/home"})
        if request.url.path == "/home":
            return httpx.Response(
                200,
                text='<form action="/search"><input name="q"></form>',
                headers={"content-type": "text/html"},
            )
        if request.url.path == "/sitemap.xml":
            return httpx.Response(
                200,
                text='<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.test/map-only</loc></url></urlset>',
            )
        return httpx.Response(404)

    result = crawler(handler).run()
    assert "/home" in seen and "/map-only" in seen
    assert result.surface.forms[0].inputs[0].name == "q"
    assert "/sitemap.xml" not in result.unreachable


def test_denied_redirect_never_sends_second_request():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://elsewhere.test/"})

    c = crawler(handler)
    assert c.fetch("https://example.test/") is None
    assert len(seen) == 1
    assert "/" in c._unreachable


def test_redirect_loop_is_recorded():
    c = crawler(lambda r: httpx.Response(302, headers={"location": "/"}))
    assert c.fetch("https://example.test/") is None
    assert c._unreachable["/"] == "redirect loop"


def test_capped_response_records_truncation():
    c = crawler(lambda r: httpx.Response(200, content=b"x" * 100), max_body_bytes=10)
    r = c.fetch("https://example.test/")
    assert r.truncated and len(r.body_excerpt) == 10


def test_transport_only_probe_does_not_follow_redirect():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return (
            httpx.Response(302, headers={"location": "https://elsewhere.test/"})
            if request.url.scheme == "http"
            else httpx.Response(404)
        )

    result = crawler(handler, transport_http_port=80).run()
    assert result.cleartext_probe.status == 302
    assert sum(u.startswith("http://") for u in seen) == 1
    assert not any("elsewhere" in u for u in seen)


def test_crawl_stops_before_worker_deadline_and_preserves_collected_pages(monkeypatch):
    import scopelens.checks.crawl as module

    clock = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    requests = []

    def handler(request):
        requests.append(request.url.path)
        clock[0] += 4
        return httpx.Response(
            200, text='<a href="/next">next</a>', headers={"content-type": "text/html"}
        )

    c = crawler(handler, max_duration_seconds=20, timeout=10)
    result = c.run()
    assert clock[0] <= 20
    assert result.responses
    assert result.surface.stats.stopped_by == "crawl time budget reached (20s)"
    before = len(requests)
    assert c.fetch("https://example.test/another") is None
    assert len(requests) == before
    assert c._unreachable["/another"] == "crawl time budget exhausted"


def test_crawl_deadline_applies_to_redirect_hops(monkeypatch):
    import scopelens.checks.crawl as module

    clock = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    requests = []

    def handler(request):
        requests.append(request.url.path)
        clock[0] += 5
        return httpx.Response(302, headers={"location": "/another"})

    c = crawler(handler, max_duration_seconds=5)
    assert c.fetch("https://example.test/") is None
    assert requests == ["/"]
    assert c._responses[0].status == 302


def test_worker_flushes_crawl_and_each_tool_before_later_work(monkeypatch, capsys):
    import scopelens.adapters.runner as runner
    import scopelens.checks.active as active
    import scopelens.checks.conditional as conditional
    import scopelens.checks.crawl as module
    from scopelens.adapters.scanners import ScannerResult

    c = crawler(lambda request: httpx.Response(200, text="fixture"))
    monkeypatch.setattr(module, "config_from_env", lambda: c.config)
    monkeypatch.setattr(module, "Crawler", lambda config: c)
    monkeypatch.setattr(active, "http_probes", lambda config: [])
    monkeypatch.setenv("SCOPELENS_SCANNER_TOOLS_ENABLED", "true")
    monkeypatch.setenv("SCOPELENS_ARTIFACT_MARKER", "SCOPELENS_ARTIFACT ")

    def tools(config, result):
        initial = capsys.readouterr().out
        assert '"kind": "surface"' in initial
        assert '"kind": "response"' in initial
        yield ScannerResult(tool="zap", version="fixture", state="completed")
        # The first result must already be emitted if the next scanner hangs.
        assert '"tool": "zap"' in capsys.readouterr().out
        yield ScannerResult(tool="nuclei", version="fixture", state="completed")

    def collect(config):
        assert '"tool": "nuclei"' in capsys.readouterr().out
        return ScannerResult(tool="testssl", version="fixture", state="not_tested")

    monkeypatch.setattr(runner, "run_tools", tools)
    monkeypatch.setattr(conditional, "collect", collect)
    assert module.main() == 0


def test_narrow_application_scope_starts_at_permitted_prefix():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return httpx.Response(
            200, text='<a href="/app/page">page</a>', headers={"content-type": "text/html"}
        )

    result = crawler(handler, allowed_path_prefixes=("/app",)).run()
    assert seen == ["/app", "/app/page"]
    assert result.responses[0].route == "/app"


def test_narrow_application_seed_skips_excluded_prefix():
    seen = []
    result = crawler(
        lambda request: (
            seen.append(request.url.path) or httpx.Response(200, text="owned application")
        ),
        allowed_path_prefixes=("/app", "/staff"),
        excluded_paths=("/app",),
    ).run()
    assert seen == ["/staff"]
    assert result.responses[0].route == "/staff"
