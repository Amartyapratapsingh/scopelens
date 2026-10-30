from types import SimpleNamespace

from scopelens.browser.policy import BrowserAction
from scopelens.browser.worker import Controller, PlaywrightTimeout
from scopelens.checks.crawl import CrawlConfig


def controller():
    instance = Controller.__new__(Controller)
    instance.config = CrawlConfig(
        origin="https://fixture.invalid",
        scheme="https",
        host="fixture.invalid",
        port=443,
        max_pages=10,
        max_depth=1,
        timeout=10,
        max_body_bytes=1048576,
        user_agent="fixture",
    )
    instance.sequence = 0
    instance.gaps = []
    instance.pending_requests = {}
    instance.pending_request_count = 0
    return instance


class Request:
    def __init__(self, url, resource_type="script"):
        self.url = url
        self.method = "GET"
        self.resource_type = resource_type
        self.response = lambda: SimpleNamespace(url=url)


def test_stalled_parser_asset_remains_pending_and_action_completion_failed():
    instance = controller()
    pending = Request("https://fixture.invalid/blocked.js?token=secret-fixture-value")
    done = Request("https://fixture.invalid/style.css", "stylesheet")
    denied = Request("https://other.invalid/script.js")
    for request in [pending, done, denied]:
        instance.request_started(request)
    captured = []
    instance.capture_response = lambda response: captured.append(response.url)
    instance.request_finished(done)
    instance.request_failed(denied)
    completions = []
    instance.command = lambda operation, **fields: completions.append((operation, fields))

    class Page:
        url = "https://fixture.invalid/"

        def wait_for_load_state(self, state, *, timeout):
            raise PlaywrightTimeout("fixture stalled")

    instance.state = lambda page: (_ for _ in ()).throw(PlaywrightTimeout("body absent"))
    try:
        instance.act(Page(), BrowserAction(kind="navigate", url=Page.url), lambda: None)
    except PlaywrightTimeout:
        pass
    else:
        raise AssertionError("Missing body must fail state capture")
    gap = next(g for g in instance.gaps if g["reason"] == "document_ready_timeout")
    assert gap["pending_request_count"] == 1
    assert len(gap["pending_requests"]) == 1
    assert gap["pending_requests"][0]["resource_type"] == "script"
    assert "secret-fixture-value" not in gap["pending_requests"][0]["url"]
    background = next(g for g in instance.gaps if g["reason"] == "background_requests_pending")
    assert background["pending_request_count"] == 1
    assert background["pending_requests"][0]["resource_type"] == "script"
    assert "secret-fixture-value" not in background["pending_requests"][0]["url"]
    assert captured == [done.url]
    assert completions[-1] == (
        "complete",
        {"before_hash": "", "after_hash": "", "result": "failed"},
    )
    instance.request_failed(pending)
    assert instance.pending_transport()["pending_request_count"] == 0


def test_transport_metadata_caps_objects_and_excerpt_without_losing_count():
    instance = controller()
    requests = [Request(f"https://fixture.invalid/script-{i}.js") for i in range(600)]
    for request in requests:
        instance.request_started(request)
    gap = instance.pending_transport()
    assert gap["pending_request_count"] == 600
    assert len(instance.pending_requests) == 500
    assert len(gap["pending_requests"]) == 20
    assert gap["pending_metadata_limited"]
    instance.capture_response = lambda response: None
    for request in requests:
        instance.request_finished(request)
    assert instance.pending_transport() == {
        "pending_request_count": 0,
        "pending_requests": [],
        "pending_metadata_limited": False,
    }


def test_static_grace_does_not_excuse_long_polling_or_unknown_requests():
    for resource_type, count in (("fetch", 1), ("script", 1), ("image", 2), ("font", 0)):
        instance = controller()
        request = Request("https://fixture.invalid/asset", resource_type)
        instance.pending_requests = {request: 0}
        instance.pending_request_count = count
        page = SimpleNamespace(
            wait_for_timeout=lambda *args: (_ for _ in ()).throw(AssertionError("unexpected wait"))
        )
        assert not instance.settle_static_assets(page)


def test_failed_image_cannot_be_excused_as_a_completed_transfer():
    instance = controller()
    request = Request("https://fixture.invalid/asset.png", "image")
    instance.request_started(request)
    page = SimpleNamespace(
        wait_for_timeout=lambda *args: instance.request_failed(request),
        wait_for_load_state=lambda *args, **kwargs: None,
    )
    assert not instance.settle_static_assets(page)


def test_browser_navigation_starts_inside_narrow_application_scope():
    import pytest

    instance = controller()
    instance.config.allowed_path_prefixes = ("/app",)
    instance.command = lambda *args, **kwargs: {"context_id": "fixture"}
    observed = []

    class NavigationObserved(Exception):
        pass

    def act(page, action, navigate):
        observed.append(action.url)
        return navigate()

    def goto(url, **kwargs):
        observed.append(url)
        raise NavigationObserved

    instance.act = act
    with pytest.raises(NavigationObserved):
        instance.explore(SimpleNamespace(goto=goto))
    assert observed == ["https://fixture.invalid/app", "https://fixture.invalid/app"]
