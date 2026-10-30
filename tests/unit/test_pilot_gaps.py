from scopelens.checks.analyze import unreachable_from_artifacts


def test_browser_records_redirect_headers_without_requesting_unavailable_body():
    from types import SimpleNamespace
    from unittest.mock import Mock

    from scopelens.browser.worker import Controller

    controller = Controller.__new__(Controller)
    controller.config = SimpleNamespace(max_body_bytes=1024)
    controller.in_scope = lambda _: True
    controller.responses, controller.gaps = [], []
    response = Mock(url="http://example.test/", status=301)
    response.headers_array.return_value = [{"name": "Location", "value": "https://example.test/"}]
    response.all_headers.return_value = {"location": "https://example.test/"}
    response.body.side_effect = AssertionError("redirect bodies are unavailable")
    controller.capture_response(response)
    assert controller.responses[0]["headers"]["location"] == "https://example.test/"
    assert not controller.gaps
    response.body.assert_not_called()


def test_busy_page_retains_visible_state_and_records_settle_gap():
    from unittest.mock import Mock

    from playwright.sync_api import TimeoutError as PlaywrightTimeout

    from scopelens.browser.policy import BrowserAction
    from scopelens.browser.worker import Controller

    controller = Controller.__new__(Controller)
    controller.sequence, controller.gaps = 0, []
    controller.command = Mock()
    controller.state = Mock(return_value="visible-state")
    page = Mock(url="https://example.test/")
    page.wait_for_load_state.side_effect = PlaywrightTimeout("still loading")
    action = BrowserAction(kind="navigate", url=page.url)
    assert controller.act(page, action, Mock()) == "visible-state"
    assert controller.gaps == [
        {
            "url": page.url,
            "reason": "document_ready_timeout",
            "pending_request_count": 0,
            "pending_metadata_limited": False,
            "pending_requests": [],
        },
        {
            "url": page.url,
            "reason": "background_requests_pending",
            "pending_request_count": 0,
            "pending_metadata_limited": False,
            "pending_requests": [],
        },
    ]
    controller.command.assert_called_with(
        "complete", before_hash=action.state_hash, after_hash="visible-state", result="succeeded"
    )


def test_third_party_failure_is_not_a_missing_target_route():
    artifacts = [
        {
            "kind": "browser_summary",
            "data": {
                "gaps": [
                    {"url": "https://fonts.example.test/style.css", "reason": "request_failed"},
                    {"url": "https://example.test:443/app", "reason": "navigation_failed"},
                    {"url": "http://example.test/app", "reason": "request_failed"},
                    {"url": "https://example.test:8443/app", "reason": "request_failed"},
                ]
            },
        }
    ]
    assert unreachable_from_artifacts(artifacts, origin="https://example.test") == {
        "/app": "navigation_failed"
    }


def test_crawl_failures_are_preserved_alongside_browser_gaps():
    artifacts = [{"kind": "unreachable", "data": {"/backup.sql": "timeout"}}]
    assert unreachable_from_artifacts(artifacts, origin="https://example.test") == {
        "/backup.sql": "timeout"
    }
