import json

import httpx
import pytest
from evaluation.holdout_api import create_scan, save_http_error


def client_with(responses, calls):
    def handle(request):
        calls.append((request.method, request.url.path, request.content))
        value = responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return httpx.Response(value[0], json=value[1])

    return httpx.Client(base_url="http://local", transport=httpx.MockTransport(handle))


def test_success_is_created_once_without_scope_poll():
    calls = []
    with client_with([(201, {"id": "scan"})], calls) as client:
        assert create_scan(client, "scope", True).json() == {"id": "scan"}
    assert len(calls) == 1


def test_explicit_missing_scope_waits_until_visible_then_retries_once():
    calls, sleeps = [], []
    responses = [
        (404, {"detail": "scope not found"}),
        (404, {"detail": "scope not found"}),
        (200, {"id": "scope"}),
        (201, {"id": "scan"}),
    ]
    with client_with(responses, calls) as client:
        assert (
            create_scan(client, "scope", False, clock=lambda: 0, sleep=sleeps.append).json()["id"]
            == "scan"
        )
    assert [(m, p) for m, p, _ in calls] == [
        ("POST", "/api/scans"),
        ("GET", "/api/scopes/scope"),
        ("GET", "/api/scopes/scope"),
        ("POST", "/api/scans"),
    ]
    assert calls[0][2] == calls[-1][2]
    assert sleeps == [0.25]


def test_unknown_404_is_not_retried():
    calls = []
    with (
        client_with(
            [(404, {"detail": "assessment configuration not found for this scope"})], calls
        ) as client,
        pytest.raises(httpx.HTTPStatusError),
    ):
        create_scan(client, "scope", False)
    assert len(calls) == 1


def test_timeout_with_uncertain_creation_is_not_retried():
    calls = []
    with (
        client_with([httpx.ReadTimeout("uncertain response")], calls) as client,
        pytest.raises(httpx.ReadTimeout),
    ):
        create_scan(client, "scope", True)
    assert len(calls) == 1


def test_visibility_deadline_prevents_another_scan_post():
    calls, clock = [], iter([0, 0, 10, 10])
    with (
        client_with(
            [(404, {"detail": "scope not found"}), (404, {"detail": "scope not found"})], calls
        ) as client,
        pytest.raises(httpx.HTTPStatusError),
    ):
        create_scan(client, "scope", False, clock=lambda: next(clock), sleep=lambda _: None)
    assert [m for m, _, _ in calls] == ["POST", "GET"]


def test_wrong_visible_id_prevents_retry():
    calls = []
    with (
        client_with(
            [(404, {"detail": "scope not found"}), (200, {"id": "other"})], calls
        ) as client,
        pytest.raises(RuntimeError, match="Visible scope ID differs"),
    ):
        create_scan(client, "scope", False)
    assert len(calls) == 2


def test_second_scan_failure_is_not_retried_again():
    calls = []
    with (
        client_with(
            [
                (404, {"detail": "scope not found"}),
                (200, {"id": "scope"}),
                (404, {"detail": "scope not found"}),
            ],
            calls,
        ) as client,
        pytest.raises(httpx.HTTPStatusError),
    ):
        create_scan(client, "scope", False)
    assert [m for m, _, _ in calls].count("POST") == 2


def test_visibility_request_timeout_uses_the_remaining_wait_budget():
    replies = iter(
        [(404, {"detail": "scope not found"}), (200, {"id": "scope"}), (201, {"id": "scan"})]
    )
    timeouts = []

    def handle(request):
        if request.method == "GET":
            timeouts.append(request.extensions["timeout"])
        status, body = next(replies)
        return httpx.Response(status, json=body)

    with httpx.Client(base_url="http://local", transport=httpx.MockTransport(handle)) as client:
        create_scan(client, "scope", False, clock=lambda: 0)
    assert timeouts == [{"connect": 10, "read": 10, "write": 10, "pool": 10}]


def test_error_capture_drops_headers_login_payload_and_redacts_secrets(tmp_path):
    request = httpx.Request(
        "POST",
        "http://local/api/auth/login",
        json={"password": "private"},
        headers={"authorization": "Bearer private"},
    )
    response = httpx.Response(
        400,
        request=request,
        json={
            "detail": "scope not found",
            "password": "private",
            "connection": "postgresql://user:private@db/app",
        },
    )
    save_http_error(response, tmp_path)
    path = tmp_path / "api-error-0001.json"
    record = json.loads(path.read_text())
    assert record["request"] is None
    assert record["headers_recorded"] is False
    assert record["response_body_redacted"]["detail"] == "scope not found"
    assert "private" not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
