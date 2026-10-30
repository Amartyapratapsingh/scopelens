"""Execute the dependency-isolated proxy hooks with a minimal mitmproxy fixture."""

import asyncio
import base64
import importlib.util
import json
import sys
from types import SimpleNamespace

import pytest

from scopelens.config import REPO_ROOT


@pytest.fixture
def addon(monkeypatch):
    monkeypatch.setenv("SCOPELENS_PROXY_MAX_IN_FLIGHT", "8")
    monkeypatch.setenv("SCOPELENS_SCOPE_MAX_IN_FLIGHT", "8")

    async def immediate_policy(function, *args, **kwargs):
        # These policy stubs do no I/O. Keep admission scheduling deterministic;
        # the real threaded policy transport has a separate mitmproxy regression.
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", immediate_policy)

    def make(status, body, headers):
        return SimpleNamespace(status_code=status, body=json.loads(body), headers=headers)

    fake = SimpleNamespace(
        ctx=SimpleNamespace(log=SimpleNamespace(warn=lambda *a: None, error=lambda *a: None)),
        http=SimpleNamespace(Response=SimpleNamespace(make=make)),
        tcp=object(),
        udp=object(),
    )
    monkeypatch.setitem(sys.modules, "mitmproxy", fake)
    spec = importlib.util.spec_from_file_location(
        "zap_proxy_fixture", REPO_ROOT / "backend/scopelens/broker/mitm_addon.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def flow(header='{"signature":"fixture"}', **changes):
    encoded = base64.b64encode(header.encode()).decode()
    request = SimpleNamespace(
        method="GET",
        scheme="http",
        host="172.28.0.11",
        port=80,
        host_header="172.28.0.11",
        path="/xss?q=marker",
        pretty_url="http://172.28.0.11/xss?q=marker",
        content=b"",
        headers={"x-scopelens-egress": "token", "x-scopelens-zap-task": encoded},
    )
    for key, value in changes.items():
        setattr(request, key, value)
    return SimpleNamespace(
        id="flow",
        request=request,
        client_conn=SimpleNamespace(id="actual-client"),
        metadata={},
        response=None,
        killable=True,
        kill=lambda: None,
    )


def policy(**changes):
    def no_ordinary(*a, **k):
        pytest.fail("signed request fell back to ordinary scan authorization")

    result = SimpleNamespace(
        authorize=no_ordinary,
        zap_task=lambda p: {
            "allowed": True,
            "addresses": ["172.28.0.11"],
            "limits": {"task_remaining_seconds": "5"},
        },
        alive=lambda token: {"allowed": True},
        zap_alive=lambda signed: {"allowed": True},
    )
    for key, value in changes.items():
        setattr(result, key, value)
    return result


@pytest.mark.parametrize(
    "fault", ["malformed", "non_http", "credentials", "task_closed", "deadline", "policy_denied"]
)
def test_signed_task_denials_never_fall_back_to_scan_grant(addon, fault):
    enforcer = addon.ScopeEnforcer()
    current = flow()
    client = policy()
    if fault == "malformed":
        current.request.headers[addon.ZAP_TASK_HEADER] = "not base64"
    if fault == "non_http":
        current.request.scheme = "ftp"
    if fault == "credentials":
        current.request.headers["cookie"] = "secret"
    if fault == "task_closed":
        client.zap_alive = lambda signed: {"allowed": False}
    if fault == "deadline":
        client.zap_task = lambda p: {"allowed": True, "limits": {"task_remaining_seconds": "0"}}
    if fault == "policy_denied":
        client.zap_task = lambda p: {"allowed": False, "reason": "fixture_denied"}
    enforcer.client = client
    asyncio.run(enforcer._request(current))
    assert current.response.status_code == 403 and enforcer.allowed == 0
    assert addon.ZAP_TASK_HEADER not in current.request.headers


def test_signature_and_token_removed_before_admitted_target_request(addon):
    enforcer = addon.ScopeEnforcer()
    observed = []

    def authorize(payload):
        observed.append(payload)
        return {
            "allowed": True,
            "addresses": ["172.28.0.11"],
            "limits": {"task_remaining_seconds": "5"},
        }

    enforcer.client = policy(zap_task=authorize)
    current = flow()
    asyncio.run(enforcer._request(current))
    assert current.response is None and enforcer.allowed == 1
    assert not current.request.headers
    assert observed[0]["signed"] == {"signature": "fixture"}
    assert observed[0]["url"] == current.request.pretty_url
    enforcer._release(current)


def test_signed_https_inner_request_requires_task_policy_and_strips_authority_headers(addon):
    enforcer = addon.ScopeEnforcer()
    observed = []

    def admit(payload):
        observed.append(payload)
        return {
            "allowed": True,
            "addresses": ["172.28.0.11"],
            "limits": {"task_remaining_seconds": "5"},
        }

    enforcer.client = policy(zap_task=admit)
    current = flow(scheme="https", port=443, pretty_url="https://172.28.0.11/xss?q=marker")
    asyncio.run(enforcer._request(current))
    assert current.response is None and enforcer.allowed == 1
    assert observed[0]["url"] == "https://172.28.0.11/xss?q=marker"
    assert observed[0]["signed"] == {"signature": "fixture"}
    assert not current.request.headers
    enforcer._release(current)


def test_task_header_cannot_open_connect_tunnel(addon):
    enforcer = addon.ScopeEnforcer()
    enforcer.client = policy()
    current = flow(method="CONNECT")
    asyncio.run(enforcer.http_connect(current))
    assert current.response.status_code == 403 and enforcer.allowed == 0
    assert not current.request.headers


def test_response_stream_stops_when_task_closes(addon):
    enforcer = addon.ScopeEnforcer()
    killed = []
    enforcer.client = policy(zap_alive=lambda signed: {"allowed": False})
    current = flow()
    current.kill = lambda: killed.append(True)
    current.metadata = {
        "scopelens_token": "token",
        "scopelens_body_cap": 1024,
        "scopelens_zap_task": {"signature": "fixture"},
    }
    current.response = SimpleNamespace(headers={})
    enforcer.responseheaders(current)
    assert current.response.stream(b"chunk") == b"" and killed == [True]


def test_reviewed_probe_header_is_policy_only_and_removed_before_target(addon):
    enforcer = addon.ScopeEnforcer()
    observed = []
    enforcer.client = policy(
        authorize=lambda payload: (
            observed.append(payload)
            or {
                "allowed": True,
                "addresses": ["172.28.0.11"],
                "limits": {},
            }
        )
    )
    current = flow(
        headers={addon.TOKEN_HEADER: "token", addon.PROBE_HEADER: "conditional:" + "a" * 64}
    )
    asyncio.run(enforcer._request(current))
    assert current.response is None
    assert observed[0]["probe_task"] == "conditional:" + "a" * 64
    assert not current.request.headers
    enforcer._release(current)


def test_reviewed_probe_cannot_override_signed_task_channel(addon):
    current = flow()
    current.request.headers[addon.PROBE_HEADER] = "conditional:" + "a" * 64
    enforcer = addon.ScopeEnforcer()
    enforcer.client = policy()
    asyncio.run(enforcer._request(current))
    assert current.response.status_code == 403
    assert current.response.body["reason"] == "invalid_probe_task"
    assert not current.request.headers


@pytest.mark.parametrize("connect", [False, True])
def test_proxy_denial_logs_at_level_visible_under_quiet_mode(addon, connect):
    messages = []
    addon.ctx.log.error = messages.append
    current = flow()
    enforcer = addon.ScopeEnforcer()
    if connect:
        enforcer._block_connect(current, "budget_exhausted", "fixture detail")
    else:
        enforcer._block(current, "budget_exhausted", "fixture detail")
    assert len(messages) == 1
    assert "broker denied" in messages[0] and "budget_exhausted" in messages[0]
    assert "token" not in messages[0] and "?" not in messages[0]


async def settle_admissions():
    # request() wraps the inner hook in wait_for; drain those scheduling turns without
    # wall-clock sleeps or any target IO.
    for _ in range(10):
        await asyncio.sleep(0)


def concurrency_fixture(addon, per_scan, tokens):
    enforcer = addon.ScopeEnforcer()
    enforcer.client = policy(
        authorize=lambda payload: {
            "allowed": True,
            "addresses": ["172.28.0.11"],
            "limits": {"max_in_flight": str(per_scan[payload["egress_token"]])},
        }
    )
    flows = []
    for index, token in enumerate(tokens):
        current = flow(headers={addon.TOKEN_HEADER: token})
        current.id = str(index)
        current.client_conn.id = str(index)
        flows.append(current)
    return enforcer, flows


async def stop_admissions(enforcer, flows, tasks):
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    for current in flows:
        enforcer._release(current)


@pytest.mark.parametrize(
    "override,limit,rate",
    [
        (None, 2, 2),
        ({"max_in_flight": 4, "requests_per_second": 5}, 4, 5),
        ({"max_in_flight": 20, "requests_per_second": 20}, 8, 10),
    ],
)
def test_proxy_honours_ledger_effective_scope_limits(
    addon, monkeypatch, settings, override, limit, rate
):
    from scopelens.execution.ledger import budget_limits_for

    monkeypatch.delenv("SCOPELENS_PROXY_MAX_IN_FLIGHT", raising=False)
    monkeypatch.delenv("SCOPELENS_SCOPE_MAX_IN_FLIGHT", raising=False)
    settings = settings.model_copy(
        update={
            "scope_max_in_flight": 8,
            "scope_max_requests_per_second": 10,
            "budgets": settings.budgets.model_copy(
                update={"max_in_flight": 2, "requests_per_second": 2}
            ),
        }
    )
    effective = budget_limits_for(SimpleNamespace(budgets_override=override), settings)
    assert effective.requests_per_second == rate

    async def exercise():
        enforcer, flows = concurrency_fixture(
            addon, {"scan": effective.max_in_flight}, ["scan"] * (limit + 1)
        )
        tasks = [asyncio.create_task(enforcer.request(current)) for current in flows]
        try:
            await settle_admissions()
            assert sum(t.done() for t in tasks) == limit
            assert enforcer.allowed == limit
            assert all(f.response is None for f in flows)
            enforcer.response(flows[0])
            await settle_admissions()
            assert all(t.done() for t in tasks)
            assert enforcer.allowed == limit + 1
            assert sum("scopelens_scan_slot" in f.metadata for f in flows) == limit
        finally:
            await stop_admissions(enforcer, flows, tasks)

    asyncio.run(exercise())


def test_global_proxy_limit_bounds_multiple_scans(addon, monkeypatch):
    monkeypatch.setenv("SCOPELENS_PROXY_MAX_IN_FLIGHT", "3")

    async def exercise():
        enforcer, flows = concurrency_fixture(addon, {"a": 4, "b": 4}, ["a", "b"] * 3)
        tasks = [asyncio.create_task(enforcer.request(current)) for current in flows]
        try:
            await settle_admissions()
            assert sum(t.done() for t in tasks) == 3
            enforcer.response(flows[0])
            await settle_admissions()
            assert sum(t.done() for t in tasks) == 4
            assert sum("scopelens_scan_slot" in f.metadata for f in flows) == 3
        finally:
            await stop_admissions(enforcer, flows, tasks)

    asyncio.run(exercise())


@pytest.mark.parametrize("ceiling", [4, 8])
def test_per_scan_concurrency_is_clamped_to_configured_ceiling(addon, monkeypatch, ceiling):
    monkeypatch.setenv("SCOPELENS_PROXY_MAX_IN_FLIGHT", "12")
    monkeypatch.setenv("SCOPELENS_SCOPE_MAX_IN_FLIGHT", str(ceiling))

    async def exercise():
        enforcer, flows = concurrency_fixture(addon, {"scan": 50}, ["scan"] * 10)
        tasks = [asyncio.create_task(enforcer.request(current)) for current in flows]
        try:
            await settle_admissions()
            assert sum(t.done() for t in tasks) == ceiling
            assert enforcer.allowed == ceiling
        finally:
            await stop_admissions(enforcer, flows, tasks)

    asyncio.run(exercise())


@pytest.mark.parametrize("limit", ["0", "-1", "invalid", ""])
def test_invalid_global_concurrency_fails_at_proxy_startup(addon, monkeypatch, limit):
    monkeypatch.setenv("SCOPELENS_PROXY_MAX_IN_FLIGHT", limit)
    with pytest.raises(ValueError):
        addon.ScopeEnforcer()


@pytest.mark.parametrize("limit", ["0", "-1", "invalid", ""])
def test_invalid_scope_ceiling_fails_at_proxy_startup(addon, monkeypatch, limit):
    monkeypatch.setenv("SCOPELENS_SCOPE_MAX_IN_FLIGHT", limit)
    with pytest.raises(ValueError):
        addon.ScopeEnforcer()


@pytest.mark.parametrize("limit", [0, -1, "invalid", None])
def test_invalid_policy_concurrency_denies_and_releases_slots(addon, monkeypatch, limit):
    monkeypatch.delenv("SCOPELENS_PROXY_MAX_IN_FLIGHT", raising=False)

    async def exercise():
        enforcer, flows = concurrency_fixture(addon, {"scan": 1}, ["scan"])
        enforcer.client.authorize = lambda payload: {
            "allowed": True,
            "addresses": ["172.28.0.11"],
            "limits": {"max_in_flight": limit},
        }
        await enforcer.request(flows[0])
        assert flows[0].response.status_code == 403
        assert flows[0].response.body["reason"] == "policy_malformed"
        assert "scopelens_slot" not in flows[0].metadata
        # A subsequent valid scan gets all eight global slots: the denial did not leak one.
        enforcer.client.authorize = lambda payload: {
            "allowed": True,
            "addresses": ["172.28.0.11"],
            "limits": {"max_in_flight": "8"},
        }
        _, other = concurrency_fixture(addon, {"other": 8}, ["other"] * 8)
        tasks = [asyncio.create_task(enforcer.request(f)) for f in other]
        try:
            await settle_admissions()
            assert all(t.done() for t in tasks)
            assert enforcer.allowed == 8
        finally:
            await stop_admissions(enforcer, other, tasks)

    asyncio.run(exercise())


def test_native_broker_verdict_overwrites_upstream_spoof(addon):
    enforcer = addon.ScopeEnforcer()
    enforcer.client = policy()
    current = flow()
    asyncio.run(enforcer._request(current))
    current.response = SimpleNamespace(status_code=502, headers={addon.ZAP_DECISION_HEADER: "deny"})
    enforcer.responseheaders(current)
    assert current.response.headers[addon.ZAP_DECISION_HEADER] == "allow"
    enforcer.response(current)


def test_native_denial_verdict_survives_response_hook(addon):
    enforcer = addon.ScopeEnforcer()
    enforcer.client = policy(zap_task=lambda p: {"allowed": False, "reason": "fixture_denied"})
    current = flow()
    asyncio.run(enforcer._request(current))
    assert current.response.status_code == 403
    assert current.response.headers[addon.ZAP_DECISION_HEADER] == "deny"
    enforcer.responseheaders(current)
    assert current.response.headers[addon.ZAP_DECISION_HEADER] == "deny"


def test_ordinary_upstream_cannot_supply_native_verdict(addon):
    enforcer = addon.ScopeEnforcer()
    current = flow(headers={})
    current.response = SimpleNamespace(headers={addon.ZAP_DECISION_HEADER: "allow"})
    enforcer.responseheaders(current)
    assert addon.ZAP_DECISION_HEADER not in current.response.headers


def test_native_request_without_completed_admission_has_unknown_verdict(addon):
    enforcer = addon.ScopeEnforcer()
    current = flow()
    current.metadata["scopelens_native_request"] = True
    current.response = SimpleNamespace(headers={addon.ZAP_DECISION_HEADER: "allow"})
    enforcer.responseheaders(current)
    assert current.response.headers[addon.ZAP_DECISION_HEADER] == "unknown"
