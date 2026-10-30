"""Default-inert launcher and trusted transport contracts; no native qualification."""

import base64
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest

from scopelens.adapters.zap_active import (
    REVIEWED_RULES,
    ActiveRulePin,
    ActiveRuleTask,
    reviewed_rule,
)
from scopelens.adapters.zap_active_worker import CONFIG_SHA256, verify_binaries
from scopelens.domain.enums import AuthorityDomain, ProfileName
from scopelens.execution.supervisor import WorkerResult
from scopelens.execution.zap_active import (
    _forward,
    _read_result,
    append_results,
    container_kwargs,
    dispatch,
)


@pytest.fixture
def native(settings, monkeypatch):
    pin = ActiveRulePin(
        rule_id="40012",
        control_id="SL-C03-XSS-01",
        engine_version="2.17.0",
        engine_sha256="2" * 64,
        rule_config_sha256=CONFIG_SHA256,
        addon_filename="ascanrules-release-78.zap",
        addon_sha256="3" * 64,
        allowed_values=("scopelens", "marker"),
        max_requests=2,
        deadline_seconds=5,
    )
    task = ActiveRuleTask(
        scan_id="00000000-0000-0000-0000-000000000001",
        task_id="native-task",
        input_id="input",
        rule_id=pin.rule_id,
        url="http://172.28.0.11/xss?q=scopelens",
        input_name="q",
        rule_config_sha256=CONFIG_SHA256,
        max_requests=2,
        deadline_seconds=5,
    )
    monkeypatch.setitem(REVIEWED_RULES, pin.rule_id, pin)
    return pin, task


def scope(**changes):
    return SimpleNamespace(
        authority_domain=AuthorityDomain.LAB,
        allowed_check_profile=ProfileName.EXTERNAL_ACTIVE_V2,
        scheme="http",
        lab_binding=SimpleNamespace(service="labs-bad"),
        origin="http://172.28.0.11",
        **changes,
    )


def test_empty_allowlist_dispatches_zero_active_requests(settings, tmp_path, monkeypatch):
    manifest = tmp_path / "approved.json"
    manifest.write_text('{"version":"zap-active-allowlist-v1","approved_rules":[]}')
    monkeypatch.setattr("scopelens.adapters.zap_active.REVIEWED_RULES", {})
    configured = settings.model_copy(
        update={"zap_active_lab_enabled": True, "zap_active_allowlist_file": manifest}
    )

    class UnreachableSupervisor:
        @property
        def client(self):
            pytest.fail("empty allowlist must not access Docker or construct transport")

    assert (
        dispatch(
            configured,
            UnreachableSupervisor(),
            scan_id="scan",
            scope=scope(),
            probes=[{"kind": "xss", "path": "/xss", "parameter": "q"}],
            token="secret",
        )
        == []
    )


@pytest.mark.parametrize(
    "manifest",
    [
        "{}",
        "null",
        '{"version":"wrong","approved_rules":[]}',
        '{"version":"zap-active-allowlist-v1","approved_rules":[{}]}',
    ],
)
def test_bad_manifest_fails_closed(settings, tmp_path, monkeypatch, manifest):
    monkeypatch.setattr("scopelens.adapters.zap_active.REVIEWED_RULES", {})
    path = tmp_path / "approved.json"
    path.write_text(manifest)
    assert (
        reviewed_rule("40012", settings.model_copy(update={"zap_active_allowlist_file": path}))
        is None
    )


def test_container_has_no_network_mounts_or_secrets(native):
    pin, task = native
    config = container_kwargs("sha256:" + "a" * 64, task, pin)
    assert config["network_mode"] == "none"
    assert "network" not in config and "volumes" not in config
    assert config["read_only"] and not config["privileged"]
    assert config["cap_drop"] == ["ALL"]
    assert config["security_opt"] == ["no-new-privileges:true"]
    assert set(config["environment"]) == {"PATH", "HOME"}
    assert config["labels"]["scopelens.scan_id"] == task.scan_id
    assert config["labels"]["scopelens.managed"] == "worker"
    with pytest.raises(ValueError, match="immutable"):
        container_kwargs("mutable:tag", task, pin)


def test_native_binary_and_addon_hashes_are_checked(native, tmp_path):
    pin, _ = native
    (tmp_path / "plugin").mkdir()
    jar = b"jar fixture"
    addon = b"addon fixture"
    (tmp_path / "zap-2.17.0.jar").write_bytes(jar)
    (tmp_path / "plugin" / pin.addon_filename).write_bytes(addon)
    bound = pin.model_copy(
        update={
            "engine_sha256": hashlib.sha256(jar).hexdigest(),
            "addon_sha256": hashlib.sha256(addon).hexdigest(),
        }
    )
    verify_binaries(bound, tmp_path)
    (tmp_path / "plugin" / pin.addon_filename).write_bytes(b"changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_binaries(bound, tmp_path)
    with pytest.raises(ValueError, match="incomplete"):
        verify_binaries(bound.model_copy(update={"addon_sha256": None}), tmp_path)


def test_forward_strips_worker_headers_and_binds_actual_container(native, settings, monkeypatch):
    _, task = native
    calls = []

    def sign(config, grant, **fields):
        calls.append(fields)
        return SimpleNamespace(model_dump_json=lambda: '{"signed":"fixture"}')

    monkeypatch.setattr("scopelens.execution.zap_active.sign_request", sign)

    def upstream(request):
        assert request.headers["x-scopelens-egress"] == "broker-token"
        assert json.loads(base64.b64decode(request.headers["x-scopelens-zap-task"])) == {
            "signed": "fixture"
        }
        assert "cookie" not in request.headers and "authorization" not in request.headers
        return httpx.Response(
            200,
            content=b"response",
            headers={
                "Set-Cookie": "secret",
                "Content-Type": "text/html",
                "x-scopelens-zap-decision": "allow",
            },
        )

    with httpx.Client(transport=httpx.MockTransport(upstream)) as client:
        result, allowed = _forward(
            client, settings, {}, task, "a" * 64, {"method": "GET", "url": task.url}, "broker-token"
        )
    assert allowed and result["headers"] == {"content-type": "text/html"}
    assert base64.b64decode(result["body"]) == b"response"
    assert calls[0]["worker_id"] == "a" * 64


def test_anonymous_native_requests_do_not_replay_target_cookies(native, settings, monkeypatch):
    _, task = native
    monkeypatch.setattr(
        "scopelens.execution.zap_active.sign_request",
        lambda *args, **kwargs: SimpleNamespace(model_dump_json=lambda: '{"signed":"fixture"}'),
    )
    requests = []

    def target(request):
        requests.append(request)
        return httpx.Response(
            200,
            content=b"fixture",
            headers={
                "Set-Cookie": "sessionid=synthetic-fixture; Path=/; Domain=172.28.0.11",
                "x-scopelens-zap-decision": "allow",
            },
        )

    with httpx.Client(transport=httpx.MockTransport(target)) as client:
        for _ in range(2):
            assert _forward(
                client,
                settings,
                {},
                task,
                "a" * 64,
                {"method": "GET", "url": task.url},
                "synthetic-token",
            )[1]
    assert len(requests) == 2
    assert all("cookie" not in request.headers for request in requests)


@pytest.mark.parametrize("fault", ["origin", "payload", "method", "identity", "headers"])
def test_unbound_worker_request_cannot_reach_transport(native, settings, fault):
    _, task = native
    offered = {"method": "GET", "url": task.url}
    if fault == "origin":
        offered["url"] = "http://172.28.0.10/xss?q=scopelens"
    if fault == "payload":
        offered["url"] = task.url.replace("scopelens", "unreviewed")
    if fault == "method":
        offered["method"] = "POST"
    if fault == "identity":
        offered["worker_id"] = "b" * 64
    if fault == "headers":
        offered["headers"] = {"Cookie": "secret"}
    client = SimpleNamespace(
        stream=lambda *a, **k: pytest.fail("unbound request reached transport")
    )
    if fault in {"origin", "payload"}:
        assert not _forward(client, settings, {}, task, "a" * 64, offered, "token")[1]
    else:
        with pytest.raises(ValueError):
            _forward(client, settings, {}, task, "a" * 64, offered, "token")


def test_result_reader_uses_fixed_ipc_file_without_host_extraction():
    from scopelens.execution.zap_active import READ_FILE

    def exec_run(command):
        assert command == ["python", "-I", "-c", READ_FILE, "result.json"]
        return 0, b'{"site":[]}'

    container = SimpleNamespace(exec_run=exec_run)
    assert _read_result(container) == b'{"site":[]}'


def test_scanner_artifacts_are_retained_without_proof_credit():
    from scopelens.adapters.scanners import ScannerResult

    crawl = WorkerResult("run", 0, "", "", 0)
    result = ScannerResult(tool="zap-active", version="2.17.0", state="not_tested")
    artifact = append_results(crawl, [result]).artifacts()[0]
    assert artifact["kind"] == "scanner_result" and artifact["data"]["assessed_rule_ids"] == []
    assert append_results(crawl, []) is crawl


def test_supervisor_uses_created_container_and_closes_on_cancellation(
    native, settings, monkeypatch
):
    from contextlib import contextmanager

    from scopelens.execution.zap_active import run_task

    pin, task = native
    events = []
    actual = "a" * 64
    container = SimpleNamespace(
        id=actual,
        start=lambda: events.append("started"),
        remove=lambda **kw: events.append("removed"),
    )
    supervisor = SimpleNamespace(
        client=SimpleNamespace(containers=SimpleNamespace(create=lambda **kw: container))
    )

    @contextmanager
    def session(config):
        yield object()

    def issue(session, **fields):
        assert fields["worker_id"] == actual
        events.append("issued")
        return {"grant_id": "grant"}

    def sign(*args, **fields):
        assert fields["worker_id"] == actual
        return object()

    def close(session, **fields):
        assert fields["worker_id"] == actual and fields["grant_id"] == "grant"
        events.append("closed")

    monkeypatch.setattr("scopelens.execution.zap_active.session_scope", session)
    monkeypatch.setattr("scopelens.execution.zap_active.issue_grant", issue)
    monkeypatch.setattr("scopelens.execution.zap_active.sign_request", sign)
    monkeypatch.setattr("scopelens.execution.zap_active.grant_live", lambda *a, **kw: False)
    monkeypatch.setattr("scopelens.execution.zap_active.close_grant", close)
    result = run_task(
        settings.model_copy(update={"kali_worker_image": "sha256:" + "b" * 64}),
        supervisor,
        task,
        pin,
        "token",
    )
    assert result.state == "cancelled"
    assert events == ["issued", "started", "closed", "removed"]


@pytest.mark.parametrize("refused", [None, "disableAllScanners", "setOptionTargetParamsInjectable"])
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_native_setup_is_loopback_only_and_disabled_before_rule_selection(
    native, monkeypatch, refused, scheme, tmp_path
):
    from scopelens.adapters import zap_active_worker as worker

    pin, task = native
    task = task.model_copy(update={"url": task.url.replace("http:", scheme + ":", 1)})
    calls = []
    stopped = []

    class Server:
        def __init__(self, address, handler):
            assert address == ("127.0.0.1", 8777)

        def serve_forever(self):
            pass

        def shutdown(self):
            pass

    class Process:
        def __init__(self, command, **kwargs):
            assert command[command.index("-host") + 1] == "127.0.0.1"
            assert "SCOPELENS_EGRESS_TOKEN" not in kwargs["env"]
            assert kwargs["stdout"] is worker.sys.stderr and kwargs["stderr"] is worker.sys.stderr

        def terminate(self):
            stopped.append(True)

        def wait(self, **kwargs):
            return 0

    def respond(request):
        assert request.url.host == "127.0.0.1" and request.url.port == 8778
        assert 0 < request.extensions["timeout"]["read"] <= task.deadline_seconds
        operation = request.url.path.split("/")[-2]
        calls.append((operation, dict(request.url.params)))
        if operation.startswith("setOption"):
            # Pinned ZAP 2.17.0 option setters require case-sensitive "Integer".
            # Lowercase "integer" returns HTTP 400 before accessUrl/target I/O.
            if "Integer" not in request.url.params:
                return httpx.Response(400, json={"code": "missing_parameter"})
            assert "integer" not in request.url.params
        if refused == operation:
            if operation == "setOptionTargetParamsInjectable":
                return httpx.Response(400, json={"code": "fixture_refusal"})
            payload = {"code": "fixture_refusal"}
        else:
            payload = {
                "version": "2.17.0",
                "contextId": "1",
                "scan": "1",
                "status": "100",
                "alerts": [],
            }
        return httpx.Response(200, json=payload)

    real_client = httpx.Client
    monkeypatch.setattr(worker, "verify_binaries", lambda pin: None)
    monkeypatch.setattr(worker, "IPC", tmp_path)
    monkeypatch.setattr(worker, "HTTPServer", Server)
    monkeypatch.setattr(worker.subprocess, "Popen", Process)
    monkeypatch.setattr(
        worker.httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(respond))
    )
    if refused:
        with pytest.raises(ValueError, match="refused") as error:
            worker.run(task, pin)
        assert refused in str(error.value)
        assert "apikey" not in str(error.value) and "127.0.0.1" not in str(error.value)
        assert not any(name == "accessUrl" for name, _ in calls)
    else:
        assert worker.run(task, pin) == {"site": [{"alerts": []}]}
        disabled = next(i for i, (name, _) in enumerate(calls) if name == "disableAllScanners")
        enabled = next(i for i, (name, _) in enumerate(calls) if name == "enableScanners")
        assert disabled < enabled and calls[enabled][1]["ids"] == pin.rule_id
        scan = next(params for name, params in calls if name == "scan")
        assert (
            scan["method"] == "GET" and scan["recurse"] == "false" and scan["inScopeOnly"] == "true"
        )
        assert scan["url"] == worker.native_url(task)
        assert worker.logical_url(task, pin, scan["url"]) == task.url
    assert stopped == [True]


@pytest.mark.parametrize(
    ("status", "verdict"),
    [(200, "allow"), (403, "deny"), (502, "allow"), (200, None), (200, "forged")],
)
def test_native_response_records_broker_verdict_separately_from_http_status(
    native, settings, monkeypatch, status, verdict
):
    _, task = native
    monkeypatch.setattr(
        "scopelens.execution.zap_active.sign_request",
        lambda *a, **k: SimpleNamespace(model_dump_json=lambda: "{}"),
    )
    headers = {} if verdict is None else {"x-scopelens-zap-decision": verdict}
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(status, headers=headers))
    ) as client:
        result, completed = _forward(
            client, settings, {}, task, "a" * 64, {"method": "GET", "url": task.url}, "token"
        )
    assert result["diagnostics"]["http_status"] == status
    assert result["diagnostics"]["broker_decision"] == (
        verdict if verdict in {"allow", "deny"} else "unknown"
    )
    assert completed == (verdict == "allow" and status < 400)
    assert "x-scopelens-zap-decision" not in result["headers"]


def test_response_body_timeout_preserves_observed_status_and_broker_verdict(
    native, settings, monkeypatch
):
    _, task = native
    monkeypatch.setattr(
        "scopelens.execution.zap_active.sign_request",
        lambda *a, **k: SimpleNamespace(model_dump_json=lambda: "{}"),
    )

    class DelayedBody(httpx.SyncByteStream):
        def __iter__(self):
            raise httpx.ReadTimeout("private timeout detail")
            yield b""  # pragma: no cover - iterator shape only.

    diagnostic = {}
    with (
        httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    502, headers={"x-scopelens-zap-decision": "allow"}, stream=DelayedBody()
                )
            )
        ) as client,
        pytest.raises(httpx.ReadTimeout),
    ):
        _forward(
            client,
            settings,
            {},
            task,
            "a" * 64,
            {"method": "GET", "url": task.url},
            "token",
            diagnostic=diagnostic,
        )
    assert diagnostic == {"phase": "transport", "http_status": 502, "broker_decision": "allow"}
    assert "private" not in json.dumps(diagnostic)
