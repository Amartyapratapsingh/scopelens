"""Faults between grant creation and the first request retain safe evidence."""

import io
import json
import tarfile
from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr

from scopelens.adapters.scanners import ScannerResult
from scopelens.adapters.zap_active import ActiveRulePin, ActiveRuleTask
from scopelens.adapters.zap_active_worker import CONFIG_SHA256
from scopelens.execution import zap_active as launcher
from scopelens.execution.supervisor import WorkerResult


@pytest.mark.parametrize(
    ("status", "code", "observed"),
    [
        ("created", 0, None),
        ("running", 0, None),
        ("paused", 0, None),
        ("dead", 0, None),
        ("exited", 0, 0),
        ("exited", 17, 17),
        ("exited", True, None),
        ("exited", None, None),
    ],
)
def test_only_observed_integer_worker_exits_are_recorded(status, code, observed):
    container = SimpleNamespace(status=status, attrs={"State": {"ExitCode": code}})
    assert launcher._observed_exit(container) == observed


@pytest.mark.parametrize(
    ("fault", "phase", "exception_class", "exit_code"),
    [
        ("create", "launch", "OSError", None),
        ("start", "launch", "RuntimeError", None),
        ("issue", "grant", "ValueError", None),
        ("alive", "grant", "RuntimeError", None),
        ("client", "transport", "ValueError", None),
        ("channel", "read", "ValueError", None),
        ("forward", "transport", "ConnectError", None),
        ("result", "read", "ValueError", 0),
        ("exited", "read", None, 17),
        ("close", "read", None, 0),
        ("remove", "read", None, 0),
        ("success", "read", None, 0),
        ("handoff", "read", None, 0),
        ("broker_denied", "read", None, 1),
        ("upstream_error", "read", None, 1),
        ("unknown_verdict", "read", None, 1),
    ],
)
def test_native_failure_evidence_before_removal(
    settings, monkeypatch, fault, phase, exception_class, exit_code
):
    events = []
    pin = ActiveRulePin(
        rule_id="40012",
        control_id="SL-C03-XSS-01",
        engine_version="2.17.0",
        engine_sha256="2" * 64,
        rule_config_sha256=CONFIG_SHA256,
        allowed_values=("scopelens",),
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

    class Container:
        id = "a" * 64
        status = "created"

        def __init__(self):
            self.attrs = {"State": {"ExitCode": 0}}
            self.reads = 0
            self.acknowledged = False

        def start(self):
            if fault == "start":
                raise RuntimeError("do not retain this sensitive exception text")
            self.status = "running"

        def reload(self):
            self.reads += 1
            if fault == "handoff" and self.acknowledged:
                self.status = "exited"
                self.attrs = {"State": {"ExitCode": exit_code}}
            if fault in {"broker_denied", "upstream_error", "unknown_verdict"} and self.reads > 1:
                self.status = "exited"
                self.attrs = {"State": {"ExitCode": exit_code}}
            if fault in {"result", "exited", "close", "remove", "success"}:
                self.status = "exited"
                self.attrs = {"State": {"ExitCode": exit_code}}

        def exec_run(self, args):
            if args[3] == launcher.READ_FILE:
                assert args[-1] == "local-api.json"
                return 0, json.dumps(
                    {
                        "phase": "local_api",
                        "operation": "core/action/accessUrl",
                        "http_status": None,
                        "exception_class": "ReadTimeout",
                        "deadline_expired": True,
                    }
                ).encode()
            if fault == "handoff":
                if args[3] == launcher.ACK_RESULT:
                    self.acknowledged = True
                    events.append("acknowledged")
                    return 0, b""
                assert args[3] == launcher.READ_REQUEST
                return 0, b'{"result_ready":true}'
            if fault == "channel":
                return 2, b"api.key=unretained-exec-output"
            return 0, json.dumps(
                {"id": "b" * 32, "request": {"method": "GET", "url": task.url}}
            ).encode()

        def get_archive(self, path):
            assert path == "/tmp/zap-active-ipc/local-api.json"
            diagnostic = {
                "phase": "local_api",
                "operation": "core/action/accessUrl",
                "http_status": None,
                "exception_class": "ReadTimeout",
                "deadline_expired": True,
            }
            raw = json.dumps(diagnostic).encode()
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w") as archive:
                member = tarfile.TarInfo("local-api.json")
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
            return iter([buffer.getvalue()]), {}

        def logs(self, **kwargs):
            assert kwargs == {
                "stdout": False,
                "stderr": True,
                "stream": True,
                "follow": False,
                "tail": 40,
            }
            events.append("logs")
            grant_material = b"bare-task-capability" if fault != "issue" else b"no grant minted"
            return iter(
                [
                    b"noise\n" * 1000,
                    b"ValueError: native API refused configuration\n"
                    b"apikey=local-key Cookie: session-value Bearer bearer-value\n"
                    b"bare-egress-credential " + grant_material + b" bare-signing-key\n",
                ]
            )

        def remove(self, **kwargs):
            assert kwargs == {"force": True}
            events.append("removed")
            if fault == "remove":
                raise RuntimeError("private remove failure")

    container = Container()

    def create(**kwargs):
        if fault == "create":
            raise OSError("must not retain this exception body")
        return container

    @contextmanager
    def session(config):
        yield object()

    def issue(*args, **kwargs):
        if fault == "issue":
            raise ValueError("private grant failure")
        return {"grant_id": "grant", "token": "bare-task-capability"}

    def alive(*args, **kwargs):
        if fault == "alive":
            raise RuntimeError("private liveness failure")
        return True

    def close(*args, **kwargs):
        events.append("closed")
        if fault == "close":
            raise RuntimeError("private close failure")

    def result(*args):
        if fault == "handoff":
            assert container.status == "running"
            events.append("result_collected")
            return b'{"site":[]}'
        if fault in {"close", "remove", "success"}:
            return b'{"site":[]}'
        raise ValueError("private archive failure")

    def upstream(request):
        assert request.method == "GET" and str(request.url) == task.url
        if fault == "broker_denied":
            return httpx.Response(403, headers={launcher.ZAP_DECISION_HEADER: "deny"})
        if fault == "upstream_error":
            return httpx.Response(502, headers={launcher.ZAP_DECISION_HEADER: "allow"})
        if fault == "unknown_verdict":
            return httpx.Response(200)
        raise httpx.ConnectError("must not retain transport credentials", request=request)

    real_client = httpx.Client

    def client(**kwargs):
        if fault == "client":
            raise ValueError("private client failure")
        return real_client(transport=httpx.MockTransport(upstream))

    monkeypatch.setattr(launcher, "session_scope", session)
    monkeypatch.setattr(launcher, "issue_grant", issue)
    monkeypatch.setattr(launcher, "grant_live", alive)
    monkeypatch.setattr(launcher, "close_grant", close)
    monkeypatch.setattr(launcher, "reviewed_rule", lambda *args: pin)
    monkeypatch.setattr(
        launcher,
        "sign_request",
        lambda *args, **kwargs: SimpleNamespace(model_dump_json=lambda: "{}"),
    )
    monkeypatch.setattr(launcher, "_read_result", result)
    monkeypatch.setattr(launcher.httpx, "Client", client)
    supervisor = SimpleNamespace(client=SimpleNamespace(containers=SimpleNamespace(create=create)))
    result = launcher.run_task(
        settings.model_copy(
            update={
                "kali_worker_image": "sha256:" + "c" * 64,
                "zap_active_signing_key": SecretStr("bare-signing-key"),
            }
        ),
        supervisor,
        task,
        pin,
        "bare-egress-credential",
    )
    artifact = launcher.append_results(WorkerResult("run", 0, "", "", 0), [result]).artifacts()[0]
    diagnostic = artifact["launcher_diagnostics"]
    assert diagnostic["phase"] == phase and diagnostic["exception_class"] == exception_class
    assert diagnostic["exit_code"] == exit_code
    assert diagnostic["exit_status"] == (
        "observed" if exit_code is not None else "no exit observed"
    )
    assert result.state == ("completed" if fault in {"success", "handoff"} else "error")
    if fault == "handoff":
        assert diagnostic["result_acknowledged"] is True
        assert events.index("result_collected") < events.index("acknowledged")
        assert events.count("result_collected") == 1
    assert set(artifact["data"]) == set(ScannerResult.model_fields)
    assert ("process exit 1" in result.errors) == (exit_code == 1)
    if fault in {"broker_denied", "upstream_error", "unknown_verdict"}:
        expected = {
            "broker_denied": (403, "deny", "native broker denied request: HTTP 403"),
            "upstream_error": (502, "allow", "native upstream HTTP 502; broker allowed request"),
            "unknown_verdict": (200, "unknown", "native broker decision unavailable: HTTP 200"),
        }[fault]
        assert expected[2] in result.errors
        assert len(diagnostic["requests"]) == 1
        assert diagnostic["requests"][0]["http_status"] == expected[0]
        assert diagnostic["requests"][0]["broker_decision"] == expected[1]
    if exit_code is None:
        assert "no exit observed" in result.errors
    if fault != "create":
        assert diagnostic["worker_local_api"] == {
            "phase": "local_api",
            "operation": "core/action/accessUrl",
            "http_status": None,
            "exception_class": "ReadTimeout",
            "deadline_expired": True,
        }
        assert events.index("logs") < events.index("removed")
        assert len(diagnostic["worker_stderr_tail"].encode()) <= launcher.LOG_TAIL_LIMIT
        assert "ValueError: native API refused configuration" in diagnostic["worker_stderr_tail"]
        assert diagnostic["worker_stderr_truncated"]
    if fault not in {"create", "issue"}:
        assert events.index("closed") < events.index("removed")
    if fault == "close":
        assert diagnostic["grant_close_exception_class"] == "RuntimeError"
    if fault == "remove":
        assert diagnostic["worker_remove_exception_class"] == "RuntimeError"
    encoded = json.dumps(artifact)
    for secret in (
        "local-key",
        "session-value",
        "bearer-value",
        "bare-egress-credential",
        "bare-task-capability",
        "bare-signing-key",
        "private",
        "sensitive exception text",
    ):
        assert secret not in encoded


def test_stderr_read_limit_drops_incomplete_line_and_closes_stream():
    events = []

    def chunks():
        try:
            yield b"first complete line\n" + b"apikey=" + b"x" * launcher.LOG_READ_LIMIT
            pytest.fail("stderr collection must stop at its read ceiling")
        finally:
            events.append("closed")

    result = launcher._stderr_tail(SimpleNamespace(logs=lambda **kwargs: chunks()), [])
    assert result["worker_stderr_tail"] == "first complete line\n"
    assert result["worker_stderr_truncated"]
    assert events == ["closed"]


def test_unavailable_worker_logs_report_class_without_exception_text():
    def logs(**kwargs):
        raise OSError("apikey=must-not-leak")

    result = launcher._stderr_tail(SimpleNamespace(logs=logs), [])
    assert result == {
        "worker_stderr_tail": "",
        "worker_stderr_capture": "unavailable",
        "worker_stderr_capture_exception_class": "OSError",
    }
