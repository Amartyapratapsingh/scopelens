"""Interleave the real IPC reader with the worker's actual bridge publication."""

import json
import os
import subprocess
import sys

import pytest

from scopelens.adapters import zap_active_worker as worker
from scopelens.adapters.zap_active import ActiveRulePin, ActiveRuleTask
from scopelens.execution.zap_active import READ_REQUEST


def read_request(root):
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            READ_REQUEST.replace("/tmp/zap-active-ipc/requests", str(root)),
        ],
        capture_output=True,
        timeout=2,
        check=False,
    )


def test_reader_cannot_observe_partial_bridge_request(tmp_path, monkeypatch):
    requests = tmp_path / "requests"
    requests.mkdir()
    (tmp_path / "responses").mkdir()
    identity = "a" * 32
    request = {"method": "GET", "url": "http://172.28.0.11/xss?q=scopelens"}
    observations = {}
    events = []
    real_open, real_fdopen = worker.Path.open, os.fdopen
    real_fsync, real_replace = os.fsync, os.replace

    class PausedWriter:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def write(self, value):
            half = len(value) // 2
            self.stream.write(value[:half])
            self.stream.flush()
            observations["partial"] = read_request(requests)
            self.stream.write(value[half:])
            return len(value)

        def flush(self):
            events.append("flush")
            self.stream.flush()

        def fileno(self):
            return self.stream.fileno()

    def open_path(path, *args, **kwargs):
        stream = real_open(path, *args, **kwargs)
        if path.parent == requests and "w" in kwargs.get("mode", args[0] if args else "r"):
            return PausedWriter(stream)
        return stream

    def fsync(fd):
        assert events == ["flush"]
        events.append("fsync")
        real_fsync(fd)

    def replace(source, destination):
        assert source.parent == destination.parent == requests
        assert events == ["flush", "fsync"]
        assert os.stat(source).st_mode & 0o777 == 0o600
        observations["before_rename"] = read_request(requests)
        real_replace(source, destination)
        observations["published"] = read_request(requests)

    monkeypatch.setattr(worker, "IPC", tmp_path)
    monkeypatch.setattr(worker.secrets, "token_hex", lambda size: identity)
    monkeypatch.setattr(worker.Path, "open", open_path)
    monkeypatch.setattr(
        os, "fdopen", lambda *args, **kwargs: PausedWriter(real_fdopen(*args, **kwargs))
    )
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    bridge = worker.Bridge.__new__(worker.Bridge)
    bridge.path, bridge.headers, bridge.deadline = request["url"], {}, 0
    bridge.pin = ActiveRulePin(
        rule_id="40012",
        control_id="SL-C03-XSS-01",
        engine_version="2.17.0",
        engine_sha256="2" * 64,
        rule_config_sha256=worker.CONFIG_SHA256,
        allowed_values=("scopelens",),
        max_requests=2,
        deadline_seconds=5,
    )
    bridge.task = ActiveRuleTask(
        scan_id="00000000-0000-0000-0000-000000000001",
        task_id="test",
        input_id="input",
        rule_id="40012",
        url=request["url"],
        input_name="q",
        rule_config_sha256=worker.CONFIG_SHA256,
        max_requests=2,
        deadline_seconds=5,
    )
    bridge.send_error = lambda status: None
    bridge.do_GET()
    for stage in ("partial", "before_rename"):
        result = observations[stage]
        assert result.returncode == 0, result.stderr.decode()
        assert json.loads(result.stdout) == {}
    result = observations["published"]
    assert result.returncode == 0, result.stderr.decode()
    assert json.loads(result.stdout) == {"id": identity, "request": request}
    assert list(requests.iterdir()) == []


def test_failed_fsync_removes_unpublished_file(tmp_path, monkeypatch):
    requests = tmp_path / "requests"
    requests.mkdir()
    monkeypatch.setattr(worker, "IPC", tmp_path)

    def fail(fd):
        raise OSError("fixture fsync failure")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(OSError):
        worker.publish_request("a" * 32, {"method": "GET", "url": "http://172.28.0.11/"})
    assert list(requests.iterdir()) == []
    assert json.loads(read_request(requests).stdout) == {}


def test_temporary_collision_does_not_follow_or_remove_symlink(tmp_path, monkeypatch):
    requests = tmp_path / "requests"
    requests.mkdir()
    destination = tmp_path / "protected"
    destination.write_text("unchanged")
    temporary = requests / ("a" * 32 + ".tmp")
    temporary.symlink_to(destination)
    monkeypatch.setattr(worker, "IPC", tmp_path)
    with pytest.raises(OSError):
        worker.publish_request("a" * 32, {"method": "GET", "url": "http://172.28.0.11/"})
    assert destination.read_text() == "unchanged"
    assert temporary.is_symlink()
    assert json.loads(read_request(requests).stdout) == {}


@pytest.mark.parametrize("name", ["unexpected.tmp", "a" * 32 + ".partial", "a" * 32 + "Xjson"])
def test_reader_still_rejects_unrecognized_files(tmp_path, name):
    (tmp_path / name).write_text("{}")
    assert read_request(tmp_path).returncode == 2


def test_reader_still_caps_directory_entries_including_temporary_files(tmp_path):
    for number in range(33):
        (tmp_path / (f"{number:032x}" + ".tmp")).write_text("partial")
    assert read_request(tmp_path).returncode == 2


def test_oversized_request_never_creates_a_file(tmp_path, monkeypatch):
    requests = tmp_path / "requests"
    requests.mkdir()
    monkeypatch.setattr(worker, "IPC", tmp_path)
    with pytest.raises(ValueError, match="size limit"):
        worker.publish_request("a" * 32, {"url": "x" * 16384})
    assert list(requests.iterdir()) == []
