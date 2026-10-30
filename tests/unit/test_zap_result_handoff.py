"""Finished native results remain readable until their trusted acknowledgement."""

import json
import os
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from scopelens.adapters import zap_active_worker as worker
from scopelens.execution.zap_active import ACK_RESULT, READ_FILE, READ_REQUEST


def script_call(script, root, *args):
    return subprocess.run(
        [sys.executable, "-I", "-c", script.replace("/tmp/zap-active-ipc", str(root)), *args],
        capture_output=True,
        timeout=2,
    )


def test_result_publisher_waits_for_reader_and_ack(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "IPC", tmp_path)
    errors = []
    result = {"site": [{"alerts": []}]}

    def publish():
        try:
            worker.publish_result(result, time.monotonic() + 3)
        except Exception as error:  # noqa: BLE001 - assert the background publisher failure.
            errors.append(error)

    thread = threading.Thread(target=publish)
    thread.start()
    try:
        end = time.monotonic() + 2
        while time.monotonic() < end and not (tmp_path / "result.json").exists():
            time.sleep(0.01)
        assert thread.is_alive(), "Worker exited before the trusted reader collected its output"
        seen = script_call(READ_REQUEST, tmp_path)
        assert seen.returncode == 0 and json.loads(seen.stdout) == {"result_ready": True}
        assert json.loads((tmp_path / "result.json").read_text()) == result
        collected = script_call(READ_FILE, tmp_path, "result.json")
        assert collected.returncode == 0 and json.loads(collected.stdout) == result
        assert (tmp_path / "result.json").stat().st_mode & 0o777 == 0o600
        ack = script_call(ACK_RESULT, tmp_path)
        assert ack.returncode == 0
        thread.join(timeout=2)
        assert not thread.is_alive() and errors == []
        assert not (tmp_path / "result.tmp").exists()
    finally:
        (tmp_path / "result.ack").touch()
        thread.join(timeout=4)


def test_result_ack_wait_cannot_extend_absolute_task_deadline(tmp_path, monkeypatch):
    monkeypatch.setattr(worker, "IPC", tmp_path)
    clock = [10.0]
    monkeypatch.setattr(
        worker,
        "time",
        SimpleNamespace(
            monotonic=lambda: clock[0], sleep=lambda delay: clock.__setitem__(0, clock[0] + delay)
        ),
    )
    with pytest.raises(TimeoutError, match="acknowledgement deadline"):
        worker.publish_result({"site": []}, 10.02)
    assert clock[0] < 10.031
    assert json.loads((tmp_path / "result.json").read_text()) == {"site": []}


def test_reader_rejects_symlink_result_and_ack_writer_does_not_follow_links(tmp_path):
    protected = tmp_path / "protected"
    protected.write_text("unchanged")
    (tmp_path / "result.json").symlink_to(protected)
    assert script_call(READ_REQUEST, tmp_path).returncode == 2
    (tmp_path / "result.ack").symlink_to(protected)
    assert script_call(ACK_RESULT, tmp_path).returncode != 0
    assert protected.read_text() == "unchanged"


@pytest.mark.parametrize("fault", ["symlink", "directory", "fifo", "size", "unknown_name"])
def test_bounded_exec_reader_refuses_unsafe_files_before_output(tmp_path, fault):
    result = tmp_path / "result.json"
    protected = tmp_path / "protected"
    protected.write_text("private-content-must-not-leak")
    name = "result.json"
    if fault == "symlink":
        result.symlink_to(protected)
    elif fault == "directory":
        result.mkdir()
    elif fault == "fifo":
        os.mkfifo(result)
    elif fault == "size":
        result.write_bytes(b"x" * 1_048_577)
    else:
        name = "../protected"
    collected = script_call(READ_FILE, tmp_path, name)
    assert collected.returncode != 0 and collected.stdout == b""
    assert protected.read_text() == "private-content-must-not-leak"
