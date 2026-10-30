"""Isolated local fault controls and read-only driver restrictions.

These tests do not stand in for deployed supervisor/intake recovery evidence.
"""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from uuid import uuid4

import httpx
import pytest
from labs.academic_faults.app import FLAGS, handler
from labs.academic_faults.scenarios import ORIGIN, SERVICE, configuration
from labs.academic_workflows.app import BASELINE, PASSWORD
from labs.academic_workflows.scenarios import write_recipe
from tests.test_academic_workflows import capture_into, sessions

from scopelens.workflows.assessment import run_workflow
from scopelens.workflows.cleanup import SQLiteCleanupJournal


@contextmanager
def fault_lab(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        (tmp_path / "release-mutation").touch()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_failed_reset_keeps_real_proof_and_fences_other_property(tmp_path):
    with fault_lab(tmp_path) as origin, sessions(origin) as clients, sessions(origin) as cleanup:
        journal = SQLiteCleanupJournal(tmp_path / "journal.sqlite")
        evidence = []
        marks = run_workflow(
            write_recipe(origin, "marks"),
            clients,
            cleanup,
            journal,
            capture_into(evidence),
            admit=lambda _: True,
        )
        assert marks.state == "confirmed" and marks.cleanup_state == "cleanup_failed"
        assert any(r["kind"] == "cleanup" and r["status"] == 503 for r in evidence)
        other = run_workflow(
            write_recipe(origin, "attendance"),
            clients,
            cleanup,
            journal,
            capture_into(evidence),
            admit=lambda _: True,
        )
        assert other.state == "blocked"
        rows = [json.loads(line) for line in (tmp_path / "requests.jsonl").read_text().splitlines()]
        assert len([r for r in rows if r["path"] == "/records/student_a/marks"]) == 1
        assert not any(r["path"] == "/records/student_a/attendance" for r in rows)
        serialized = json.dumps(rows)
        assert PASSWORD not in serialized and "sid=" not in serialized


def test_hold_marker_follows_applied_write_and_requires_local_release(tmp_path):
    (tmp_path / "hold-mutation").touch()
    with (
        fault_lab(tmp_path) as origin,
        httpx.Client(base_url=origin, trust_env=False, timeout=5) as client,
    ):
        assert (
            client.post("/login", json={"username": "student_b", "password": PASSWORD}).status_code
            == 200
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(client.post, "/records/student_a/marks", json={"value": 99})
            deadline = time.monotonic() + 2
            while not (tmp_path / "mutation-applied").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert (tmp_path / "mutation-applied").exists()
            assert not result.done(), "fault must hold the applied mutation's response"
            (tmp_path / "release-mutation").touch()
            assert result.result().status_code == 200
        view = client.get("/records/student_a").json()
        assert view["marks"] == 99
        assert client.post("/records/student_a/reset").status_code == 403
        assert (
            client.post("/login", json={"username": "staff", "password": PASSWORD}).status_code
            == 200
        )
        assert client.post("/records/student_a/reset").status_code == 503
        (tmp_path / "allow-reset").touch()
        assert client.post("/records/student_a/reset").status_code == 200
        assert client.get("/records/student_a").json()["marks"] == BASELINE["marks"]
        assert client.post("/admin/allow-reset").status_code == 404


def test_exact_fault_binding_reuses_academic_identity_and_resource_contract():
    scope = {"id": str(uuid4()), "origin": ORIGIN, "lab_binding": {"service": SERVICE}}
    value = configuration(scope, "encrypted-fault-credential", "marks")
    workflow = value["workflows"][0]
    assert workflow["resource_id"] == "student-a-record"
    assert workflow["owner_identity"] == workflow["cleanup_identity"] == "staff"
    assert workflow["mutation"]["url"] == ORIGIN + "/records/student_a/marks"
    assert value["identities"][2]["probe"]["request"]["url"] == ORIGIN + "/me"
    fresh = configuration(scope, "fresh-encrypted-reference")
    assert not fresh["workflows"]
    for origin in ("https://customer.test", "http://172.28.0.22:8080", ORIGIN + "/evil"):
        with pytest.raises(ValueError, match="exact owned lab binding"):
            configuration({**scope, "origin": origin}, "reference", "marks")
    with pytest.raises(ValueError):
        configuration({**scope, "lab_binding": {"service": "labs-academic-a"}}, "reference")


def test_unknown_lifecycle_flag_cannot_execute_container_command(monkeypatch):
    from scripts import verify_academic_recovery_lab as driver

    monkeypatch.setattr(driver, "docker_python", lambda _: pytest.fail("unknown flag executed"))
    assert {"hold-mutation", "release-mutation", "allow-reset"} == FLAGS
    with pytest.raises(ValueError, match="unknown"):
        driver.lifecycle_flag("../../other-container")


def test_queued_scan_directory_cannot_replay_original_mutation(monkeypatch, tmp_path):
    import sys

    from scripts import verify_academic_recovery_lab as driver

    (tmp_path / "failure-queued.json").write_text(json.dumps({"scan_id": str(uuid4())}))
    monkeypatch.setattr(sys, "argv", ["gate", "--output", str(tmp_path)])
    monkeypatch.setattr(driver, "Settings", lambda: pytest.fail("replay reached backend setup"))
    with pytest.raises(SystemExit, match="Original mutations must not be replayed"):
        driver.main()


def test_fixture_telemetry_counts_every_record_write():
    from scripts.verify_academic_recovery_lab import fixture_writes

    rows = [
        {"method": "POST", "path": "/login", "status": 200},
        {"method": "GET", "path": "/records/student_a", "status": 200},
        {"method": "POST", "path": "/records/student_a/profile", "status": 200},
        {"method": "POST", "path": "/records/student_a/reset", "status": 503},
    ]
    assert fixture_writes(rows) == rows[2:]
