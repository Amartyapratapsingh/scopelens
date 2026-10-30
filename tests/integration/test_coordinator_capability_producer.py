"""Trusted coordinator persists image measurements under live scan authority."""

from unittest.mock import Mock

import pytest
from sqlalchemy import select

from scopelens.execution.capability_producer import source_digest
from scopelens.execution.coordinator import _measure_capabilities, _prepare
from scopelens.execution.supervisor import DockerWorkerSupervisor, SupervisorError
from scopelens.persistence.models import AuditEventRow, ScanRow
from scopelens.writer.report import _capabilities

pytestmark = pytest.mark.db
IMAGE = "sha256:" + "1" * 64


def setup(settings, queued_scan, monkeypatch):
    scan, task = queued_scan
    _, scope, _, _ = _prepare(settings, scan_id=scan.id, task_id=task.id)
    image = Mock()
    image.id, image.attrs = IMAGE, {"Architecture": "arm64"}
    client = Mock()
    client.images.get.return_value = image
    container = client.containers.run.return_value
    container.image.id = IMAGE
    container.wait.return_value = {"StatusCode": 0}
    import json

    container.logs.return_value = [
        json.dumps(
            {
                "version": "runtime-probe-v2",
                "role": "tool",
                "tools": [],
                "source_sha256": source_digest(),
            }
        ).encode()
    ]
    configured = settings.model_copy(
        update={
            "scanner_tools_enabled": False,
            "browser_enabled": False,
            "tool_worker_image": "mutable:tag",
        }
    )
    return scan, scope, client, configured


def test_measurement_persists_before_execution_and_pins_worker_image(
    settings, queued_scan, db_session, monkeypatch
):
    scan, scope, client, configured = setup(settings, queued_scan, monkeypatch)
    updated = _measure_capabilities(
        configured, DockerWorkerSupervisor(configured, client=client), scan_id=scan.id, scope=scope
    )
    assert updated.tool_worker_image == IMAGE
    db_session.refresh(scan)
    frozen = scan.assessment_plan
    snapshot = frozen["capability_snapshot"]
    assert snapshot["installation_complete"] and snapshot["runtime_inventory_complete"]
    assert snapshot["candidate_fingerprint"] == source_digest()
    public = _capabilities(
        frozen, scan.profile, scan_id=str(scan.id), scope_version_id=str(scan.scope_version_id)
    )
    assert public["installed_tools"]["count"] == 0
    assert public["executable_checks"]["count"] is not None
    assert public["independently_qualified_families"]["count"] is None
    assert db_session.scalar(
        select(AuditEventRow).where(AuditEventRow.action == "capability.measurement")
    )
    assert not db_session.get(ScanRow, scan.id).budget_spent.get("requests", 0)


def test_probe_failure_removes_stale_claim_instead_of_measuring_absence(
    settings, queued_scan, db_session, monkeypatch
):
    scan, scope, client, configured = setup(settings, queued_scan, monkeypatch)
    supervisor = DockerWorkerSupervisor(configured, client=client)
    _measure_capabilities(configured, supervisor, scan_id=scan.id, scope=scope)
    client.containers.run.return_value.logs.return_value = [b"malformed"]
    _measure_capabilities(configured, supervisor, scan_id=scan.id, scope=scope)
    db_session.refresh(scan)
    assert "capability_snapshot" not in scan.assessment_plan
    assert scan.assessment_plan["capability_measurement"]["installation_complete"] is False


def test_cancellation_during_probe_cannot_persist_capability_claim(
    settings, queued_scan, db_session, monkeypatch
):
    scan, scope, client, configured = setup(settings, queued_scan, monkeypatch)

    def revoke(*_, **__):
        db_session.refresh(scan)
        scan.cancel_epoch += 1
        db_session.commit()
        return {"StatusCode": 0}

    client.containers.run.return_value.wait.side_effect = revoke
    with pytest.raises(SupervisorError, match="authority revoked"):
        _measure_capabilities(
            configured,
            DockerWorkerSupervisor(configured, client=client),
            scan_id=scan.id,
            scope=scope,
        )
    db_session.refresh(scan)
    assert "capability_snapshot" not in scan.assessment_plan
