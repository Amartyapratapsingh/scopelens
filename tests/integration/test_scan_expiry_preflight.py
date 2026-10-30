"""Expiry during queue wait must settle before worker admission."""

import pytest
from sqlalchemy import text

from scopelens.domain.enums import ScanStatus
from scopelens.execution.coordinator import coordinate
from scopelens.execution.supervisor import RecordingSupervisor
from scopelens.persistence.models import ScanRow

pytestmark = pytest.mark.db


def test_expired_queued_authority_launches_no_worker(settings, queued_scan, db_session):
    scan, task = queued_scan
    # Synthetic clock/authority fault injection on this isolated test DB only.
    db_session.execute(
        text(
            "UPDATE scope_versions SET authorization_expires_at = now() - interval '1 second' WHERE id = :id"
        ),
        {"id": scan.scope_version_id},
    )
    db_session.commit()
    supervisor = RecordingSupervisor()
    result = coordinate(
        settings,
        scan_id=scan.id,
        task_id=task.id,
        attempt_id=task.attempt_id,
        supervisor=supervisor,
    )
    assert result.scan_status == ScanStatus.FAILED
    assert "authorization expired while queued" in result.reason
    assert not supervisor.specs
    db_session.expire_all()
    row = db_session.get(ScanRow, scan.id)
    assert row.started_at is None
    assert row.budget_spent.get("requests", 0) == 0
    assert row.egress_token_hash is None
