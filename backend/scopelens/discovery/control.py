"""Persist passive discovery from the coordinator, outside its target transaction."""

from scopelens.domain.evidence import EvidenceOrigin
from scopelens.evidence.intake import record_json_evidence
from scopelens.evidence.store import LocalDiskEvidenceStore
from scopelens.persistence.models import ScanRow
from scopelens.persistence.session import session_scope


def discover_for_scan(settings, scan_id, *, origin):
    if not settings.passive_discovery_enabled:
        return
    with session_scope(settings) as session:
        scan = session.get(ScanRow, scan_id)
        if scan is None or "passive_host_discovery" in (scan.assessment_plan or {}):
            return
    from scopelens.discovery.passive import cached_collect

    snapshot = cached_collect(origin)
    # Only the fixed provider fetch runs outside the transaction. No worker artifact
    # can populate this snapshot or its supervisor evidence provenance.
    with session_scope(settings) as session:
        scan = session.get(ScanRow, scan_id)
        if scan is None or "passive_host_discovery" in (scan.assessment_plan or {}):
            return
        store = LocalDiskEvidenceStore(
            settings.evidence_store_path, settings.evidence_encryption_key.get_secret_value()
        )
        record_json_evidence(
            session,
            settings=settings,
            store=store,
            scan=scan,
            origin=EvidenceOrigin.SUPERVISOR,
            producer="passive_host_discovery",
            payload=snapshot,
            summary="CT/DNS host inventory; zero target HTTP requests",
        )
        scan.assessment_plan = {**(scan.assessment_plan or {}), "passive_host_discovery": snapshot}
