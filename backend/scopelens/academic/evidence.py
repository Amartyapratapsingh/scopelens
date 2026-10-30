"""Load fixed collector captures from intake records with stored provenance and integrity."""

import json

from scopelens.evidence.retention import expired
from scopelens.evidence.store import EvidenceStoreError
from scopelens.persistence.models import TaskRow

PRODUCERS = {
    "reviewed_expansion_capture": "expansion",
    "reviewed_expansion_browser_capture": "expansion_browser",
}


def load_captures(session, scan, rows, store, retention_days):
    """Missing/retired captures remain unproven; damaged snapshots return a generic conflict."""
    import hashlib

    result = []
    for row in rows:
        source = PRODUCERS.get(row.producer)
        if source is None or row.origin != "supervisor":
            continue
        if (
            row.scan_id != scan.id
            or row.scope_version_id != scan.scope_version_id
            or row.scope_content_hash != scan.scope_version.content_hash
            or not row.run_id
            or not row.task_id
            or not row.producer_hash
            or row.truncated
            or row.redaction_state not in {"clean", "redacted"}
            or expired(row, retention_days)
        ):
            continue
        task = session.get(TaskRow, row.task_id)
        if task is None or task.scan_id != scan.id:
            continue
        try:
            content = store.get(row.content_ref)
        except EvidenceStoreError:
            continue
        if hashlib.sha256(content).hexdigest() != row.content_hash:
            raise ValueError("capture integrity mismatch")
        capture = json.loads(content)
        if not isinstance(capture, dict) or capture.get("source") != source:
            raise ValueError("capture provenance mismatch")
        if capture.get("run_id", row.run_id) != row.run_id:
            raise ValueError("capture run mismatch")
        if capture.get("kind") not in {"identity_response", "identity_observation"}:
            continue
        if not isinstance(capture.get("data"), dict):
            raise ValueError("capture data invalid")
        # The persisted intake ID replaces all provisional worker references.
        result.append({**capture, "run_id": row.run_id, "evidence_ref": str(row.id)})
    return result
