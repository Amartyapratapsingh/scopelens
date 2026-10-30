import json
import uuid
from pathlib import Path

from sqlalchemy import select

from scopelens.config import Settings
from scopelens.persistence.models import EvidenceRow, FindingRow, ScanRow
from scopelens.persistence.session import get_session_factory

s = Settings()
ids = json.loads(Path("/tmp/m2_scan_ids.json").read_text())
with get_session_factory(s)() as db:
    for label, identifier in ids.items():
        sid = uuid.UUID(identifier)
        scan = db.get(ScanRow, sid)
        rows = db.scalars(select(EvidenceRow).where(EvidenceRow.scan_id == sid)).all()
        byid = {str(r.id): r for r in rows}
        manifest = next(r for r in rows if r.producer == "capture_manifest")
        assert manifest.task_id and manifest.run_id
        data = json.loads((Path("/app/runs/evidence") / manifest.content_ref).read_text())
        linked = [byid[r] for name, r in data["artifacts"].items() if name.startswith("artifact:")]
        captures = [r for r in linked if r.producer == "reviewed_crawler_capture"]
        assert captures and all(r.task_id and r.run_id and r.producer_hash for r in captures)
        for finding in db.scalars(select(FindingRow).where(FindingRow.scan_id == sid)):
            assert finding.evidence_refs
            assert all(ref in byid for ref in finding.evidence_refs)
            assert all(byid[ref].origin != "untrusted_observation" for ref in finding.evidence_refs)
        assert scan.assessment_plan["discovered_instances"]
        print(
            label,
            len(captures),
            "linked captures; proof references and run/task/source provenance verified",
        )
