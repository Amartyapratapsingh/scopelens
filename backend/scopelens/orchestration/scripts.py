"""Generated analysis is executed only in the dedicated VM and kept untrusted."""

import hashlib
from datetime import UTC, datetime

import httpx
from sqlalchemy import select

from scopelens.broker.policy import scan_for_token
from scopelens.domain.evidence import EvidenceOrigin
from scopelens.evidence.intake import record_json_evidence
from scopelens.evidence.store import LocalDiskEvidenceStore
from scopelens.execution.leases import lease_is_live
from scopelens.orchestration.models import call_model
from scopelens.persistence.models import ScanRow
from scopelens.persistence.session import session_scope


def analyze_local(settings, scan_id, artifacts, *, token):
    if not settings.generated_scripts_enabled:
        return {"state": "disabled"}
    # No screenshots, credentials, full page bodies or answers enter generated analysis.
    summary = {
        "responses": [
            {
                "route": a["data"].get("route"),
                "status": a["data"].get("status"),
                "content_type": a["data"].get("content_type"),
            }
            for a in artifacts
            if a.get("kind") == "response"
        ][:100]
    }
    proposal = call_model(settings, scan_id, "script", summary)
    if proposal.get("state") != "completed":
        return proposal
    script = proposal["value"]
    digest = hashlib.sha256(script["source"].encode()).hexdigest()
    with session_scope(settings) as db:
        scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
        if (
            not scan
            or scan.cancel_requested_at
            or scan.egress_token_epoch != scan.cancel_epoch
            or scan_for_token(db, token) is None
            or not lease_is_live(db, scan_id)
            or scan.scope_version.authorization_expires_at <= datetime.now(UTC)
        ):
            return {"state": "cancelled"}
        # Persist intent before crossing the VM boundary. A lost call is never replayed.
        prior = (scan.assessment_plan or {}).get("generated_analysis")
        if prior:
            return {"state": "already_attempted"}
        scan.assessment_plan = {
            **(scan.assessment_plan or {}),
            "generated_analysis": {
                "state": "outcome_unknown",
                "source_hash": digest,
                "network": "none",
            },
        }
    try:
        response = httpx.post(
            settings.sandbox_gateway_url.rstrip("/") + "/execute",
            headers={"Authorization": "Bearer " + settings.session_secret.get_secret_value()},
            json={
                "scan_id": str(scan_id),
                "source": script["source"],
                "language": script["language"],
                "artifacts": summary,
                "network": "none",
            },
            timeout=28,
            trust_env=False,
            follow_redirects=False,
        )
        response.raise_for_status()
        result = response.json()
    except (httpx.HTTPError, ValueError):
        result = {"state": "outcome_unknown", "reason": "sandbox gateway unavailable"}
    with session_scope(settings) as db:
        scan = db.get(ScanRow, scan_id)
        record = record_json_evidence(
            db,
            settings=settings,
            store=LocalDiskEvidenceStore(
                settings.evidence_store_path,
                settings.evidence_encryption_key.get_secret_value()
                if settings.evidence_encryption_key
                else None,
            ),
            scan=scan,
            origin=EvidenceOrigin.UNTRUSTED_OBSERVATION,
            producer="generated_artifact_analysis",
            producer_hash=digest,
            payload=result,
            summary="Untrusted output from a generated local-artifact script",
        )
        scan.assessment_plan = {
            **(scan.assessment_plan or {}),
            "generated_analysis": {
                "state": result.get("state"),
                "source_hash": digest,
                "network": "none",
                "evidence_ref": record.id,
                "trusted": False,
            },
        }
    return result
