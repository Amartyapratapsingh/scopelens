"""Deployed read-only recovery gate using explicitly injected synthetic pending intents.

No mutation is sent or replayed. The two unique fence rows are test records, not real
interrupted scans. Both are eventually verified through the normal recovery API, so
teardown does not relabel any historical fence. Target authority is fixed to the owned
labs-browser-workflows service; this command accepts no external URL.
"""

import argparse
import json
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from scripts.verify_authenticated_inputs_lab import FIXTURE_PASSWORD

from scopelens.broker.policy import BrokerRequest, authorize, issue_egress_token, revoke_egress
from scopelens.config import Settings
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.recovery import RECOVERY_PRODUCER, RecoverySpec, evaluate_recovery
from scopelens.persistence.models import CleanupRow, ScanRow, ScopeVersionRow
from scopelens.persistence.repositories import create_scan_row, record_audit
from scopelens.persistence.session import session_scope
from scopelens.scope.dns import StaticResolver


def configuration(scope, reference, nonce, *, original=False):
    base = scope["origin"] + "/bad"
    result = {
        "scope_version_id": scope["id"],
        "identities": [
            {
                "id": "A",
                "role": "fixture-owner",
                "login": {
                    "request": {
                        "method": "POST",
                        "url": base + "/credential-login",
                        "json_body": {"role": "A"},
                        "secret_fields": {"password": reference},
                    }
                },
                "probe": {"request": {"url": base + "/identity"}, "expected_identity": "A"},
            }
        ],
    }
    if original:
        result["workflows"] = [
            {
                "id": f"recovery_{nonce}_{name}",
                "family": "mass_assignment",
                "resource_id": f"synthetic-recovery-{nonce}-{name}",
                "action_grant_id": "owned-recovery-fixture-never-executed",
                "authority": "lab",
                "disposable": True,
                "synchronous_write": True,
                "actor_identity": "A",
                "owner_identity": "A",
                "cleanup_identity": "A",
                "readback": {"url": base + "/record"},
                "seed": {"pointer": "/seed", "value": "scopelens-disposable-record"},
                "before": {"pointer": "/content", "value": ""},
                "forbidden_after": {"pointer": "/content", "value": "never-sent-synthetic-value"},
                "mutation": {"method": "POST", "url": base + "/mutate"},
                "cleanup": {"method": "POST", "url": base + "/cleanup"},
            }
            for name in ("first", "second")
        ]
    return result


def inject_pending_intents(settings, scope, config):
    """Explicit fault injection, transactionally audited; does not enqueue original work."""
    with session_scope(settings) as db:
        registered = db.get(ScopeVersionRow, uuid.UUID(scope["id"]))
        source = create_scan_row(
            db,
            operator_id=registered.operator_id,
            scope_version=registered,
            score_version=settings.score_version,
        )
        source.assessment_plan = {
            "expansion_config": config["configuration"],
            "configuration_id": config["id"],
            "configuration_hash": config["content_hash"],
            "synthetic_recovery_gate": True,
        }
        old_token = issue_egress_token(db, scan=source)
        revoke_egress(db, scan=source)
        source.status = "cancelled"
        source.cancel_requested_at = source.cancelled_at = source.finished_at = datetime.now(UTC)
        source.status_reason = "Synthetic recovery gate: pending intent injected; no mutation or target scan was executed"
        fences = []
        for recipe in config["configuration"]["workflows"]:
            fence = CleanupRow(
                scope_version_id=registered.id,
                scan_id=source.id,
                recipe_id=recipe["id"],
                resource_id=recipe["resource_id"],
                state="pending",
            )
            db.add(fence)
            db.flush()
            fences.append(str(fence.id))
        record_audit(
            db,
            actor="owned-lab-recovery-gate",
            action="lab.recovery.intent.inject",
            subject_type="scan",
            subject_id=str(source.id),
            outcome="synthetic",
            detail={
                "synthetic": True,
                "mutation_sent": False,
                "cleanup_ids": fences,
                "note": "Dedicated synthetic pending intents only; historical rows and target records untouched",
            },
        )
        target = urlsplit(scope["origin"])
        denial = authorize(
            db,
            settings=settings,
            request=BrokerRequest(
                method="GET",
                scheme=target.scheme,
                host=target.hostname,
                port=target.port or 80,
                path="/bad/record",
                egress_token=old_token,
            ),
            resolver=StaticResolver({}),
        )
        assert not denial.allowed and denial.reason == "revoked_egress_token"
        return str(source.id), fences


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/cleanup-recovery-deployed"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    settings = Settings()
    nonce = secrets.token_hex(8)
    expires = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    with httpx.Client(
        base_url="http://127.0.0.1:8090", timeout=30, follow_redirects=False
    ) as client:

        def post(path, body):
            response = client.post(path, json=body)
            response.raise_for_status()
            return response.json()

        def get(path):
            response = client.get(path)
            response.raise_for_status()
            return response.json()

        post(
            "/api/auth/login",
            {
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        scope_body = {
            "authority_domain": "lab",
            "scheme": "http",
            "lab_service": "labs-browser-workflows",
            "lab_port": 8080,
            "allowed_methods": ["GET", "HEAD", "POST"],
            "allowed_check_profile": "staging-stateful-v1",
            "authorization_expires_at": expires,
            "owner_note": "Synthetic read-only recovery gate; never execute original mutations",
        }
        original_scope = post("/api/scopes", scope_body)
        original_secret = post(
            "/api/assessments/credentials",
            {
                "scope_version_id": original_scope["id"],
                "value": FIXTURE_PASSWORD,
                "expires_at": expires,
            },
        )
        original_config = post(
            "/api/assessments/configurations",
            configuration(original_scope, original_secret["reference"], nonce, original=True),
        )
        source_id, cleanup_ids = inject_pending_intents(settings, original_scope, original_config)
        # This is a NEW authorization revision and separately stored credential reference.
        fresh_scope = post("/api/scopes", scope_body)
        assert (
            fresh_scope["id"] != original_scope["id"]
            and fresh_scope["origin"] == original_scope["origin"]
        )
        fresh_secret = post(
            "/api/assessments/credentials",
            {
                "scope_version_id": fresh_scope["id"],
                "value": FIXTURE_PASSWORD,
                "expires_at": expires,
            },
        )
        frozen = configuration(fresh_scope, fresh_secret["reference"], nonce)
        AssessmentConfiguration.model_validate(frozen)
        fresh_config = post("/api/assessments/configurations", frozen)
        receipts = []
        (args.output / "synthetic-intent.json").write_text(
            json.dumps(
                {
                    "source_scan_id": source_id,
                    "cleanup_ids": cleanup_ids,
                    "synthetic_pending_intent": True,
                    "mutation_sent": False,
                    "old_token_denial": "revoked_egress_token",
                    "old_token_check": "in-process broker policy against persisted revoked scan",
                },
                indent=2,
            )
        )
        for index, cleanup_id in enumerate(cleanup_ids):
            created = post(
                "/api/cleanup-recoveries",
                {
                    "cleanup_id": cleanup_id,
                    "scope_version_id": fresh_scope["id"],
                    "assessment_configuration_id": fresh_config["id"],
                },
            )
            scan_id = created["id"]
            print(f"synthetic recovery {index + 1}: {scan_id}", flush=True)
            deadline = time.monotonic() + 600
            while time.monotonic() < deadline:
                view = get(f"/api/cleanup-recoveries/{scan_id}")
                if view["status"] in {"completed", "completed_partial", "failed", "cancelled"}:
                    break
                time.sleep(2)
            else:
                post(f"/api/scans/{scan_id}/cancel", {})
                raise AssertionError(
                    "recovery deadline exceeded; fresh scan cancelled and fence retained"
                )
            assert view["status"] == "completed" and view["result"]["verified"], view
            metadata = get(f"/api/scans/{scan_id}/evidence")
            selected = next(row for row in metadata if row["id"] == view["result"]["evidence_ref"])
            assert selected["trusted"] and selected["producer"] == RECOVERY_PRODUCER
            artifact = get(f"/api/scans/{scan_id}/evidence/{selected['id']}/download")
            with session_scope(settings) as db:
                recovered = db.get(ScanRow, uuid.UUID(scan_id))
                spec = RecoverySpec.model_validate(recovered.assessment_plan["cleanup_recovery"])
                assert evaluate_recovery(spec, artifact)[0]
                assert recovered.scope_version_id == uuid.UUID(fresh_scope["id"])
                assert db.get(CleanupRow, uuid.UUID(cleanup_id)).state == "clean"
                if index == 0:
                    assert db.get(CleanupRow, uuid.UUID(cleanup_ids[1])).state == "pending"
            serialized = json.dumps({"view": view, "evidence": artifact})
            assert FIXTURE_PASSWORD not in serialized and "sid=A" not in serialized
            (args.output / f"recovery-{index + 1}.json").write_text(serialized)
            receipts.append(
                {
                    "scan_id": scan_id,
                    "cleanup_id": cleanup_id,
                    "state": "clean",
                    "proof_ref": selected["id"],
                }
            )
            (args.output / "receipts.json").write_text(json.dumps(receipts, indent=2))
            print(
                "  original fence released from fresh trusted readback; no mutation sent",
                flush=True,
            )


if __name__ == "__main__":
    main()
