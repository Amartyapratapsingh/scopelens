"""Recovery keeps the old resource fenced until fresh, trusted readback proves restoration."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from scopelens.domain.enums import ProfileName
from scopelens.domain.evidence import EvidenceOrigin
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import IdentityProfile
from scopelens.domain.workflow import WorkflowRecipe
from scopelens.evidence.intake import record_json_evidence
from scopelens.execution.leases import acquire_lease
from scopelens.execution.ledger import create_scan_with_task
from scopelens.expansion.recovery import (
    RECOVERY_PRODUCER,
    RECOVERY_TASK_TYPE,
    RecoveryRefused,
    collect_recovery,
    digest,
    evaluate_recovery,
    finalize_recovery,
    prepare_recovery,
    queue_recovery,
)
from scopelens.persistence.models import (
    AssessmentConfigurationRow,
    AuditEventRow,
    CleanupRow,
    EvidenceRow,
    OutboxEventRow,
    ScopeVersionRow,
)
from scopelens.persistence.repositories import scope_row_to_domain

pytestmark = pytest.mark.db


def copy_scope(base, **changes):
    fields = {
        column.name: getattr(base, column.name) for column in ScopeVersionRow.__table__.columns
    }
    fields.update(
        id=uuid.uuid4(),
        version=base.version + 1,
        content_hash=uuid.uuid4().hex * 2,
        created_at=datetime.now(UTC),
    )
    fields.update(changes)
    return ScopeVersionRow(**fields)


@pytest.fixture
def recovery_rows(db_session, lab_scope, settings):
    old_scope = copy_scope(
        lab_scope,
        allowed_check_profile=ProfileName.STAGING_STATEFUL_V1.value,
        allowed_methods=["GET", "HEAD", "POST"],
    )
    db_session.add(old_scope)
    db_session.flush()
    origin = scope_row_to_domain(old_scope).origin
    identity = IdentityProfile.model_validate(
        {
            "id": "A",
            "role": "owner",
            "login": {
                "request": {"method": "POST", "url": origin + "/login", "json_body": {"role": "A"}}
            },
            "probe": {"request": {"url": origin + "/identity"}, "expected_identity": "A"},
        }
    )
    recipe = WorkflowRecipe.model_validate(
        {
            "id": "original-flow",
            "family": "mass_assignment",
            "resource_id": "original-resource",
            "action_grant_id": "owned-fixture",
            "authority": "lab",
            "disposable": True,
            "synchronous_write": True,
            "actor_identity": "A",
            "owner_identity": "A",
            "cleanup_identity": "A",
            "readback": {"url": origin + "/record"},
            "seed": {"pointer": "/seed", "value": "owned-synthetic-record"},
            "before": {"pointer": "/content", "value": ""},
            "forbidden_after": {"pointer": "/content", "value": "changed"},
            "mutation": {"method": "POST", "url": origin + "/mutate"},
            "cleanup": {"method": "POST", "url": origin + "/cleanup"},
        }
    )
    original_config = AssessmentConfiguration(
        scope_version_id=old_scope.id, identities=(identity,), workflows=(recipe,)
    )
    original, _ = create_scan_with_task(
        db_session,
        operator_id=old_scope.operator_id,
        scope_version=old_scope,
        score_version=settings.score_version,
    )
    original.status = "cancelled"
    original.cancel_requested_at = datetime.now(UTC)
    original.cancel_epoch, original.egress_token_epoch = 1, 0
    original.egress_token_hash = "old-revoked-hash"
    original.assessment_plan = {"expansion_config": original_config.model_dump(mode="json")}
    cleanup = CleanupRow(
        scope_version_id=old_scope.id,
        scan_id=original.id,
        resource_id=recipe.resource_id,
        recipe_id=recipe.id,
        state="mutation_sent",
    )
    other = CleanupRow(
        scope_version_id=old_scope.id,
        scan_id=original.id,
        resource_id="different-resource",
        recipe_id=recipe.id,
        state="cleanup_failed",
    )
    fresh_scope = copy_scope(old_scope)
    db_session.add_all([cleanup, other, fresh_scope])
    db_session.flush()
    fresh = AssessmentConfiguration(scope_version_id=fresh_scope.id, identities=(identity,))
    configuration = AssessmentConfigurationRow(
        operator_id=fresh_scope.operator_id,
        scope_version_id=fresh_scope.id,
        configuration=fresh.model_dump(mode="json"),
        content_hash=digest(fresh.model_dump(mode="json")),
    )
    db_session.add(configuration)
    db_session.commit()
    return SimpleNamespace(
        cleanup=cleanup,
        other=other,
        original=original,
        old_scope=old_scope,
        fresh_scope=fresh_scope,
        fresh=fresh,
        configuration=configuration,
    )


def queue(db, rows, settings):
    return queue_recovery(
        db,
        rows.cleanup,
        rows.original,
        rows.old_scope,
        rows.fresh_scope,
        rows.fresh,
        actor="operator",
        score_version=settings.score_version,
    )


def collect(spec, *, status=200, restored=True, wrong_identity=False, cancel=False):
    sent = []

    def handle(request):
        sent.append((request.method, request.url.path))
        if request.url.path == "/login":
            return httpx.Response(200, headers={"Set-Cookie": "sid=synthetic-A; Path=/"}, json={})
        if request.url.path == "/identity":
            return httpx.Response(200, json={"identity": "B" if wrong_identity else "A"})
        assert request.url.path == "/record"
        return httpx.Response(
            status,
            json={"seed": "owned-synthetic-record", "content": "" if restored else "changed"},
        )

    result = collect_recovery(
        spec,
        lambda role: httpx.Client(transport=httpx.MockTransport(handle)),
        lambda ref: pytest.fail("old credentials must not be reused"),
        cancelled=lambda: cancel,
    )
    return result, sent


@pytest.mark.parametrize(
    "change",
    [
        "old_scope",
        "origin",
        "authority",
        "owner",
        "expired",
        "wrong_configuration",
        "identity",
        "identity_probe",
        "running_original",
        "path_denied",
    ],
)
def test_queue_rejects_changed_authority_or_identity(recovery_rows, change):
    r = recovery_rows
    scope, config = r.fresh_scope, r.fresh
    if change == "old_scope":
        scope = r.old_scope
    elif change == "origin":
        scope = copy_scope(scope, host="127.0.0.1")
    elif change == "authority":
        scope = copy_scope(scope, authority_domain="production", lab_binding=None)
    elif change == "owner":
        scope = copy_scope(scope, operator_id=uuid.uuid4())
    elif change == "expired":
        scope = copy_scope(scope, authorization_expires_at=datetime.now(UTC) - timedelta(seconds=1))
    elif change == "wrong_configuration":
        config = config.model_copy(update={"scope_version_id": uuid.uuid4()})
    elif change == "identity":
        config = config.model_copy(
            update={"identities": (config.identities[0].model_copy(update={"role": "different"}),)}
        )
    elif change == "identity_probe":
        profile = config.identities[0]
        config = config.model_copy(
            update={
                "identities": (
                    profile.model_copy(
                        update={
                            "probe": profile.probe.model_copy(update={"expected_identity": "B"})
                        }
                    ),
                )
            }
        )
    elif change == "running_original":
        r.original.status = "testing"
    elif change == "path_denied":
        scope = copy_scope(scope, excluded_paths=["/record"])
        config = config.model_copy(update={"scope_version_id": scope.id})
    with pytest.raises(RecoveryRefused):
        prepare_recovery(
            r.cleanup, r.original, r.old_scope, scope, config, recovery_scan_id=uuid.uuid4()
        )
    assert r.cleanup.state == "mutation_sent"


def test_queue_is_durable_fresh_and_contains_no_mutation_authority(
    db_session, recovery_rows, settings
):
    scan, task, spec = queue(db_session, recovery_rows, settings)
    db_session.commit()
    assert (
        scan.id != recovery_rows.original.id
        and scan.scope_version_id == recovery_rows.fresh_scope.id
    )
    assert scan.egress_token_hash is None and scan.cancel_epoch == 0
    assert task.task_type == RECOVERY_TASK_TYPE
    frozen = scan.assessment_plan
    assert (
        not frozen["expansion_config"]["workflows"]
        and not frozen["expansion_config"]["browser_workflows"]
    )
    assert "/mutate" not in json.dumps(frozen) and "/cleanup" not in json.dumps(frozen)
    assert db_session.scalar(
        select(OutboxEventRow).where(OutboxEventRow.payload["scan_id"].astext == str(scan.id))
    )
    assert recovery_rows.cleanup.state == "mutation_sent"
    with pytest.raises(RecoveryRefused, match="already_pending"):
        queue(db_session, recovery_rows, settings)
    artifact, sent = collect(spec)
    assert evaluate_recovery(spec, artifact)[0]
    assert sent == [
        ("POST", "/login"),
        ("GET", "/identity"),
        ("GET", "/record"),
        ("GET", "/identity"),
    ]


@pytest.mark.parametrize(
    "case",
    [
        "restored",
        "blocked",
        "changed",
        "wrong_identity",
        "cancelled",
        "untrusted",
        "tampered",
        "old_token",
        "changed_fence",
        "wrong_run",
    ],
)
def test_finalizer_requires_trusted_readback_and_preserves_original_audit(
    db_session, recovery_rows, settings, evidence_store, case
):
    r = recovery_rows
    scan, task, spec = queue(db_session, r, settings)
    lease = acquire_lease(db_session, scan_id=scan.id, holder="recovery-test", ttl_seconds=120)
    scan.egress_token_hash = "fresh-token-hash"
    task.state, task.lease_token = "running", lease.fencing_token
    original_evidence = record_json_evidence(
        db_session,
        settings=settings,
        store=evidence_store,
        scan=r.original,
        origin=EvidenceOrigin.SUPERVISOR,
        producer="original-test",
        payload={"original": "evidence"},
    )
    artifact, sent = collect(
        spec,
        status=403 if case == "blocked" else 200,
        restored=case != "changed",
        wrong_identity=case == "wrong_identity",
        cancel=case == "cancelled",
    )
    artifact["data"]["worker_claims_clean"] = True
    evidence = record_json_evidence(
        db_session,
        settings=settings,
        store=evidence_store,
        scan=scan,
        origin=EvidenceOrigin.UNTRUSTED_OBSERVATION
        if case == "untrusted"
        else EvidenceOrigin.SUPERVISOR,
        producer=RECOVERY_PRODUCER,
        producer_hash="reviewed-worker-hash",
        payload=artifact,
        task_id=task.id,
        run_id="new-run",
        role="A",
    )
    row = db_session.get(EvidenceRow, uuid.UUID(evidence.id))
    if case == "tampered":
        evidence_store.put(row.content_ref, b'{"clean":true}')
    if case == "old_token":
        scan.egress_token_hash = r.original.egress_token_hash
    if case == "changed_fence":
        r.cleanup.updated_at += timedelta(seconds=1)
    db_session.flush()
    kwargs = dict(
        lease=lease,
        run_id="wrong-run" if case == "wrong_run" else "new-run",
        evidence_id=row.id,
        store=evidence_store,
    )
    if case in {"old_token", "changed_fence"}:
        with pytest.raises(RecoveryRefused):
            finalize_recovery(db_session, scan, **kwargs)
        assert r.cleanup.state == "mutation_sent"
        return
    valid, _ = finalize_recovery(db_session, scan, **kwargs)
    db_session.commit()
    assert valid is (case == "restored")
    assert r.cleanup.state == ("clean" if valid else "mutation_sent")
    assert r.other.state == "cleanup_failed" and r.original.egress_token_hash == "old-revoked-hash"
    assert not any(path in {"/mutate", "/cleanup"} for _, path in sent)
    audit = db_session.scalar(
        select(AuditEventRow).where(AuditEventRow.action == "cleanup.recovery.verify")
    )
    assert audit.detail["original_state"] == "mutation_sent"
    assert audit.detail["original_evidence_refs"] == [str(original_evidence.id)]
    assert audit.detail["recovery_evidence_ref"] == str(row.id)


def test_operator_api_is_disabled_until_dedicated_runtime_and_never_accepts_clean_claim(
    authed_client, recovery_rows, db_session
):
    client = authed_client
    client.app.state.cleanup_recovery_runtime_enabled = False
    r = recovery_rows
    payload = {
        "cleanup_id": str(r.cleanup.id),
        "scope_version_id": str(r.fresh_scope.id),
        "assessment_configuration_id": str(r.configuration.id),
    }
    response = client.post("/api/cleanup-recoveries", json=payload)
    assert response.status_code == 503
    client.app.state.cleanup_recovery_runtime_enabled = True
    assert (
        client.post("/api/cleanup-recoveries", json={**payload, "clean": True}).status_code == 422
    )
    pending = client.get("/api/cleanup-recoveries/pending")
    assert pending.status_code == 200 and len(pending.json()) == 2
    response = client.post("/api/cleanup-recoveries", json=payload)
    assert response.status_code == 202, response.text
    recovery = response.json()
    assert recovery["status"] == "queued" and recovery["cleanup_id"] == str(r.cleanup.id)
    assert client.get("/api/cleanup-recoveries/" + recovery["id"]).status_code == 200
    db_session.refresh(r.cleanup)
    assert r.cleanup.state == "mutation_sent"


def test_coordinator_uses_only_recovery_worker_and_trusted_finalizer(
    db_session, recovery_rows, settings, monkeypatch, tmp_path
):
    from scopelens.execution import coordinator
    from scopelens.execution.supervisor import (
        ARTIFACT_MARKER,
        RESULT_MARKER,
        RecordingSupervisor,
        WorkerResult,
    )
    from scopelens.expansion.recovery import RecoverySpec
    from scopelens.persistence.models import FindingRow, ScanRow, ScoreSnapshotRow
    from scopelens.persistence.session import session_scope

    scan, task, _ = queue(db_session, recovery_rows, settings)
    db_session.commit()

    def forbidden(*args, **kwargs):
        pytest.fail("generic scan/report stage must not run during cleanup recovery")

    monkeypatch.setattr(coordinator, "_measure_tls_outside_transaction", forbidden)
    monkeypatch.setattr(coordinator, "_analyse", forbidden)
    monkeypatch.setattr("scopelens.orchestration.graph.run_graph", forbidden)

    class Supervisor(RecordingSupervisor):
        def run(self, spec, *, run_id):
            self.specs.append(spec)
            self.run_ids.append(run_id)
            assert spec.command == ["python", "-m", "scopelens.expansion.recovery_worker"]
            assert spec.environment["SCOPELENS_SCANNER_TOOLS_ENABLED"] == "false"
            assert spec.environment["SCOPELENS_EGRESS_TOKEN"] != "old-revoked-token"
            recovery = RecoverySpec.model_validate_json(
                spec.environment["SCOPELENS_RECOVERY_INPUT"]
            )
            artifact, requests = collect(recovery)
            with session_scope(settings) as session:
                for method, path in requests:
                    session.add(
                        AuditEventRow(
                            actor="broker",
                            action="broker.admit",
                            subject_type="scan",
                            subject_id=str(scan.id),
                            outcome="allowed",
                            detail={"method": method, "path": path},
                        )
                    )
            return WorkerResult(
                run_id=run_id,
                exit_code=0,
                stdout=ARTIFACT_MARKER
                + json.dumps(artifact)
                + "\n"
                + RESULT_MARKER
                + json.dumps({"ok": True, "body_bytes": 0}),
                stderr="",
                duration_seconds=0.1,
            )

    supervisor = Supervisor()
    enabled = settings.model_copy(
        update={
            "browser_enabled": True,
            "scanner_tools_enabled": True,
            "adaptive_enabled": True,
            "evidence_store_path": tmp_path / "coordinator-evidence",
        }
    )
    result = coordinator.coordinate(
        enabled,
        scan_id=scan.id,
        task_id=task.id,
        attempt_id=task.attempt_id,
        supervisor=supervisor,
        run_id="fresh-recovery-run",
    )
    assert result.scan_status.value == "completed", result
    assert result.requests_admitted == 4 and len(supervisor.specs) == 1
    db_session.expire_all()
    assert db_session.get(CleanupRow, recovery_rows.cleanup.id).state == "clean"
    assert db_session.get(CleanupRow, recovery_rows.other.id).state == "cleanup_failed"
    saved = db_session.get(ScanRow, scan.id)
    assert saved.assessment_plan["cleanup_recovery_result"]["verified"]
    assert not db_session.scalar(select(FindingRow).where(FindingRow.scan_id == scan.id))
    assert not db_session.scalar(
        select(ScoreSnapshotRow).where(ScoreSnapshotRow.scan_id == scan.id)
    )


def test_live_gate_injects_only_distinct_synthetic_intents_and_denies_old_token(
    db_session, recovery_rows, settings
):
    from scripts.verify_cleanup_recovery_lab import configuration, inject_pending_intents

    from scopelens.persistence.models import ScanRow, TaskRow

    r = recovery_rows
    scope = {"id": str(r.old_scope.id), "origin": scope_row_to_domain(r.old_scope).origin}
    config = configuration(scope, "synthetic-credential-ref", "unique-test-nonce", original=True)
    source_id, fences = inject_pending_intents(
        settings,
        scope,
        {"id": str(uuid.uuid4()), "content_hash": digest(config), "configuration": config},
    )
    db_session.expire_all()
    source = db_session.get(ScanRow, uuid.UUID(source_id))
    assert source.status == "cancelled" and source.assessment_plan["synthetic_recovery_gate"]
    assert source.cancel_epoch > source.egress_token_epoch
    assert not db_session.scalar(select(TaskRow).where(TaskRow.scan_id == source.id))
    assert not db_session.scalar(
        select(OutboxEventRow).where(OutboxEventRow.payload["scan_id"].astext == source_id)
    )
    assert len(fences) == 2 and len(set(fences)) == 2
    for ident in fences:
        row = db_session.get(CleanupRow, uuid.UUID(ident))
        assert row.state == "pending" and row.resource_id.startswith(
            "synthetic-recovery-unique-test-nonce-"
        )
    event = db_session.scalar(
        select(AuditEventRow).where(AuditEventRow.action == "lab.recovery.intent.inject")
    )
    assert event.detail["synthetic"] and event.detail["mutation_sent"] is False
    assert db_session.get(CleanupRow, r.cleanup.id).state == "mutation_sent"
