"""PostgreSQL restoration history and control RPCs for sequential shared resources."""

import copy
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from tests.integration.test_cleanup_recovery import recovery_rows  # noqa: F401 - pytest fixture
from tests.integration.test_cleanup_revocation import configuration, scan_with_capability
from tests.integration.test_expansion_api import scope

from scopelens.api.deps import settings_dependency
from scopelens.expansion.cleanup_history import cleanup_states_for_scan
from scopelens.internal_app import create_policy_app
from scopelens.persistence.models import AuditEventRow, CleanupRow, ScanRow
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


def http_recipe(recipe):
    result = copy.deepcopy(recipe)
    result["family"] = "workflow_authorization"
    result["owner_identity"] = result.pop("viewer_identity")
    result["forbidden_after"] = {"pointer": "/content", "value": "changed"}
    result.pop("mutation_field")
    result.pop("viewer_url")
    return result


@pytest.fixture
def history_setup(authed_client, settings, request):
    primary = scope(
        authed_client,
        allowed_check_profile="staging-stateful-v1",
        allowed_methods=["GET", "HEAD", "POST"],
    )
    payload = configuration(primary)
    first = payload["browser_workflows"][0]
    second = {**copy.deepcopy(first), "id": "workflow-next"}
    kind = getattr(request, "param", "mixed")
    if kind == "browser":
        payload["browser_workflows"] = [first, second]
    elif kind == "http":
        payload["browser_workflows"] = []
        payload["workflows"] = [http_recipe(first), http_recipe(second)]
    else:
        payload["browser_workflows"] = [first]
        payload["workflows"] = [http_recipe(second)]
    response = authed_client.post("/api/assessments/configurations", json=payload)
    assert response.status_code == 201, response.text
    config = response.json()
    scan_id, token, capability = scan_with_capability(authed_client, primary, config["id"])
    app = create_policy_app()
    app.dependency_overrides[settings_dependency] = lambda: settings
    with TestClient(app) as policy:

        def rpc(recipe_id, operation, **fields):
            response = policy.post(
                "/internal/broker/assessment",
                json={
                    "egress_token": token,
                    "capability": capability,
                    "recipe_id": recipe_id,
                    "resource_id": first["resource_id"],
                    "operation": operation,
                    **fields,
                },
            )
            assert response.status_code == 200, response.text
            return response.json()

        yield SimpleNamespace(
            scan_id=scan_id,
            settings=settings,
            primary=primary,
            config=config,
            first=first["id"],
            second=second["id"],
            resource_id=first["resource_id"],
            rpc=rpc,
        )


def history(fixture):
    with session_scope(fixture.settings) as session:
        return cleanup_states_for_scan(session, session.get(ScanRow, fixture.scan_id))


def restore(fixture, recipe_id):
    assert fixture.rpc(recipe_id, "cleanup_claim") == {"allowed": True, "state": "pending"}
    assert fixture.rpc(recipe_id, "cleanup_mark", state="mutation_sent") == {
        "allowed": True,
        "state": "mutation_sent",
    }
    assert fixture.rpc(recipe_id, "cleanup_mark", state="clean") == {
        "allowed": True,
        "state": "clean",
    }


@pytest.mark.parametrize("history_setup", ["browser", "http", "mixed"], indirect=True)
def test_sequential_recipes_retain_both_clean_states_after_resource_row_reassignment(history_setup):
    fixture = history_setup
    restore(fixture, fixture.first)
    assert history(fixture) == {fixture.first: "clean"}
    assert fixture.rpc(fixture.second, "cleanup_claim") == {"allowed": True, "state": "pending"}
    assert history(fixture) == {fixture.first: "clean", fixture.second: "pending"}
    assert fixture.rpc(fixture.second, "cleanup_mark", state="clean")["allowed"]
    assert history(fixture) == {fixture.first: "clean", fixture.second: "clean"}
    with session_scope(fixture.settings) as session:
        rows = list(
            session.scalars(select(CleanupRow).where(CleanupRow.scan_id == fixture.scan_id))
        )
        assert len(rows) == 1
        assert rows[0].recipe_id == fixture.second and rows[0].state == "clean"
        events = list(
            session.scalars(
                select(AuditEventRow)
                .where(
                    AuditEventRow.subject_id == str(fixture.scan_id),
                    AuditEventRow.action == "workflow.cleanup_transition",
                )
                .order_by(AuditEventRow.seq)
            )
        )
        assert [event.outcome for event in events] == [
            "pending",
            "mutation_sent",
            "clean",
            "pending",
            "clean",
        ]
        assert all(event.actor == "assessment-control" for event in events)
        assert all(
            event.detail["configuration_hash"] == fixture.config["content_hash"]
            and event.detail["scope_version_id"] == fixture.primary["id"]
            for event in events
        )


@pytest.mark.parametrize("state", ["pending", "mutation_sent", "cleanup_failed"])
def test_unresolved_recipe_still_fences_other_recipe_on_shared_resource(history_setup, state):
    fixture = history_setup
    assert fixture.rpc(fixture.first, "cleanup_claim")["allowed"]
    if state != "pending":
        assert fixture.rpc(fixture.first, "cleanup_mark", state=state)["allowed"]
    assert fixture.rpc(fixture.second, "cleanup_claim") == {
        "allowed": False,
        "reason": "unresolved_cleanup",
    }
    assert not fixture.rpc(fixture.second, "cleanup_mark", state="clean")["allowed"]
    assert history(fixture) == {fixture.first: state}


def test_reclaim_same_recipe_supersedes_its_prior_clean_without_losing_other_history(history_setup):
    fixture = history_setup
    restore(fixture, fixture.first)
    restore(fixture, fixture.second)
    assert history(fixture) == {fixture.first: "clean", fixture.second: "clean"}
    assert fixture.rpc(fixture.first, "cleanup_claim")["allowed"]
    assert history(fixture) == {fixture.first: "pending", fixture.second: "clean"}
    assert fixture.rpc(fixture.first, "cleanup_mark", state="cleanup_failed")["allowed"]
    assert history(fixture) == {fixture.first: "cleanup_failed", fixture.second: "clean"}
    assert fixture.rpc(fixture.second, "cleanup_claim")["reason"] == "unresolved_cleanup"


def test_verified_recovery_row_supersedes_earlier_pending_history(
    db_session, request, settings, evidence_store
):
    from tests.integration.test_cleanup_recovery import collect, queue

    from scopelens.domain.evidence import EvidenceOrigin
    from scopelens.evidence.intake import record_json_evidence
    from scopelens.execution.leases import acquire_lease
    from scopelens.expansion.recovery import RECOVERY_PRODUCER, digest, finalize_recovery

    rows = request.getfixturevalue("recovery_rows")
    rows.cleanup.state = "pending"
    frozen = rows.original.assessment_plan
    configuration_hash = digest(frozen["expansion_config"])
    rows.original.assessment_plan = {**frozen, "configuration_hash": configuration_hash}
    pending = AuditEventRow(
        actor="assessment-control",
        action="workflow.cleanup_transition",
        subject_type="scan",
        subject_id=str(rows.original.id),
        outcome="pending",
        detail={
            "scope_version_id": str(rows.original.scope_version_id),
            "configuration_hash": configuration_hash,
            "recipe_id": rows.cleanup.recipe_id,
            "resource_id": rows.cleanup.resource_id,
        },
    )
    db_session.add(pending)
    db_session.flush()
    assert cleanup_states_for_scan(db_session, rows.original) == {rows.cleanup.recipe_id: "pending"}
    scan, task, spec = queue(db_session, rows, settings)
    lease = acquire_lease(db_session, scan_id=scan.id, holder="history-recovery", ttl_seconds=120)
    scan.egress_token_hash = "fresh-token-hash"
    task.state, task.lease_token = "running", lease.fencing_token
    artifact, requests = collect(spec)
    evidence = record_json_evidence(
        db_session,
        settings=settings,
        store=evidence_store,
        scan=scan,
        origin=EvidenceOrigin.SUPERVISOR,
        producer=RECOVERY_PRODUCER,
        producer_hash="reviewed-worker-hash",
        payload=artifact,
        task_id=task.id,
        run_id="history-recovery-run",
        role="A",
    )
    verified, _ = finalize_recovery(
        db_session,
        scan,
        lease=lease,
        run_id="history-recovery-run",
        evidence_id=uuid.UUID(evidence.id),
        store=evidence_store,
    )
    db_session.commit()
    assert verified and rows.cleanup.state == "clean"
    assert rows.cleanup.updated_at >= pending.occurred_at and pending.outcome == "pending"
    assert cleanup_states_for_scan(db_session, rows.original) == {rows.cleanup.recipe_id: "clean"}
    assert rows.original.cancel_epoch > rows.original.egress_token_epoch
    assert not any(path in {"/mutate", "/cleanup"} for _, path in requests)


@pytest.mark.parametrize(
    "mismatch",
    [
        "scope",
        "configuration_hash",
        "actor",
        "subject",
        "action",
        "resource",
        "recipe",
        "missing_recipe_resource",
        "unknown_recipe_without_resource",
    ],
)
def test_unbound_or_untrusted_clean_event_cannot_clear_pending_recipe(history_setup, mismatch):
    fixture = history_setup
    assert fixture.rpc(fixture.first, "cleanup_claim")["allowed"]
    detail = {
        "scope_version_id": fixture.primary["id"],
        "configuration_hash": fixture.config["content_hash"],
        "recipe_id": fixture.first,
        "resource_id": fixture.resource_id,
    }
    fields = {
        "actor": "assessment-control",
        "action": "workflow.cleanup_transition",
        "subject_type": "scan",
        "subject_id": str(fixture.scan_id),
        "outcome": "clean",
        "detail": detail,
    }
    if mismatch == "scope":
        detail["scope_version_id"] = str(uuid.uuid4())
    elif mismatch == "configuration_hash":
        detail["configuration_hash"] = "different-frozen-configuration"
    elif mismatch == "actor":
        fields["actor"] = "worker"
    elif mismatch == "subject":
        fields["subject_id"] = str(uuid.uuid4())
    elif mismatch == "action":
        fields["action"] = "worker.cleanup_claim"
    elif mismatch == "resource":
        detail["resource_id"] = "different-resource"
    elif mismatch == "recipe":
        detail["recipe_id"] = "unconfigured-recipe"
    elif mismatch == "missing_recipe_resource":
        detail.pop("recipe_id")
        detail.pop("resource_id")
    elif mismatch == "unknown_recipe_without_resource":
        detail["recipe_id"] = "unconfigured-recipe"
        detail.pop("resource_id")
    with session_scope(fixture.settings) as session:
        session.add(AuditEventRow(**fields))
    assert history(fixture) == {fixture.first: "pending"}
    assert fixture.rpc(fixture.second, "cleanup_claim")["reason"] == "unresolved_cleanup"
