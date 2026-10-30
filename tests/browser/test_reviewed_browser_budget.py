"""Reviewed captures have bounded task accounting independent of exploration."""

from dataclasses import asdict

import pytest
from tests.integration import test_probe_page_budget
from tests.integration.test_broker import PUBLIC_V4, request_for, resolver_for

from scopelens.broker.policy import BrokerRequest, authorize
from scopelens.broker.probe_tasks import conditional_reference
from scopelens.browser.policy import BrowserAction, BrowserCommand, command
from scopelens.domain.enums import ProfileName
from scopelens.execution.budget import read_usage
from scopelens.persistence.models import BrowserSessionRow
from scopelens.persistence.repositories import scope_row_to_domain

pytestmark = pytest.mark.db
approved_scan = test_probe_page_budget.prepared


@pytest.fixture
def captures(db_session, settings, approved_scan):
    _scope, token, scan = approved_scan
    entries = [{"kind": "xss", "path": f"/app/xss{i}", "parameter": "q"} for i in range(8)]
    scan.assessment_plan = {"conditional_probes": entries}
    db_session.commit()
    settings = settings.model_copy(
        update={"browser_max_actions": 2, "browser_max_active_actions": 500}
    )

    def run(operation, **fields):
        # model_copy keeps this accounting regression executable on the old schema too.
        reference = fields.pop("probe_task", None)
        request = BrowserCommand(
            egress_token=token, owner="reviewed-owner-long", operation=operation, **fields
        ).model_copy(update={"probe_task": reference})
        decision = command(db_session, settings, request)
        db_session.commit()
        return decision

    assert run("open")["allowed"]
    return run, settings, approved_scan, entries


def action(scope, entry=None):
    return BrowserAction(
        kind="navigate",
        url=scope_row_to_domain(scope).origin + (entry["path"] + "?q=marker" if entry else "/app"),
    )


def explore(captures):
    run, _, (scope, _, _), _ = captures
    for sequence in (1, 2):
        assert run("admit", sequence=sequence, action=action(scope))["allowed"]
        assert run("complete", sequence=sequence)["allowed"]
    assert run("admit", sequence=3, action=action(scope))["reason"] == "action_budget"


def test_42_reviewed_captures_after_exploration_cap_use_shared_request_budget(captures, db_session):
    run, settings, prepared, entries = captures
    scope, token, scan = prepared
    assert settings.browser_max_active_actions == 500
    explore(captures)
    for index in range(42):
        entry = entries[index // 6]
        reference = conditional_reference(entry)
        sequence = index + 3
        assert run("admit", sequence=sequence, action=action(scope, entry), probe_task=reference)[
            "allowed"
        ]
        request = BrokerRequest(
            **{
                **asdict(request_for(scope, token, path=entry["path"] + "?q=marker")),
                "probe_task": reference,
            },
        )
        assert authorize(
            db_session, settings=settings, request=request, resolver=resolver_for(PUBLIC_V4)
        ).allowed
        db_session.commit()
        assert run("complete", sequence=sequence)["allowed"]
    assert run("admit", sequence=45, action=action(scope))["reason"] == "action_budget"
    db_session.refresh(scan)
    assert sum(scan.assessment_plan["reviewed_browser_actions"].values()) == 42
    assert read_usage(scan)[1].requests == 42  # HTTP is charged once, not twice.
    assert len(scan.assessment_plan["page_request_keys"]) == 0


def test_reviewed_actions_do_not_spend_exploration_allowance(captures):
    run, _, (scope, _, _), entries = captures
    reference = conditional_reference(entries[0])
    for sequence in range(1, 4):
        assert run(
            "admit", sequence=sequence, action=action(scope, entries[0]), probe_task=reference
        )["allowed"]
        assert run("complete", sequence=sequence)["allowed"]
    for sequence in (4, 5):
        assert run("admit", sequence=sequence, action=action(scope))["allowed"]
        assert run("complete", sequence=sequence)["allowed"]
    assert run("admit", sequence=6, action=action(scope))["reason"] == "action_budget"


@pytest.mark.parametrize("case", ["missing", "unknown", "wrong_path", "sql", "click"])
def test_annotation_cannot_bypass_exploration_without_browser_authority(captures, db_session, case):
    run, _, (scope, _, scan), entries = captures
    explore(captures)
    target = action(scope, entries[0])
    reference = conditional_reference(entries[0])
    if case == "missing":
        reference = None
    elif case == "unknown":
        reference = "input:unknown"
    elif case == "wrong_path":
        target = action(scope, entries[1])
    elif case == "sql":
        sql = {**entries[0], "kind": "sql"}
        scan.assessment_plan = {"conditional_probes": [sql]}
        db_session.commit()
        reference = conditional_reference(sql)
    else:
        target = target.model_copy(
            update={"kind": "click", "label": "Show", "state_hash": "a" * 64}
        )
    assert (
        run("admit", sequence=3, action=target, probe_task=reference)["reason"] == "action_budget"
    )
    db_session.refresh(scan)
    assert "reviewed_browser_actions" not in scan.assessment_plan


def test_existing_registry_task_cap_is_enforced(captures):
    run, _, (scope, _, _), entries = captures
    reference = conditional_reference(entries[0])
    for sequence in range(1, 9):  # SL-C03-XSS-01 already permits at most eight requests.
        assert run(
            "admit", sequence=sequence, action=action(scope, entries[0]), probe_task=reference
        )["allowed"]
        assert run("complete", sequence=sequence)["allowed"]
    assert (
        run("admit", sequence=9, action=action(scope, entries[0]), probe_task=reference)["reason"]
        == "reviewed_browser_task_budget"
    )


def test_active_action_ceiling_is_per_scan_and_survives_successor(captures, db_session):
    run, settings, (scope, _, scan), entries = captures
    settings.browser_max_active_actions = 3
    for sequence in range(1, 4):
        assert run(
            "admit",
            sequence=sequence,
            action=action(scope, entries[sequence]),
            probe_task=conditional_reference(entries[sequence]),
        )["allowed"]
        assert run("complete", sequence=sequence, result="failed")["allowed"]
    row = db_session.get(BrowserSessionRow, scan.id)
    # A trusted successor resets context-local ordering and action history, not scan usage.
    row.sequence, row.actions = 0, []
    db_session.commit()
    assert (
        run(
            "admit",
            sequence=1,
            action=action(scope, entries[0]),
            probe_task=conditional_reference(entries[0]),
        )["reason"]
        == "active_action_budget"
    )


def test_active_order_and_inflight_checks_remain(captures):
    run, _, (scope, _, _), entries = captures
    fields = {"action": action(scope, entries[0]), "probe_task": conditional_reference(entries[0])}
    assert run("admit", sequence=2, **fields)["reason"] == "action_order_or_inflight"
    assert run("admit", sequence=1, **fields)["allowed"]
    assert run("admit", sequence=2, **fields)["reason"] == "action_order_or_inflight"
    assert run("complete", sequence=1)["allowed"]
    assert run("admit", sequence=2, **fields)["allowed"]


def test_exhausted_http_task_budget_also_blocks_browser_capture(captures, db_session):
    run, _, (scope, _, scan), entries = captures
    reference = conditional_reference(entries[0])
    scan.assessment_plan = {**scan.assessment_plan, "reviewed_probe_requests": {reference: 8}}
    db_session.commit()
    assert (
        run("admit", sequence=1, action=action(scope, entries[0]), probe_task=reference)["reason"]
        == "reviewed_browser_task_budget"
    )


def test_shared_request_exhaustion_blocks_active_admission(captures, db_session):
    run, settings, (scope, _, scan), entries = captures
    scan.budget_reserved = {"requests": settings.budgets.max_total_requests}
    db_session.commit()
    assert (
        run(
            "admit",
            sequence=1,
            action=action(scope, entries[0]),
            probe_task=conditional_reference(entries[0]),
        )["reason"]
        == "request_budget"
    )


@pytest.mark.parametrize("approved_scan", [ProfileName.EXTERNAL_ACTIVE_V2], indirect=True)
@pytest.mark.parametrize("claim", ["valid", "missing", "wrong_plan", "blocked", "template"])
def test_expanded_capture_requires_admitted_claim_and_bound_template(captures, db_session, claim):
    from tests.unit.test_reviewed_probe_authority import expanded_scan

    from scopelens.broker.probe_tasks import input_reference
    from scopelens.domain.assessment import stable_id

    run, _, (scope, _, scan), _ = captures
    explore(captures)
    frozen = expanded_scan().assessment_plan
    frozen["request_catalogue"]["templates"][0]["origin"] = scope_row_to_domain(scope).origin
    frozen["input_assessment_plan"]["scope_version"] = str(scan.scope_version_id)
    frozen["input_assessment_plan"]["tasks"][0]["control_id"] = "SL-C03-XSS-01"
    if claim == "missing":
        frozen["assessment_execution_claims"] = {}
    elif claim == "wrong_plan":
        frozen["assessment_execution_claims"]["task:task"]["plan_id"] = "other"
    elif claim == "blocked":
        frozen["input_assessment_plan"]["tasks"][0]["state"] = "blocked"
    elif claim == "template":
        frozen["request_catalogue"]["templates"][0]["authority"] = "resource_only"
    frozen["input_assessment_plan"]["catalogue_hash"] = stable_id(frozen["request_catalogue"])
    scan.assessment_plan = {**scan.assessment_plan, **frozen}
    db_session.commit()
    target = BrowserAction(
        kind="navigate", url=scope_row_to_domain(scope).origin + "/app/search?q=marker&fixed=stable"
    )
    decision = run("admit", sequence=3, action=target, probe_task=input_reference("task"))
    assert decision["allowed"] is (claim == "valid")
    assert decision["reviewed_probe"] is (claim == "valid")
    if claim != "valid":
        assert decision["reason"] == "action_budget"


@pytest.mark.parametrize("approved_scan", [ProfileName.EXTERNAL_ACTIVE_V2], indirect=True)
def test_42_expanded_admissions_use_validated_claims_and_existing_task_caps(captures, db_session):
    from copy import deepcopy

    from tests.unit.test_reviewed_probe_authority import expanded_scan

    from scopelens.broker.probe_tasks import input_reference
    from scopelens.domain.assessment import stable_id
    from scopelens.domain.registry import load_registry

    run, settings, (scope, _, scan), _ = captures
    explore(captures)
    frozen = expanded_scan().assessment_plan
    template = frozen["request_catalogue"]["templates"][0]
    task = frozen["input_assessment_plan"]["tasks"][0]
    templates, tasks = [], []
    for index in range(14):
        templates.append(
            {
                **deepcopy(template),
                "id": f"template-{index}",
                "origin": scope_row_to_domain(scope).origin,
                "path": f"/app/search{index}",
                "route_template": f"/app/search{index}",
            }
        )
        tasks.append(
            {
                **deepcopy(task),
                "id": f"task-{index}",
                "template_id": f"template-{index}",
                "control_id": "SL-C03-HTML-01",
            }
        )
    frozen["request_catalogue"]["templates"] = templates
    frozen["input_assessment_plan"].update(
        tasks=tasks,
        denominator=len(tasks),
        scope_version=str(scan.scope_version_id),
        catalogue_hash=stable_id(frozen["request_catalogue"]),
    )
    frozen["assessment_execution_claims"] = {
        "task:" + task["id"]: {
            "state": "admitted",
            "plan_id": frozen["input_assessment_plan"]["id"],
        }
        for task in tasks
    }
    scan.assessment_plan = {**scan.assessment_plan, **frozen}
    db_session.commit()
    for index in range(42):
        reference = input_reference(tasks[index // 3]["id"])
        sequence = index + 3
        target = BrowserAction(
            kind="navigate",
            url=scope_row_to_domain(scope).origin
            + f"/app/search{index // 3}?q=marker&fixed=stable",
        )
        verdict = run("admit", sequence=sequence, action=target, probe_task=reference)
        assert verdict["allowed"] and verdict["reviewed_probe"] is True
        assert run("complete", sequence=sequence)["allowed"]
    db_session.refresh(scan)
    counts = scan.assessment_plan["reviewed_browser_actions"]
    cap = (
        load_registry(settings.checks_registry_dir)
        .get("SL-C03-HTML-01")
        .allowed_action.max_requests
    )
    assert sum(counts.values()) == 42
    assert all(count <= cap for count in counts.values())
    assert run("admit", sequence=45, action=action(scope))["reason"] == "action_budget"


@pytest.mark.parametrize("case", ["revocation", "excluded_path"])
def test_active_capture_cannot_widen_scope_or_survive_revocation(captures, db_session, case):
    run, _, (scope, _, scan), entries = captures
    entry = entries[0]
    if case == "revocation":
        scan.cancel_epoch += 1
    else:
        entry = {**entry, "path": "/app/admin"}
        scan.assessment_plan = {"conditional_probes": [entry]}
    db_session.commit()
    assert not run(
        "admit", sequence=1, action=action(scope, entry), probe_task=conditional_reference(entry)
    )["allowed"]
    db_session.refresh(scan)
    assert "reviewed_browser_actions" not in scan.assessment_plan


def test_invalid_annotation_admitted_as_exploration_spends_exploration_cap(captures, db_session):
    run, _, (scope, _, scan), _ = captures
    assert run("admit", sequence=1, action=action(scope), probe_task="input:unknown")["allowed"]
    assert run("complete", sequence=1)["allowed"]
    row = db_session.get(BrowserSessionRow, scan.id)
    assert "probe_task" not in row.actions[0]
    assert run("admit", sequence=2, action=action(scope))["allowed"]
    assert run("complete", sequence=2)["allowed"]
    assert run("admit", sequence=3, action=action(scope))["reason"] == "action_budget"


@pytest.mark.parametrize("limit", [0, -1])
def test_active_browser_ceiling_must_be_positive(settings, limit):
    from pydantic import ValidationError

    from scopelens.config import Settings

    with pytest.raises(ValidationError):
        Settings(**{**settings.model_dump(), "browser_max_active_actions": limit})


@pytest.mark.parametrize("approved_scan", [ProfileName.EXTERNAL_ACTIVE_V2], indirect=True)
@pytest.mark.parametrize("grant", ["scan", "resource_only", "expired", "missing"])
def test_reviewed_related_capture_requires_existing_approved_scan_scope(
    captures, db_session, grant
):
    from datetime import UTC, datetime, timedelta

    from tests.unit.test_reviewed_probe_authority import expanded_scan

    from scopelens.broker.probe_tasks import input_reference
    from scopelens.domain.assessment import stable_id
    from scopelens.domain.scope import ProductionScopeCreate
    from scopelens.persistence.repositories import create_scope_version

    run, _, (_scope, _, scan), _ = captures
    related = create_scope_version(
        db_session,
        operator_id=scan.operator_id,
        payload=ProductionScopeCreate(
            host="related.example.com",
            allowed_path_prefixes=["/app"],
            allowed_check_profile=ProfileName.EXTERNAL_ACTIVE_V2,
            authorization_expires_at=datetime.now(UTC)
            + timedelta(days=-1 if grant == "expired" else 1),
        ),
        scheme="https",
        host="related.example.com",
        port=443,
        lab_binding=None,
    )
    origin = scope_row_to_domain(related).origin
    frozen = expanded_scan(authority="scan", origin=origin).assessment_plan
    frozen["input_assessment_plan"]["scope_version"] = str(scan.scope_version_id)
    frozen["input_assessment_plan"]["tasks"][0]["control_id"] = "SL-C03-XSS-01"
    frozen["input_assessment_plan"]["catalogue_hash"] = stable_id(frozen["request_catalogue"])
    frozen["expansion_config"] = {
        "related_origins": []
        if grant == "missing"
        else [
            {
                "scope_version_id": str(related.id),
                "origin": origin,
                "purpose": "resource_only" if grant == "resource_only" else "scan",
            }
        ]
    }
    scan.assessment_plan = {**scan.assessment_plan, **frozen}
    db_session.commit()
    decision = run(
        "admit",
        sequence=1,
        action=BrowserAction(kind="navigate", url=origin + "/app/search?q=marker&fixed=stable"),
        probe_task=input_reference("task"),
    )
    assert decision["allowed"] is (grant == "scan")
    db_session.refresh(scan)
    assert ("reviewed_browser_actions" in scan.assessment_plan) is (grant == "scan")


@pytest.mark.parametrize("reference", ["", "x" * 129])
def test_browser_command_rejects_invalid_reference_length(reference):
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        BrowserCommand(
            egress_token="token",
            owner="reviewed-owner-long",
            operation="admit",
            probe_task=reference,
        )
