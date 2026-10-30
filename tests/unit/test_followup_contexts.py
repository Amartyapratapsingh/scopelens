"""Read-only follow-ups use frozen contexts without replaying login or mutation."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr
from tests.test_identity_expansion import lab, matrix, profiles
from tests.unit.test_expansion_adaptive import prepared

from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.execution.supervisor import SupervisorError
from scopelens.orchestration.access_worker import collect_access_followup
from scopelens.orchestration.expansion import hypotheses_from, verify_followup
from scopelens.orchestration.followup_contexts import access_configuration, reflection_payload


def reflection():
    scope_id = uuid4()
    cat, plan, artifact = prepared("https://app.test")
    task = plan.tasks[0].model_copy(update={"control_id": "SL-C03-HTML-01"})
    plan = plan.model_copy(update={"tasks": (task,), "scope_version": str(scope_id)})
    artifact["data"].update(task_id=task.id, kind="html")
    candidate = hypotheses_from([artifact], cat, plan, browser_available=True)[0]
    saved = {
        "request_catalogue": cat.model_dump(mode="json"),
        "input_assessment_plan": plan.model_dump(mode="json"),
    }
    return saved, candidate, SimpleNamespace(id=scope_id, origin=cat.origin)


def test_reflection_is_ready_only_with_owned_browser_context_and_projects_one_task():
    saved, hypothesis, target = reflection()
    assert hypothesis.state == "ready"
    payload = json.loads(
        reflection_payload(saved, hypothesis.model_dump(), scan_id=uuid4(), scope=target)
    )
    assert len(payload["plan"]["tasks"]) == 1
    config = payload["configuration"]
    assert config["identities"] == [] and config["browser_workflows"] == []
    assert config["callback_recipes"] == [] and config["session_policies"] == []


@pytest.mark.parametrize("fault", ["plan", "scope", "method", "role", "secret", "control"])
def test_changed_reflection_binding_cannot_launch(fault):
    saved, hypothesis, target = reflection()
    if fault == "plan":
        saved["input_assessment_plan"]["id"] = "other"
    elif fault == "scope":
        target.id = uuid4()
    elif fault == "control":
        saved["input_assessment_plan"]["tasks"][0]["control_id"] = "SL-C03-SQL-01"
    else:
        template = saved["request_catalogue"]["templates"][0]
        if fault == "method":
            template["method"] = "POST"
        elif fault == "role":
            template["role_id"] = "a"
        else:
            template["inputs"][0]["secret_ref"] = "private-ref"
    with pytest.raises((SupervisorError, ValueError)):
        reflection_payload(saved, hypothesis.model_dump(), scan_id=uuid4(), scope=target)


@pytest.mark.parametrize("vulnerable", [False, True])
def test_access_followup_reuses_supplied_sessions_and_recomputes_proof(vulnerable):
    with lab(vulnerable=vulnerable) as origin:
        credentials = {}
        for name in ("a", "b"):
            with httpx.Client(trust_env=False) as client:
                client.post(
                    origin + "/login", json={"username": name, "password": "synthetic-password"}
                ).raise_for_status()
                credentials[name] = "sid=" + client.cookies["sid"]
        identities = tuple(
            p.model_copy(update={"login": None, "supplied_headers": {"Cookie": p.id}})
            for p in profiles(origin)
        )
        config = AssessmentConfiguration(
            scope_version_id=uuid4(), identities=identities, permission_matrix=matrix(origin)
        )
        cat, plan, _ = prepared(origin)
        lead = {
            "kind": "identity_response",
            "data": {"proof_type": "access", "proof_id": "rule-a", "status": 200},
        }
        hypothesis = hypotheses_from(
            [lead], cat, plan, configuration=config.model_dump(mode="json"), access_available=True
        )[0]
        assert hypothesis.state == "ready" and hypothesis.max_requests == 12
        artifacts = []
        control = SimpleNamespace(secret=lambda ref: SecretStr(credentials[ref]))
        count = collect_access_followup(
            config.model_dump(mode="json"),
            "rule-a",
            control,
            lambda _: httpx.Client(timeout=2, trust_env=False),
            lambda kind, data: artifacts.append({"kind": kind, "data": data}),
            cancelled=lambda: False,
        )
        assert count <= 12
        result = verify_followup(
            hypothesis, artifacts, configuration=config.model_dump(mode="json")
        )
        assert result["state"] == ("corroborated" if vulnerable else "contradicted")
        assert all(a.get("data", {}).get("method", "GET") in {"GET", "HEAD"} for a in artifacts)
        assert not any(value in json.dumps(artifacts) for value in credentials.values())


@pytest.mark.parametrize("fault", ["login", "expired", "write_probe", "no_supplied"])
def test_access_prerequisites_fail_closed(fault):
    identities = list(profiles("https://app.test"))
    identities = [
        p.model_copy(update={"login": None, "supplied_headers": {"Cookie": p.id}})
        for p in identities
    ]
    profile = identities[0]
    if fault == "login":
        profile = profiles("https://app.test")[0]
    elif fault == "expired":
        profile = profile.model_copy(
            update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
        )
    elif fault == "write_probe":
        profile = profile.model_copy(
            update={
                "probe": profile.probe.model_copy(
                    update={"request": profile.probe.request.model_copy(update={"method": "POST"})}
                )
            }
        )
    else:
        profile = profile.model_copy(update={"supplied_headers": {}})
    config = AssessmentConfiguration(
        scope_version_id=uuid4(),
        identities=(profile, identities[1]),
        permission_matrix=matrix("https://app.test"),
    )
    assert access_configuration(config.model_dump(mode="json"), "rule-a") is None


def test_reflection_verification_rejects_wrong_browser_family_and_input():
    saved, hypothesis, _ = reflection()
    task = saved["input_assessment_plan"]["tasks"][0]
    capture = {
        "kind": "expanded_active_probe",
        "data": {
            "task_id": task["id"],
            "template_id": task["template_id"],
            "plan_id": hypothesis.plan_id,
            "control_id": hypothesis.control,
            "kind": "xss",
            "reviewed": True,
            "input_key": task["input_key"],
            "captures": [],
        },
    }
    assert (
        verify_followup(hypothesis, [capture], frozen_plan=saved["input_assessment_plan"])["state"]
        == "inconclusive"
    )
    capture["data"].update(kind="html", input_key="other")
    assert (
        verify_followup(hypothesis, [capture], frozen_plan=saved["input_assessment_plan"])["state"]
        == "inconclusive"
    )


def test_callback_followup_reads_stored_receipts_without_target_replay(monkeypatch):
    from contextlib import contextmanager
    from unittest.mock import Mock

    from scopelens.domain.enums import ControlOutcome
    from scopelens.orchestration.followup_contexts import verify_callback_followup

    # This is an offline supervisor contract test, not deployed callback acceptance.
    config = AssessmentConfiguration(scope_version_id=uuid4(), callback_recipes=())
    task = SimpleNamespace(
        recipe_id="callback", recipe=SimpleNamespace(target_url="https://app.test/callback")
    )
    row = SimpleNamespace(
        cancel_requested_at=None,
        cancel_epoch=0,
        egress_token_epoch=0,
        operator_id=uuid4(),
        assessment_plan={"expansion_config": config.model_dump(mode="json")},
    )
    runtime = Mock()
    runtime.stored_dispatch_evidence.return_value = [
        SimpleNamespace(evidence_ref="trusted-dispatch")
    ]
    runtime.service.now.return_value = 1234

    @contextmanager
    def sessions(_):
        yield SimpleNamespace(get=lambda *_: row)

    monkeypatch.setattr("scopelens.orchestration.followup_contexts.session_scope", sessions)
    monkeypatch.setattr("scopelens.callbacks.deployment.runtime_from_settings", lambda _: runtime)
    monkeypatch.setattr(
        "scopelens.callbacks.integration.frozen_callback_tasks", lambda *_, **__: [task]
    )
    verifier = Mock(
        return_value=SimpleNamespace(
            status=ControlOutcome.CONFIRMED_ISSUE, summary="Signed target receipt proof"
        )
    )
    monkeypatch.setattr("scopelens.callbacks.runtime.evaluate_stored_callback_proof", verifier)
    _, hypothesis, _ = reflection()
    hypothesis = hypothesis.model_copy(
        update={
            "family": "callback",
            "operation": "verify-callback",
            "proof_id": "callback",
            "url": task.recipe.target_url,
            "max_requests": 0,
        }
    )
    result = verify_callback_followup(
        None, candidate=hypothesis.model_dump(), scan_id=uuid4(), run_id="read-only-callback"
    )
    assert verify_followup(hypothesis, result.artifacts())["state"] == "corroborated"
    runtime.stored_dispatch_evidence.assert_called_once_with(task)
    assert [call[0] for call in runtime.method_calls] == ["stored_dispatch_evidence", "service.now"]
    assert verifier.call_args.kwargs["trusted_refs"] == {"trusted-dispatch"}
