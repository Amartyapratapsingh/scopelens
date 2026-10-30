from types import SimpleNamespace

import pytest

from scopelens.config import ModelRoleSettings
from scopelens.orchestration.models import call_model
from scopelens.persistence.models import ScanRow
from scopelens.persistence.session import session_scope


@pytest.mark.db
def test_all_roles_share_durable_call_and_cost_limits(queued_scan, settings, monkeypatch):
    scan, _ = queued_scan
    role = ModelRoleSettings(base_url="http://provider.invalid", model="test", json_mode=True)
    settings.planner_model = settings.browser_model = settings.report_writer_model = role
    settings.model_max_calls = 2
    settings.model_cost_ceiling = 1
    calls = []

    def post(*args, **kwargs):
        calls.append(kwargs["json"])
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "state": "completed",
                "cost": None,
                "value": {"candidate_id": "a", "reason": "b"},
            },
        )

    monkeypatch.setattr("scopelens.orchestration.models.httpx.post", post)
    assert call_model(settings, scan.id, "planner", {})["state"] == "completed"
    assert call_model(settings, scan.id, "browser", {})["state"] == "completed"
    assert call_model(settings, scan.id, "report_writer", {})["reason"] == "model call limit"
    with session_scope(settings) as db:
        ledger = db.get(ScanRow, scan.id).assessment_plan["model_calls"]
        assert [r["state"] for r in ledger] == ["completed", "completed"]
        assert sum(r["charged_ceiling"] for r in ledger) == 1
        assert all(r["cost"] is None for r in ledger)
    assert len(calls) == 2


@pytest.mark.db
def test_unknown_gateway_outcome_is_charged_and_not_retried(queued_scan, settings, monkeypatch):
    import httpx

    scan, _ = queued_scan
    settings.planner_model = ModelRoleSettings(base_url="http://provider.invalid", model="test")
    settings.model_max_calls = 1
    seen = []

    def fail(*a, **kw):
        seen.append(1)
        raise httpx.ReadTimeout("synthetic")

    monkeypatch.setattr("scopelens.orchestration.models.httpx.post", fail)
    assert call_model(settings, scan.id, "planner", {})["state"] == "unavailable"
    assert call_model(settings, scan.id, "planner", {})["reason"] == "model call limit"
    assert len(seen) == 1


@pytest.mark.db
def test_fallback_reserves_both_attempts_and_gateway_waits_for_chain(
    queued_scan, settings, monkeypatch
):
    scan, _ = queued_scan
    fallback = ModelRoleSettings(
        base_url="http://provider.invalid", model="fallback", timeout_seconds=60
    )
    settings.planner_model = ModelRoleSettings(
        base_url="http://provider.invalid",
        model="primary",
        timeout_seconds=60,
        fallbacks=[fallback],
    )
    settings.model_max_calls = 30
    settings.model_cost_ceiling = 5
    seen = []

    def post(*args, **kw):
        seen.append(kw)
        return SimpleNamespace(
            raise_for_status=lambda: None, json=lambda: {"state": "completed", "cost": None}
        )

    monkeypatch.setattr("scopelens.orchestration.models.httpx.post", post)
    assert call_model(settings, scan.id, "planner", {})["state"] == "completed"
    assert seen[0]["timeout"] == 130
    assert seen[0]["json"]["remaining_cost"] == pytest.approx(1 / 3)
    with session_scope(settings) as db:
        call = db.get(ScanRow, scan.id).assessment_plan["model_calls"][0]
        assert call["attempt_slots"] == 2
        assert call["charged_ceiling"] == pytest.approx(1 / 3)
