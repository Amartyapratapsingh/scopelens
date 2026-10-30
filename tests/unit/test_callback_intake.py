"""The supervisor drops callback captures supplied by worker stdout."""

from types import SimpleNamespace

from scopelens.execution.coordinator import _analyse


def test_worker_cannot_supply_callback_snapshot(monkeypatch):
    stored = []

    def record(*args, **kwargs):
        stored.append(kwargs)
        return SimpleNamespace(id=f"trusted-{len(stored)}")

    monkeypatch.setattr("scopelens.execution.coordinator.intake.record_json_evidence", record)
    monkeypatch.setattr("scopelens.checks.analyze.analyze", lambda **kwargs: kwargs["artifacts"])
    artifacts = [
        {"kind": "surface", "data": {}},
        {"kind": "callback_capture", "source": "callback_broker", "data": {"confirmed": True}},
        {"kind": "callback_diagnostic", "data": {"state": "confirmed"}},
    ]
    result = _analyse(
        settings=SimpleNamespace(scanner_tools_enabled=False, tool_worker_image="fixed"),
        session=None,
        scan=SimpleNamespace(assessment_plan={}),
        scope=SimpleNamespace(model_dump=lambda **kwargs: {}),
        egress_token="private-token",
        worker_result=SimpleNamespace(artifacts=lambda: artifacts),
        evidence_ids=[],
        store=None,
    )
    assert [row["kind"] for row in result] == ["surface"]
    assert all(row["producer"] != "reviewed_callback_broker_capture" for row in stored)
