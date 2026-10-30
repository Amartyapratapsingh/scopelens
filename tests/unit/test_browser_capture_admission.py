"""Capture admission never skips sequence or executes a denied navigation."""

from types import SimpleNamespace

import pytest

from scopelens.browser.admission import ReviewedCaptureAdmission
from scopelens.browser.worker import ActionDenied


def test_reviewed_get_admission_and_completion_bind_actual_navigation():
    calls = []
    controller = SimpleNamespace(
        sequence=40, command=lambda op, **fields: calls.append((op, fields))
    )
    request = {"method": "GET", "url": "https://fixture.invalid/app?q=marker"}
    with ReviewedCaptureAdmission(controller).capture(SimpleNamespace(id="task"), request):
        assert controller.sequence == 41
    assert [op for op, _ in calls] == ["admit", "complete"]
    assert calls[0][1]["sequence"] == 41
    assert calls[0][1]["probe_task"] == "input:task"
    assert calls[0][1]["action"]["url"] == request["url"]
    assert calls[1][1]["result"] == "succeeded"


def test_denied_capture_never_runs_or_advances_sequence():
    calls = []
    controller = SimpleNamespace(sequence=40)

    def deny(op, **fields):
        calls.append((op, fields))
        raise ActionDenied("active_action_budget")

    controller.command = deny
    for _ in range(2):
        with (
            pytest.raises(ValueError, match="browser_action_not_admitted"),
            ReviewedCaptureAdmission(controller).capture(
                SimpleNamespace(id="task"), {"method": "GET", "url": "https://fixture.invalid/"}
            ),
        ):
            pytest.fail("denied capture executed")
    assert controller.sequence == 40
    assert [fields["sequence"] for _, fields in calls] == [41, 41]


def test_failed_capture_completes_without_erasing_original_failure():
    calls = []
    controller = SimpleNamespace(
        sequence=0, command=lambda op, **fields: calls.append((op, fields))
    )
    with (
        pytest.raises(OSError, match="fixture transport"),
        ReviewedCaptureAdmission(controller).capture(
            SimpleNamespace(id="task"), {"method": "GET", "url": "https://fixture.invalid/"}
        ),
    ):
        raise OSError("fixture transport")
    assert calls[-1] == ("complete", {"result": "failed"})
    assert controller.sequence == 1


def test_legacy_post_capture_does_not_gain_get_accounting_authority():
    controller = SimpleNamespace(sequence=0, command=lambda *a, **k: pytest.fail("POST annotation"))
    with ReviewedCaptureAdmission(controller).capture(
        SimpleNamespace(id="task"), {"method": "POST", "url": "https://fixture.invalid/"}
    ):
        pass
    assert controller.sequence == 0


@pytest.mark.parametrize(
    "verdict,reviewed",
    [
        (None, False),
        ({}, False),
        ({"reviewed_probe": False}, False),
        ({"reviewed_probe": "true"}, False),
        ({"reviewed_probe": True}, True),
    ],
)
def test_only_validated_policy_verdict_selects_active_local_budget(verdict, reviewed):
    controller = SimpleNamespace(sequence=0, command=lambda *a, **k: verdict)
    with ReviewedCaptureAdmission(controller).capture(
        SimpleNamespace(id="task"), {"method": "GET", "url": "https://fixture.invalid/"}
    ) as value:
        assert value is reviewed
