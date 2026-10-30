"""Durable admission for reviewed GET captures in the expanded browser worker."""

from contextlib import contextmanager, suppress

from scopelens.broker.probe_tasks import input_reference
from scopelens.browser.policy import BrowserAction
from scopelens.browser.worker import ActionDenied


class ReviewedCaptureAdmission:
    def __init__(self, controller):
        self.controller = controller

    @contextmanager
    def capture(self, task, request):
        # A's frozen accounting authority is GET-only. Existing approved POST captures
        # keep their local exploration cap and ordinary target HTTP authorization.
        if request["method"] != "GET":
            yield False
            return
        sequence = self.controller.sequence + 1
        action = BrowserAction(kind="navigate", url=request["url"])
        try:
            decision = self.controller.command(
                "admit",
                sequence=sequence,
                action=action.model_dump(),
                probe_task=input_reference(task.id),
            )
        except ActionDenied as exc:
            raise ValueError("browser_action_not_admitted") from exc
        self.controller.sequence = sequence
        result = "failed"
        try:
            # Only the trusted policy verdict can select the active local budget.
            yield bool(decision and decision.get("reviewed_probe") is True)
            result = "succeeded"
        finally:
            with suppress(Exception):
                self.controller.command("complete", result=result)
