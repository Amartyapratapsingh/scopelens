"""Reserve bounded model work durably, call outside the transaction, then recheck authority."""

from pydantic import BaseModel, ConfigDict, Field

from scopelens.broker.policy import scan_for_token
from scopelens.browser.policy import BrowserCommand, command
from scopelens.persistence.repositories import record_audit
from scopelens.persistence.session import session_scope


class VisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    egress_token: str
    owner: str = Field(min_length=16, max_length=128)
    screenshot: str = Field(max_length=500000, pattern=r"^[A-Za-z0-9+/=]+$")
    dom: str = Field(max_length=32000)


def vision(settings, request):
    role = settings.browser_model
    if not role.configured or role.base_url not in settings.approved_model_base_urls:
        return {"allowed": False, "reason": "provider_not_configured_or_approved"}
    with session_scope(settings) as db:
        decision = command(
            db,
            settings,
            BrowserCommand(
                egress_token=request.egress_token, owner=request.owner, operation="open"
            ),
        )
        if not decision["allowed"]:
            return decision
        scan = scan_for_token(db, request.egress_token)
        plan = dict(scan.assessment_plan or {})
        calls = list(plan.get("browser_model_calls", []))
        if len(calls) >= settings.browser_model_max_calls:
            return {"allowed": False, "reason": "model_call_budget"}
        scan_id = scan.id
        index = len(calls)
        calls.append({"state": "reserved", "model": role.model, "cost": None})
        scan.assessment_plan = {**plan, "browser_model_calls": calls}
    from scopelens.orchestration.models import call_model

    result = call_model(
        settings, scan_id, "browser", {"screenshot": request.screenshot, "dom": request.dom}
    )
    if result.get("state") == "completed":
        result = {**result, "state": "suggested", "point": result["value"]}
    with session_scope(settings) as db:
        decision = command(
            db,
            settings,
            BrowserCommand(
                egress_token=request.egress_token, owner=request.owner, operation="open"
            ),
        )
        scan = scan_for_token(db, request.egress_token)
        if scan:
            plan = dict(scan.assessment_plan or {})
            calls = list(plan.get("browser_model_calls", []))
            calls[index] = {**calls[index], **result}
            scan.assessment_plan = {**plan, "browser_model_calls": calls}
            record_audit(
                db,
                actor="browser-model",
                action="model.complete",
                subject_type="scan",
                subject_id=str(scan.id),
                outcome=result["state"],
                detail={"call": index, "cost": result.get("cost")},
            )
        if not decision["allowed"]:
            return decision
    return {"allowed": result["state"] == "suggested", **result}
