"""Atomic scan-wide model reservations, including failed/unknown calls."""

import uuid

import httpx
from sqlalchemy import select

from scopelens.adapters.roles import PROMPT_VERSION
from scopelens.persistence.models import ScanRow
from scopelens.persistence.repositories import record_audit
from scopelens.persistence.session import session_scope


def call_model(settings, scan_id, name, payload):
    role = getattr(settings, ("planner" if name == "script" else name) + "_model")
    if not role.configured:
        return {"state": "unavailable", "reason": "role not configured", "cost": None}
    with session_scope(settings) as db:
        scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
        if not scan or scan.cancel_requested_at:
            return {"state": "cancelled", "cost": None}
        plan = dict(scan.assessment_plan or {})
        calls = [dict(item) for item in plan.get("model_calls", [])]
        attempts_reserved = sum(c.get("attempt_slots", 1) for c in calls)
        slots = 1 + min(2, len(role.fallbacks))
        if attempts_reserved + slots > settings.model_max_calls:
            return {"state": "unavailable", "reason": "model call limit", "cost": None}
        spent = sum(max(c.get("charged_ceiling", 0), c.get("cost") or 0) for c in calls)
        remaining = max(0, settings.model_cost_ceiling - spent)
        if remaining <= 0:
            return {"state": "unavailable", "reason": "model cost ceiling", "cost": None}
        # Reserve a bounded slice before I/O. Concurrent roles cannot spend the same credit.
        reservation = min(remaining, slots * settings.model_cost_ceiling / settings.model_max_calls)
        call_id = uuid.uuid4().hex
        calls.append(
            {
                "id": call_id,
                "role": name,
                "attempt_slots": slots,
                "state": "outcome_unknown",
                "charged_ceiling": reservation,
                "cost": None,
                "prompt_version": PROMPT_VERSION,
            }
        )
        scan.assessment_plan = {**plan, "model_calls": calls}
    result = {"state": "unavailable", "cost": None}
    try:
        response = httpx.post(
            settings.model_gateway_url.rstrip("/") + "/complete",
            json={"role": name, "payload": payload, "remaining_cost": reservation},
            headers={"Authorization": "Bearer " + settings.session_secret.get_secret_value()},
            timeout=10 + sum(r.timeout_seconds for r in [role, *role.fallbacks[:2]]),
            trust_env=False,
            follow_redirects=False,
        )
        response.raise_for_status()
        result = response.json()
    except (httpx.HTTPError, ValueError, AttributeError):
        result = {"state": "unavailable", "reason": "provider gateway unavailable", "cost": None}
    with session_scope(settings) as db:
        scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
        plan = dict(scan.assessment_plan or {})
        calls = [dict(item) for item in plan.get("model_calls", [])]
        for item in calls:
            if item["id"] == call_id:
                # Never store model prose/scripts in the public ledger.
                item.update({k: result[k] for k in ("state", "cost", "attempts") if k in result})
        scan.assessment_plan = {**plan, "model_calls": calls}
        record_audit(
            db,
            actor="model-adapter",
            action="model.complete",
            subject_type="scan",
            subject_id=str(scan_id),
            outcome=result.get("state", "unavailable"),
            detail={"role": name, "call_id": call_id, "cost": result.get("cost")},
        )
        if scan.cancel_requested_at:
            return {"state": "cancelled", "cost": result.get("cost")}
    return result
