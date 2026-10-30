"""Durable single-owner browser sessions and deterministic action admission."""

import re
import uuid
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from scopelens.broker.policy import (
    BrokerRequest,
    _check_scope_membership,
    _related_scope,
    scan_for_token,
)
from scopelens.broker.probe_tasks import reviewed_request_limit
from scopelens.config import Settings
from scopelens.execution.budget import remaining
from scopelens.execution.leases import lease_is_live
from scopelens.execution.ledger import budget_limits_for
from scopelens.persistence.models import BrowserSessionRow
from scopelens.persistence.repositories import record_audit, scope_row_to_domain
from scopelens.scope.validator import ScopeViolation
from scopelens.security.redaction import redact

REVIEWED_BROWSER_CONTROLS = frozenset({"SL-C03-XSS-01", "SL-C03-HTML-01", "SL-C03-DOMXSS-01"})

UNSAFE = re.compile(
    r"logout|log.out|sign.out|delete|remove|purchase|checkout|pay(?:ment)?|buy|order|send|e-?mail|sms|subscribe|unsubscribe|reset|upload|withdraw|transfer",
    re.I,
)
SAFE_CONTROL = re.compile(
    r"^(?:open|show|view|expand|more|next|previous|back|close|cancel|search|details|menu|tab|load|inspect)\b",
    re.I,
)


class BrowserAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["observe", "navigate", "click", "type", "submit", "coordinate"]
    url: str = Field(max_length=4096)
    label: str = Field(default="", max_length=1000)
    selector: str = Field(default="", max_length=1000)
    form_method: str = "GET"
    value: str = Field(default="", max_length=128)
    x: int | None = Field(default=None, ge=0, le=1920)
    y: int | None = Field(default=None, ge=0, le=1080)
    state_hash: str = Field(default="", max_length=64)


class BrowserCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")
    egress_token: str = Field(min_length=1)
    owner: str = Field(min_length=16, max_length=128)
    operation: Literal["open", "admit", "complete", "close"]
    sequence: int = Field(default=0, ge=0)
    action: BrowserAction | None = None
    probe_task: str | None = Field(default=None, min_length=1, max_length=128)
    before_hash: str = Field(default="", max_length=64)
    after_hash: str = Field(default="", max_length=64)
    result: Literal["succeeded", "failed", "blocked"] = "succeeded"


def action_reason(action: BrowserAction, *, vision_enabled: bool = False) -> str | None:
    if UNSAFE.search(" ".join([action.url, action.label, action.selector])):
        return "side_effect_intent"
    if action.kind in {"click", "type", "submit", "coordinate"}:
        if not action.state_hash:
            return "missing_observed_state"
        if not SAFE_CONTROL.search(action.label.strip()):
            return "intent_not_reviewed"
    if action.kind in {"submit", "type"} and (
        action.form_method != "GET" or not re.search("search", action.label, re.I)
    ):
        return "only_read_only_search_forms"
    if action.kind == "coordinate" and not vision_enabled:
        return "vision_unavailable"
    return None


def command(session: Session, settings: Settings, request: BrowserCommand) -> dict:
    session.expire_all()
    scan = scan_for_token(session, request.egress_token)
    if scan is None:
        return {"allowed": False, "reason": "unknown_token"}
    session.refresh(scan, with_for_update=True)
    now = datetime.now(UTC)
    if (
        scan.cancel_requested_at
        or scan.cancel_epoch != scan.egress_token_epoch
        or not lease_is_live(session, scan.id, now=now)
    ):
        return {"allowed": False, "reason": "revoked_or_expired"}
    scope = scope_row_to_domain(scan.scope_version)
    if scope.is_expired(now):
        return {"allowed": False, "reason": "scope_expired"}
    row = session.get(BrowserSessionRow, scan.id)
    reason = None
    reviewed_probe = False
    if request.operation == "open":
        if row and (row.owner != request.owner or row.status != "active" or row.expires_at <= now):
            reason = "context_already_owned"
        elif not row:
            row = BrowserSessionRow(
                scan_id=scan.id,
                owner=request.owner,
                context_id=str(uuid.uuid4()),
                scope_revision=scope.content_hash(),
                expires_at=min(now + timedelta(minutes=15), scope.authorization_expires_at),
                sequence=0,
                status="active",
                cancel_epoch=scan.cancel_epoch,
                actions=[],
            )
            session.add(row)
    elif row is None or row.owner != request.owner or row.status != "active":
        reason = "not_active_owner"
    elif row.expires_at <= now or row.cancel_epoch != scan.cancel_epoch:
        reason = "session_expired"
    elif request.operation == "admit":
        # Sequence orders all actions; only unreviewed actions spend exploration capacity.
        exploration_used = row.sequence - sum(bool(a.get("probe_task")) for a in row.actions)
        if row.inflight or request.sequence != row.sequence + 1:
            reason = "action_order_or_inflight"
        elif request.action is None:
            reason = (
                "action_budget"
                if exploration_used >= settings.browser_max_actions
                else "action_required"
            )
        else:
            action = request.action
            target = urlsplit(action.url)
            task_limit = None
            broker_request = None
            if target.scheme in {"http", "https"} and target.hostname:
                broker_request = BrokerRequest(
                    method="GET",
                    scheme=target.scheme,
                    host=target.hostname,
                    port=target.port or (443 if target.scheme == "https" else 80),
                    path=(target.path or "/") + ("?" + target.query if target.query else ""),
                    egress_token=request.egress_token,
                    probe_task=request.probe_task,
                )
                if request.probe_task and action.kind == "navigate" and action.form_method == "GET":
                    # Invalid references retain exploration accounting.
                    with suppress(ScopeViolation, ValueError):
                        task_limit = reviewed_request_limit(
                            scan,
                            scope,
                            settings,
                            broker_request,
                            allowed_controls=REVIEWED_BROWSER_CONTROLS,
                        )
            usage = dict((scan.assessment_plan or {}).get("reviewed_browser_actions", {}))
            if task_limit is not None:
                used = usage.get(request.probe_task, 0)
                http_used = (
                    (scan.assessment_plan or {})
                    .get("reviewed_probe_requests", {})
                    .get(request.probe_task, 0)
                )
                if sum(usage.values()) >= settings.browser_max_active_actions:
                    reason = "active_action_budget"
                elif max(used, http_used) >= task_limit:
                    reason = "reviewed_browser_task_budget"
                elif remaining(scan, budget_limits_for(scan.scope_version, settings)).requests < 1:
                    reason = "request_budget"
            elif exploration_used >= settings.browser_max_actions:
                reason = "action_budget"
            if target.scheme not in {"http", "https"} or not target.hostname:
                reason = reason or "invalid_destination"
            elif not reason:
                membership_scope = scope
                if task_limit is not None and (
                    broker_request.host != scope.host or broker_request.port != scope.port
                ):
                    related = _related_scope(session, scan, scope, broker_request)
                    if related is not None:
                        membership_scope = related[1]
                decision = _check_scope_membership(
                    membership_scope,
                    broker_request,
                )
                if broker_request.host != membership_scope.host:
                    reason = "destination_refused"
                elif membership_scope.is_expired(now):
                    reason = "scope_expired"
                else:
                    reason = (
                        decision.reason
                        if decision
                        else action_reason(
                            action,
                            vision_enabled=(
                                settings.browser_model.configured
                                and settings.browser_model.vision
                                and settings.browser_model.json_mode
                                and settings.browser_model.base_url
                                in settings.approved_model_base_urls
                            ),
                        )
                    )
            if not reason:
                if task_limit is not None:
                    reviewed_probe = True
                    usage[request.probe_task] = usage.get(request.probe_task, 0) + 1
                    scan.assessment_plan = {
                        **(scan.assessment_plan or {}),
                        "reviewed_browser_actions": usage,
                    }
                row.sequence = request.sequence
                row.inflight = True
                row.actions = [
                    *row.actions,
                    {
                        "sequence": request.sequence,
                        "action": redact(action.model_dump()),
                        "state": "admitted",
                        "at": now.isoformat(),
                        **({"probe_task": request.probe_task} if task_limit is not None else {}),
                    },
                ]
    elif request.operation == "complete":
        if not row.inflight or row.sequence != request.sequence:
            reason = "action_not_inflight"
        else:
            row.inflight = False
            row.actions = [
                *row.actions[:-1],
                {
                    **row.actions[-1],
                    "state": request.result,
                    "before": request.before_hash,
                    "after": request.after_hash,
                },
            ]
    elif request.operation == "close":
        row.status = "closed"
        row.inflight = False
    if not reason and row is not None and row.status == "active":
        # Keep the idle bound without expiring a continuously active owner.
        # All lease, cancellation, scope, action and task checks precede renewal;
        # an expired or denied session is never revived here.
        row.expires_at = min(now + timedelta(minutes=15), scope.authorization_expires_at)
    record_audit(
        session,
        actor="browser-policy",
        action=f"browser.{request.operation}",
        subject_type="scan",
        subject_id=str(scan.id),
        outcome="denied" if reason else "allowed",
        detail={"reason": str(reason) if reason else "", "sequence": request.sequence},
    )
    session.flush()
    return {
        "allowed": not bool(reason),
        "reason": str(reason or "allowed"),
        "context_id": row.context_id if row else None,
        "sequence": row.sequence if row else 0,
        "reviewed_probe": reviewed_probe,
    }
