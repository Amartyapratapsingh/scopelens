"""Dashboard API (Build Plan §5.17, §5.16).

The contract the React frontend consumes. The frontend is M2's out-of-scope half (§0 rule 9),
so everything it needs is served here and described in `docs/API_CONTRACT.md`.

Two properties are enforced in this module rather than left to the client:

* **Every SSE event is redacted and carries a monotonic cursor.** The cursor is the audit
  row's `seq`, so a reconnect resumes without gaps and without replaying. Raw graph state,
  worker stdout and secrets never appear on the stream — Build Plan §5.17 and Plan §11 both
  require a deliberately constructed event schema rather than a forwarded one.
* **A category tile always says why it has no number.** Spec §9.4 forbids substituting 0 or
  100 for an unknown result, so the tile carries its state and reason alongside any score.
"""

from __future__ import annotations

import asyncio
import copy
import json
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from scopelens.adapters.scanners import ScannerResult
from scopelens.api.deps import AppSettings, CurrentOperator, DbSession
from scopelens.discovery.host_metadata import HostMetadata
from scopelens.discovery.priorities import HostPriorityPlan, normalized_host, prioritize_hosts
from scopelens.domain.check import Location
from scopelens.domain.enums import Category, Confidence, EvidenceStatus, Severity
from scopelens.domain.report_metadata import Capabilities, ReachSummary
from scopelens.persistence.models import (
    AuditEventRow,
    BrowserSessionRow,
    EvidenceRow,
    FindingRow,
    ScanRow,
    ScopeVersionRow,
)
from scopelens.persistence.repositories import get_scan
from scopelens.security.redaction import redact
from scopelens.writer.report import build_report, render_html, render_json

router = APIRouter(prefix="/api", tags=["dashboard"])

#: How long the SSE loop waits between polls. Long enough not to spin, short enough that a
#: status change appears promptly.
SSE_POLL_SECONDS = 1.0
#: How many events a single connection streams before closing so the client can reconnect
#: on a fresh cursor. Bounds the work one connection can do.
SSE_MAX_EVENTS = 500


class FindingView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    check_id: str
    canonical_control: str
    root_cause: str
    category: Category
    category_title: str
    title: str
    severity: Severity
    evidence_status: EvidenceStatus
    confidence: Confidence
    confidence_reasons: list[str]
    status: str
    retest_state: str | None
    locations: list[Location]
    evidence_refs: list[str]
    detail: str
    what: str
    why: str
    fix: str
    references: list[str]


class CategoryTile(BaseModel):
    """One of the twelve tiles (Spec §9.4, §9.5).

    All twelve are always present. An out-of-profile tile says `Not assessed in this profile`
    rather than being omitted, because a missing tile reads as a zero.
    """

    model_config = ConfigDict(extra="forbid")

    category: Category
    title: str
    weight: int
    in_profile: bool
    state: str
    score: int | None
    coverage_percent: float
    reason: str
    caps_applied: list[str]
    confirmed_counts: dict[str, int]


class DiscoverySummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pages_fetched: int
    stopped_by: str | None = None


class ScanSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    target_origin: str
    profile: str
    status: str
    status_reason: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    findings_count: int
    verdict: str
    overall_score: int | None
    overall_state: str
    overall_reason: str
    overall_label: str
    coverage_percent: float
    severity_counts: dict[str, int]
    score_version: str
    capabilities: Capabilities | None = None
    reach: ReachSummary | None = None
    discovery: DiscoverySummary | None = None


class HostInventoryEntry(HostMetadata):
    model_config = ConfigDict(extra="forbid")

    host: str
    role: str
    evidence: str | None = None


def _owned_scan(session: Session, scan_id: uuid.UUID, operator) -> ScanRow:  # type: ignore[no-untyped-def]
    scan = get_scan(session, scan_id)
    # A scan belonging to another operator is reported as missing, not forbidden: a 403 would
    # confirm the id exists.
    if scan is None or scan.operator_id != operator.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


def _report(session: Session, scan: ScanRow) -> dict[str, Any]:
    return build_report(session=session, scan=scan)


@router.get("/scans/{scan_id}/summary", response_model=ScanSummary)
def scan_summary(scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession) -> ScanSummary:
    scan = _owned_scan(session, scan_id, operator)
    report = _report(session, scan)
    return ScanSummary(
        scan_id=report["scan"]["id"],
        target_origin=report["scan"]["target_origin"],
        profile=report["profile"],
        status=report["scan"]["status"],
        status_reason=report["scan"]["status_reason"],
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        findings_count=len(report["findings"]),
        verdict=report["score"]["verdict"],
        overall_score=report["score"]["score"],
        overall_state=report["score"]["state"],
        overall_reason=report["score"]["reason"],
        overall_label=report["overall_label"],
        coverage_percent=report["score"]["coverage_percent"],
        severity_counts=report["severity_counts"],
        score_version=report["score_version"],
        capabilities=report.get("capabilities"),
        reach=report.get("reach"),
        discovery=(
            DiscoverySummary(
                pages_fetched=report["attack_surface"]["stats"]["pages_fetched"],
                stopped_by=report["attack_surface"]["stats"].get("stopped_by"),
            )
            if (report.get("attack_surface") or {}).get("stats")
            else None
        ),
    )


@router.get("/scans/{scan_id}/findings", response_model=list[FindingView])
def scan_findings(
    scan_id: uuid.UUID,
    operator: CurrentOperator,
    session: DbSession,
    severity: Annotated[list[Severity] | None, Query()] = None,
    confidence: Annotated[list[Confidence] | None, Query()] = None,
    evidence_status: Annotated[list[EvidenceStatus] | None, Query()] = None,
) -> list[FindingView]:
    """Findings for a scan, optionally filtered. Filters are exact matches, not substrings."""
    scan = _owned_scan(session, scan_id, operator)
    findings = _report(session, scan)["findings"]

    if severity:
        findings = [f for f in findings if f["severity"] in {s.value for s in severity}]
    if confidence:
        findings = [f for f in findings if f["confidence"] in {c.value for c in confidence}]
    if evidence_status:
        findings = [
            f for f in findings if f["evidence_status"] in {e.value for e in evidence_status}
        ]
    return [FindingView(**_finding_payload(f)) for f in findings]


@router.get("/findings/{finding_id}", response_model=FindingView)
def finding_detail(
    finding_id: uuid.UUID, operator: CurrentOperator, session: DbSession
) -> FindingView:
    """Finding detail, scoped to the operator that owns its scan."""
    row = session.get(FindingRow, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    scan = get_scan(session, row.scan_id)
    if scan is None or scan.operator_id != operator.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    for finding in _report(session, scan)["findings"]:
        if finding["id"] == str(row.id):
            return FindingView(**_finding_payload(finding))
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")


@router.get("/scans/{scan_id}/categories", response_model=list[CategoryTile])
def category_tiles(
    scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession
) -> list[CategoryTile]:
    """All twelve tiles, each with a score or the reason it has none (Spec §9.4)."""
    scan = _owned_scan(session, scan_id, operator)
    report = _report(session, scan)

    by_category: dict[str, dict[str, Any]] = {
        entry["category"]: entry for entry in report["score"]["categories"]
    }
    counts: dict[str, dict[str, int]] = {}
    for finding in report["findings"]:
        bucket = counts.setdefault(finding["category"], {})
        bucket[finding["severity"]] = bucket.get(finding["severity"], 0) + 1

    tiles: list[CategoryTile] = []
    for category in Category:
        entry = by_category.get(category.value)
        in_profile = entry is not None and category.value in report["score"]["profile_weights"]
        tiles.append(
            CategoryTile(
                category=category,
                title=category.title,
                weight=int(entry["weight"]) if entry else 0,
                in_profile=in_profile,
                state=entry["state"] if entry else "not_assessed",
                score=entry["score"] if entry else None,
                coverage_percent=float(entry["coverage_percent"]) if entry else 0.0,
                reason=entry["reason"] if entry else "Not assessed in this profile",
                caps_applied=list(entry["caps_applied"]) if entry else [],
                confirmed_counts=counts.get(category.value, {}),
            )
        )
    return tiles


@router.get("/scans/{scan_id}/hosts", response_model=list[HostInventoryEntry])
def host_inventory(
    scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession
) -> list[HostInventoryEntry]:
    """Hosts seen by the crawl, flagged tested or inventory-only (Spec §7.2, §9.1)."""
    scan = _owned_scan(session, scan_id, operator)
    return [
        HostInventoryEntry.model_validate(entry)
        for entry in _report(session, scan)["host_inventory"]
    ]


@router.get("/scans/{scan_id}/host-priorities", response_model=HostPriorityPlan)
def host_priorities(
    scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession, settings: AppSettings
) -> HostPriorityPlan:
    """Read-only triage across this operator's observed hosts and completed reports."""
    from urllib.parse import urlsplit

    scan = _owned_scan(session, scan_id, operator)
    inventory = _report(session, scan)["host_inventory"]
    wanted = {normalized_host(str(row.get("host", ""))) for row in inventory}
    # Restrict by owner before selecting any reports. Inventory text cannot grant access.
    candidates = session.scalars(
        select(ScanRow)
        .join(ScopeVersionRow, ScanRow.scope_version_id == ScopeVersionRow.id)
        .where(
            ScanRow.operator_id == operator.id,
            ScopeVersionRow.host.in_(wanted),
            ScanRow.status.in_(["completed", "completed_partial"]),
            ScanRow.finished_at.is_not(None),
        )
        .distinct(ScopeVersionRow.host)
        .order_by(ScopeVersionRow.host, ScanRow.created_at.desc(), ScanRow.id.desc())
    )
    reports = {}
    for candidate in candidates:
        host = normalized_host(urlsplit(candidate.target_origin).hostname or "")
        if host not in reports:
            reports[host] = _report(session, candidate)
        if wanted <= reports.keys():
            break
    return prioritize_hosts(
        inventory,
        reports,
        owned_domains=settings.discovery_owned_domains,
        discovery=(scan.assessment_plan or {}).get("passive_host_discovery"),
    )


@router.get("/scans/{scan_id}/export.json")
def export_json(
    scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession
) -> PlainTextResponse:
    """The JSON export. Redacted, like every other output (Spec §9.10)."""
    scan = _owned_scan(session, scan_id, operator)
    return PlainTextResponse(
        render_json(_report(session, scan)),
        media_type="application/json",
        headers={"content-disposition": f'attachment; filename="scopelens-{scan.id}.json"'},
    )


@router.get("/scans/{scan_id}/export.html")
def export_html(
    scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession
) -> PlainTextResponse:
    """The self-contained HTML report, escaped by the template environment."""
    scan = _owned_scan(session, scan_id, operator)
    return PlainTextResponse(
        render_html(_report(session, scan)),
        media_type="text/html",
        headers={"content-disposition": f'attachment; filename="scopelens-{scan.id}.html"'},
    )


# --- SSE -----------------------------------------------------------------------------

#: Audit actions that are safe and useful to stream. An allowlist rather than a denylist: a
#: new audit action is not streamed until someone decides it should be, which is the fail-safe
#: direction for a channel that reaches a browser.
STREAMABLE_ACTIONS = frozenset(
    {
        "scan.create",
        "scan.cancel",
        "scan.reconcile",
        "task.admit",
        "task.settle",
        "broker.admit",
        "outbox.dispatch",
        "evidence.record",
        "score.ready",
        "retest.request",
        "retest.complete",
        "browser.open",
        "browser.admit",
        "browser.complete",
        "browser.close",
        "model.complete",
        "adaptive.plan",
        "adaptive.complete",
    }
)


class ProgressEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cursor: int
    at: str | None
    type: str
    scan_id: str
    action: str
    outcome: str
    status: str | None = None
    task_state: str | None = None
    finding_id: str | None = None
    reason: str | None = None
    verdict: str | None = None
    coverage_percent: float | None = None
    method: str | None = None
    route: str | None = None
    allowed: bool | None = None
    logical_id: str | None = None


def _event_from_audit(row: AuditEventRow, scan_id: str) -> dict[str, Any]:
    """Build one dashboard event from an audit row.

    The payload is constructed field by field. The audit row's own ``detail`` is not
    forwarded wholesale: an event schema assembled deliberately is the only way to be sure a
    field added later for internal use does not appear in a browser.
    """
    detail = row.detail or {}
    payload: dict[str, Any] = {"scan_id": scan_id, "action": row.action, "outcome": row.outcome}

    for key in ("status", "task_state", "finding_id", "reason", "verdict", "coverage_percent"):
        if key in detail:
            payload[key] = detail[key]
    if row.action == "broker.admit":
        payload["method"] = detail.get("method")
        payload["route"] = detail.get("path")
        payload["allowed"] = row.outcome == "allowed"
    if row.action == "outbox.dispatch":
        payload["logical_id"] = detail.get("logical_id")
    if row.action in {"task.admit", "task.settle"}:
        payload["task_state"] = row.outcome
        payload["status"] = detail.get("scan_status", detail.get("status"))

    return ProgressEvent.model_validate(
        redact(
            {
                "cursor": row.seq,
                "at": row.occurred_at.isoformat() if row.occurred_at else None,
                "type": row.action,
                **payload,
            }
        )
    ).model_dump(exclude_none=True)


async def _event_stream(
    request: Request, session_factory, scan_id: uuid.UUID, start_cursor: int
) -> AsyncIterator[str]:
    """Yield SSE frames with a monotonic cursor, until the client disconnects.

    Polls the durable audit trail rather than holding in-memory state, so a reconnect — after
    a reload, a network blip or a supervisor restart — resumes from the client's cursor with
    no gap and no replay.
    """
    cursor = start_cursor
    sent = 0

    while sent < SSE_MAX_EVENTS:
        if await request.is_disconnected():
            return

        with session_factory() as session:
            rows = (
                session.query(AuditEventRow)
                .filter(AuditEventRow.seq > cursor, AuditEventRow.action.in_(STREAMABLE_ACTIONS))
                .filter(
                    or_(
                        AuditEventRow.subject_id == str(scan_id),
                        AuditEventRow.detail["scan_id"].astext == str(scan_id),
                    )
                )
                .order_by(AuditEventRow.seq)
                .limit(50)
                .all()
            )
            events = []
            for row in rows:
                events.append(_event_from_audit(row, str(scan_id)))
                cursor = row.seq

        for event in events:
            sent += 1
            # `id:` is the cursor. `event:` and `data:` follow, and the frame ends with a
            # blank line as the SSE specification requires.
            yield f"id: {event['cursor']}\nevent: {event['type']}\ndata: {json.dumps(event)}\n\n"

        if sent >= SSE_MAX_EVENTS:
            # Tell the client to reconnect rather than closing silently, so a truncated
            # stream is visible as a reconnect and not as a finished scan.
            yield 'event: stream.limit\ndata: {"reconnect": true}\n\n'
            return

        await asyncio.sleep(SSE_POLL_SECONDS)


@router.get(
    "/scans/{scan_id}/events",
    responses={
        200: {
            "content": {"text/event-stream": {"schema": {"type": "string"}}},
            "description": "SSE frames; event data follows x-sse-event-schema",
        }
    },
    openapi_extra={"x-sse-event-schema": ProgressEvent.model_json_schema()},
)
async def scan_events(
    scan_id: uuid.UUID,
    request: Request,
    operator: CurrentOperator,
    session: DbSession,
    cursor: Annotated[int, Query(ge=0)] = 0,
) -> StreamingResponse:
    """Live progress: redacted, monotonic, resumable (Build Plan §5.17).

    The cursor is the last event id the client saw. Passing it resumes exactly after that
    point; omitting it starts from the beginning of the scan's history.
    """
    _owned_scan(session, scan_id, operator)
    last_id = request.headers.get("last-event-id")
    if last_id:
        try:
            cursor = max(cursor, int(last_id))
            if int(last_id) < 0:
                raise ValueError
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="invalid Last-Event-ID") from exc

    from scopelens.persistence.session import get_session_factory

    return StreamingResponse(
        _event_stream(request, get_session_factory(), scan_id, cursor),
        media_type="text/event-stream",
        headers={
            "cache-control": "no-store",
            # Proxies that buffer would defeat the point of a live stream.
            "x-accel-buffering": "no",
        },
    )


def _finding_payload(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": finding["id"],
        "check_id": finding["check_id"],
        "canonical_control": finding["canonical_control"],
        "root_cause": finding["root_cause"],
        "category": finding["category"],
        "category_title": finding["category_title"],
        "title": finding["title"],
        "severity": finding["severity"],
        "evidence_status": finding["evidence_status"],
        "confidence": finding["confidence"],
        "confidence_reasons": finding["confidence_reasons"],
        "status": finding["status"],
        "retest_state": finding["retest_status"]
        if "retest_status" in finding
        else finding.get("retest_state"),
        "locations": finding["locations"],
        "evidence_refs": finding["evidence_refs"],
        "detail": finding["detail"],
        "what": finding["what"],
        "why": finding["why"],
        "fix": finding["fix"],
        "references": finding["references"],
    }


class RetestView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    scan_id: str
    scope_version_id: str
    state: str
    detail: str


class RetestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope_version_id: uuid.UUID | None = None
    assessment_configuration_id: uuid.UUID | None = None


@router.post(
    "/findings/{finding_id}/retest", response_model=RetestView, status_code=status.HTTP_202_ACCEPTED
)
def request_retest(
    finding_id: uuid.UUID,
    operator: CurrentOperator,
    session: DbSession,
    settings: AppSettings,
    payload: RetestRequest | None = None,
) -> RetestView:
    """Start a fresh scan against the endpoint a finding was raised on (Build Plan §9 M2).

    A retest is a *new scan*, not a re-evaluation of stored data: Spec §9.8 requires a fixed
    issue to be closed by a successful relevant retest, which means new evidence. Nothing here
    closes the finding — the outcome of the retest scan decides that, and only if the retest
    reached the location. A blocked retest leaves the finding open, because an endpoint that
    could not be reached is not an endpoint that was fixed.
    """
    from scopelens.domain.task import TaskType
    from scopelens.execution.ledger import create_scan_with_task
    from scopelens.persistence.repositories import get_scope_version, record_audit

    row = session.get(FindingRow, finding_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    original = get_scan(session, row.scan_id)
    if original is None or original.operator_id != operator.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")
    if row.retest_state == "requested":
        raise HTTPException(status_code=409, detail="a retest is already pending")

    scope_row = get_scope_version(session, original.scope_version_id)
    if scope_row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="the scope this finding was raised under no longer exists",
        )

    from scopelens.api.scans import _revalidate_scope
    from scopelens.domain.enums import ProfileName

    original_scope = scope_row
    if payload and payload.scope_version_id:
        scope_row = get_scope_version(session, payload.scope_version_id)
        if scope_row is None or scope_row.operator_id != operator.id:
            raise HTTPException(404, "renewed scope not found")
        from scopelens.persistence.repositories import scope_row_to_domain

        if (
            scope_row_to_domain(scope_row).origin != original.target_origin
            or scope_row.authority_domain != original_scope.authority_domain
            or scope_row.allowed_check_profile != original.profile
        ):
            raise HTTPException(409, "retest renewal must retain the original target and profile")
    _revalidate_scope(scope_row, settings)
    preserved = {"adaptive_requested": False}
    if ProfileName(original.profile).expanded:
        from scopelens.api.assessments import validate_configuration
        from scopelens.domain.expansion import AssessmentConfiguration
        from scopelens.persistence.models import AssessmentConfigurationRow

        plan = original.assessment_plan or {}
        try:
            configuration_id = uuid.UUID(plan["configuration_id"])
            configuration = session.get(AssessmentConfigurationRow, configuration_id)
            if (
                configuration is None
                or configuration.operator_id != operator.id
                or configuration.scope_version_id != original_scope.id
                or configuration.content_hash != plan.get("configuration_hash")
                or configuration.configuration != plan.get("expansion_config")
                or original.profile != original_scope.allowed_check_profile
            ):
                raise ValueError("original configuration binding absent")
            frozen = AssessmentConfiguration.model_validate(configuration.configuration)
        except (KeyError, ValueError, TypeError):
            raise HTTPException(409, "original assessment configuration unavailable") from None
        if payload and payload.assessment_configuration_id:
            from scopelens.checks.retest_binding import case_contract

            renewed = session.get(AssessmentConfigurationRow, payload.assessment_configuration_id)
            if renewed is None or renewed.operator_id != operator.id:
                raise HTTPException(404, "renewed assessment configuration not found")
            if renewed.scope_version_id != scope_row.id or case_contract(
                renewed.configuration
            ) != case_contract(configuration.configuration):
                raise HTTPException(409, "retest renewal must retain the original declared cases")
            preserved["retest_renewal"] = {
                "source_scan_id": str(original.id),
                "source_configuration_hash": configuration.content_hash,
                "case_contract_hash": case_contract(configuration.configuration),
            }
            configuration = renewed
            frozen = AssessmentConfiguration.model_validate(configuration.configuration)
        elif scope_row.id != original_scope.id:
            raise HTTPException(409, "renewed assessment configuration required")
        validate_configuration(frozen, scope_row, session, operator, settings)
        preserved.update(
            expansion_config=copy.deepcopy(configuration.configuration),
            configuration_id=str(configuration.id),
            configuration_hash=configuration.content_hash,
        )

    scan, _task = create_scan_with_task(
        session,
        operator_id=operator.id,
        scope_version=scope_row,
        score_version=original.score_version,
        task_type=TaskType.CRAWL,
        actor=operator.username,
    )
    # The link is recorded on the finding so the report can say a retest is in flight. Its
    # status deliberately does NOT change: only a conclusive retest may close it.
    row.retest_state = "requested"
    row.retest_scan_id = scan.id
    scan.assessment_plan = {
        **preserved,
        "retest_routes": sorted({loc["route"] for loc in row.locations}),
    }

    record_audit(
        session,
        actor=operator.username,
        action="retest.request",
        subject_type="finding",
        subject_id=str(row.id),
        outcome="queued",
        detail={"finding_id": str(row.id), "scan_id": str(scan.id)},
    )
    session.commit()

    return RetestView(
        finding_id=str(row.id),
        scan_id=str(scan.id),
        scope_version_id=str(scope_row.id),
        state="requested",
        detail=(
            "a fresh scan was queued against the same scope; the finding stays open until "
            "that scan reaches the location and reaches a conclusive outcome"
        ),
    )


@router.get("/scans/{scan_id}/scanners", response_model=list[ScannerResult])
def scanner_results(scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession):
    from scopelens.adapters.scanners import scanner_profile_view

    scan = _owned_scan(session, scan_id, operator)
    return scanner_profile_view(
        (scan.assessment_plan or {}).get("scanner_results", []), scan.profile
    )


class BrowserView(BaseModel):
    context_id: str | None
    role: str = "unauthenticated"
    status: str
    actions: int
    states: int
    gaps: list[dict[str, Any]]
    evidence_refs: list[str]
    limitations: list[str]


@router.get("/scans/{scan_id}/browser", response_model=BrowserView)
def browser_view(scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession):
    scan = _owned_scan(session, scan_id, operator)
    context = session.get(BrowserSessionRow, scan.id)
    summary = (scan.assessment_plan or {}).get("browser") or {}
    status = summary.get("status") or (context.status if context else "not_tested")
    gaps = list(summary.get("gaps", []))
    if status == "active" and scan.status in {
        "completed",
        "completed_partial",
        "cancelled",
        "failed",
    }:
        status = "incomplete"
        gaps.append({"reason": "browser ended without a completion summary"})
    refs = (
        session.query(EvidenceRow.id)
        .filter(EvidenceRow.scan_id == scan.id, EvidenceRow.producer == "reviewed_browser_capture")
        .all()
    )
    return BrowserView(
        context_id=context.context_id if context else None,
        status=status,
        actions=context.sequence if context else summary.get("actions", 0),
        states=summary.get("states", 0),
        gaps=gaps,
        evidence_refs=[str(row[0]) for row in refs],
        limitations=[
            "Unauthenticated read-only exploration",
            "Cross-origin resources and WebSockets blocked",
            "Popups closed, downloads cancelled, service workers blocked",
            "Coordinates require a configured approved vision provider and a reviewed DOM action",
        ],
    )


@router.get(
    "/scans/{scan_id}/evidence/{evidence_id}/download",
    response_class=Response,
    responses={200: {"content": {"application/octet-stream": {}}}},
)
def download_evidence(
    scan_id: uuid.UUID,
    evidence_id: uuid.UUID,
    operator: CurrentOperator,
    session: DbSession,
    settings: AppSettings,
):
    from scopelens.evidence.store import LocalDiskEvidenceStore

    scan = _owned_scan(session, scan_id, operator)
    row = session.get(EvidenceRow, evidence_id)
    if row is None or row.scan_id != scan.id:
        raise HTTPException(404, "evidence not found")
    from scopelens.evidence.retention import expired

    if expired(row, settings.evidence_retention_days):
        raise HTTPException(410, "evidence retention period expired")
    import hashlib

    from scopelens.evidence.store import EvidenceStoreError

    try:
        content = LocalDiskEvidenceStore(
            settings.evidence_store_path,
            settings.evidence_encryption_key.get_secret_value()
            if settings.evidence_encryption_key
            else None,
        ).get(row.content_ref)
    except EvidenceStoreError:
        raise HTTPException(404, "evidence unavailable") from None
    if hashlib.sha256(content).hexdigest() != row.content_hash:
        raise HTTPException(409, "evidence integrity mismatch")
    return Response(
        content,
        media_type="application/octet-stream",
        headers={
            "content-disposition": f'attachment; filename="evidence-{evidence_id}.bin"',
            "x-content-type-options": "nosniff",
            "content-security-policy": "sandbox",
        },
    )
