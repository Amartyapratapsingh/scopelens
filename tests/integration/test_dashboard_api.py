import asyncio
import json
import uuid

import pytest
from sqlalchemy.orm import sessionmaker

from scopelens.api.dashboard import _event_stream
from scopelens.checks.retest import reconcile_retests
from scopelens.domain.check import ControlOutcome, ProofResult
from scopelens.domain.enums import Category, EvidenceStatus
from scopelens.domain.enums import ControlOutcome as Outcome
from scopelens.persistence.models import AuditEventRow, CheckOutcomeRow, FindingRow, ScanRow
from scopelens.writer.report import build_report, render_html

pytestmark = pytest.mark.db


def test_terminal_scan_cannot_report_an_active_browser(authed_client, queued_scan, db_session):
    from datetime import UTC, datetime, timedelta

    from scopelens.persistence.models import BrowserSessionRow

    scan, _ = queued_scan
    scan.status = "completed_partial"
    db_session.add(
        BrowserSessionRow(
            scan_id=scan.id,
            owner="worker",
            context_id=str(uuid.uuid4()),
            scope_revision="revision",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            sequence=1,
            status="active",
        )
    )
    db_session.commit()
    view = authed_client.get(f"/api/scans/{scan.id}/browser").json()
    assert view["status"] == "incomplete" and view["gaps"]


def test_browser_gap_preserves_nested_pending_request_metadata(
    authed_client, queued_scan, db_session
):
    scan, _ = queued_scan
    gap = {
        "reason": "navigation deadline",
        "pending_requests": [{"url": "https://fixture.example/asset.js", "pending_seconds": 29.7}],
        "pending_request_count": 42,
        "pending_metadata_limited": True,
    }
    scan.assessment_plan = {
        "browser": {"status": "incomplete", "actions": 4, "states": 2, "gaps": [gap]}
    }
    db_session.commit()
    response = authed_client.get(f"/api/scans/{scan.id}/browser")
    assert response.status_code == 200
    assert response.json()["gaps"] == [gap]
    assert response.json()["status"] == "incomplete"


def test_omitting_configuration_tool_gap_cannot_raise_same_scan_coverage_or_scores(
    authed_client, queued_scan, db_session, settings
):
    from copy import deepcopy

    from scopelens.checks.analyze import analyze
    from scopelens.domain.collection import CollectedResponse
    from scopelens.domain.surface import AttackSurfaceMap

    scan, _ = queued_scan
    scan.profile = "external-configuration"
    diagnostic = "No reviewed endpoints enabled for this profile and origin"
    artifacts = [
        {
            "kind": "surface",
            "data": AttackSurfaceMap(origin=scan.target_origin).model_dump(mode="json"),
        },
        {
            "kind": "response",
            "data": CollectedResponse(
                url=scan.target_origin + "/",
                route="/",
                status=200,
                headers={"content-type": "text/html"},
                content_type="text/html",
                body_excerpt="<html><body>Owned fixed fixture</body></html>",
                body_bytes=50,
                via_proxy=True,
            ).model_dump(mode="json"),
        },
        {
            "kind": "scanner_result",
            "data": {
                "tool": "conditional-config",
                "version": "m3.1",
                "state": "not_tested",
                "errors": [diagnostic],
            },
        },
    ]
    assert (
        analyze(
            settings=settings,
            session=db_session,
            scan=scan,
            artifacts=artifacts,
            evidence_refs={"crawl": "fixed-capture"},
        )
        is not None
    )
    db_session.flush()
    before = build_report(session=db_session, scan=scan)
    assert scan.assessment_plan["scanner_results"][0]["errors"] == [diagnostic]
    assert before["score"]["coverage_percent"] > 0
    withheld = {c["category"] for c in before["score"]["categories"] if c["score"] is None}
    assert withheld and before["score"]["score"] is None

    cleaned = deepcopy(artifacts)
    cleaned[-1]["data"]["errors"] = []
    assert (
        analyze(
            settings=settings,
            session=db_session,
            scan=scan,
            artifacts=cleaned,
            evidence_refs={"crawl": "fixed-capture"},
        )
        is not None
    )
    db_session.commit()
    after = build_report(session=db_session, scan=scan)
    assert after["score"] == before["score"]
    assert after["check_outcomes"] == before["check_outcomes"]
    assert all(
        c["score"] is None for c in after["score"]["categories"] if c["category"] in withheld
    )
    omitted = after["out_of_profile_controls"]
    assert len(omitted) == 5
    assert all(row["state"] == "not_in_profile" for row in omitted)
    assert not {row["check_id"] for row in omitted}.intersection(
        row["check_id"] for row in after["check_outcomes"]
    )
    tool = authed_client.get(f"/api/scans/{scan.id}/scanners").json()[0]
    assert tool["state"] == "not_tested" and tool["errors"] == []
    assert tool["not_in_profile_controls"] == omitted
    assert "Not in profile" in render_html(after)


def add_finding(session, scan):
    row = FindingRow(
        scan_id=scan.id,
        check_id="SL-C04-CSP-01",
        canonical_control="browser.csp",
        root_cause="csp",
        dedup_key="csp|browser.csp",
        category="C04",
        title="Missing policy",
        severity="low",
        evidence_status="confirmed",
        confidence="high",
        confidence_reasons=["Observed"],
        locations=[
            {
                "route": "/",
                "header": "content-security-policy",
                "detail": "<script>window.marker=1</script>",
            }
        ],
        evidence_refs=["captured"],
        detail="authorization: Bearer synthetic-secret-value",
        status="open",
    )
    session.add(row)
    session.commit()
    return row


def test_dashboard_routes_exports_filters_and_redaction(authed_client, queued_scan, db_session):
    scan, _ = queued_scan
    row = add_finding(db_session, scan)
    for suffix in ("summary", "findings", "categories", "hosts", "export.json", "export.html"):
        r = authed_client.get(f"/api/scans/{scan.id}/{suffix}")
        assert r.status_code == 200, (suffix, r.text)
        assert "synthetic-secret-value" not in r.text
    assert len(authed_client.get(f"/api/scans/{scan.id}/categories").json()) == 12
    assert len(authed_client.get(f"/api/scans/{scan.id}/findings?severity=low").json()) == 1
    assert authed_client.get(f"/api/scans/{scan.id}/findings?severity=high").json() == []
    assert authed_client.get(f"/api/findings/{row.id}").status_code == 200
    html = authed_client.get(f"/api/scans/{scan.id}/export.html").text
    assert "<script>" not in html and "&lt;script&gt;" in html
    assert (
        "attachment"
        in authed_client.get(f"/api/scans/{scan.id}/export.json").headers["content-disposition"]
    )


def test_empty_report_and_inventory_markup_escape(queued_scan, db_session):
    scan, _ = queued_scan
    report = build_report(session=db_session, scan=scan)
    report["host_inventory"] = [
        {"host": "example.test", "role": "inventory_only", "evidence": "<img src=x onerror=bad()>"}
    ]
    html = render_html(report)
    assert "No issues found in the checks that completed" in html
    assert "<img src=x" not in html
    assert "Coverage" in html


def test_auth_and_owner_boundaries(client, authed_client, queued_scan, db_session):
    scan, _ = queued_scan
    other = uuid.uuid4()
    assert authed_client.get(f"/api/scans/{other}/summary").status_code == 404
    client.cookies.clear()
    assert client.get(f"/api/scans/{scan.id}/summary").status_code == 401


@pytest.mark.parametrize(
    "result_status,scan_status,expected",
    [
        (Outcome.PASS, "completed", "fixed"),
        (Outcome.BLOCKED, "completed", "incomplete"),
        (Outcome.PASS, "failed", "incomplete"),
        (Outcome.PASS, "cancelled", "incomplete"),
    ],
)
def test_retest_updates_original_only_after_relevant_fresh_proof(
    authed_client, queued_scan, db_session, result_status, scan_status, expected
):
    original, _ = queued_scan
    finding = add_finding(db_session, original)
    response = authed_client.post(f"/api/findings/{finding.id}/retest")
    assert response.status_code == 202
    assert authed_client.post(f"/api/findings/{finding.id}/retest").status_code == 409
    new_id = uuid.UUID(response.json()["scan_id"])
    scan = db_session.get(ScanRow, new_id)
    assert scan.id != original.id
    outcome = ControlOutcome(
        check_id=finding.check_id,
        canonical_control="browser.csp",
        category=Category.C04_BROWSER_CROSS_ORIGIN,
        status=result_status,
        required_instances=("/",),
        completed_instances=("/",) if result_status == Outcome.PASS else (),
        proof=ProofResult(
            satisfied=False, status=EvidenceStatus.CONFIRMED, evidence_refs=("fresh",)
        ),
    )
    db_session.add(
        CheckOutcomeRow(
            scan_id=scan.id,
            check_id=finding.check_id,
            canonical_control="browser.csp",
            category="C04",
            status=result_status.value,
            summary="fresh result",
            payload=outcome.model_dump(mode="json"),
        )
    )
    scan.status = scan_status
    db_session.flush()
    reconcile_retests(db_session, scan)
    reconcile_retests(db_session, scan)
    db_session.commit()
    db_session.refresh(finding)
    assert finding.retest_state == expected
    assert finding.status == ("resolved" if expected == "fixed" else "open")
    assert (
        db_session.query(AuditEventRow)
        .filter_by(action="retest.complete", subject_id=str(scan.id))
        .count()
        == 1
    )


def test_sse_task_events_resume_and_strip_unknown_fields(queued_scan, db_session, engine):
    scan, _ = queued_scan
    rows = []
    for action in ("task.admit", "broker.admit", "task.settle"):
        row = AuditEventRow(
            actor="test",
            action=action,
            subject_type="task",
            subject_id=str(uuid.uuid4()),
            outcome="allowed",
            detail={"scan_id": str(scan.id), "method": "GET", "path": "/", "stdout": "secret text"},
        )
        db_session.add(row)
        rows.append(row)
    db_session.commit()

    class Request:
        async def is_disconnected(self):
            return False

    async def read():
        stream = _event_stream(Request(), sessionmaker(engine), scan.id, rows[0].seq)
        frames = [await anext(stream), await anext(stream)]
        await stream.aclose()
        return frames

    frames = asyncio.run(read())
    assert "broker.admit" in frames[0] and "task.settle" in frames[1]
    assert all("stdout" not in f and "secret text" not in f for f in frames)
    ids = [int(f.splitlines()[0].split(": ")[1]) for f in frames]
    assert ids == sorted(ids) and ids[0] > rows[0].seq
    assert json.loads(frames[0].split("data: ")[1])["scan_id"] == str(scan.id)


def test_scan_event_sequence_follows_commit_order(queued_scan, db_session):
    import threading

    from scopelens.persistence.repositories import record_audit

    scan, _ = queued_scan
    factory = sessionmaker(bind=db_session.get_bind(), expire_on_commit=False)
    ready, finished = threading.Event(), threading.Event()
    seqs = []
    with factory() as first:
        one = record_audit(
            first,
            actor="test",
            action="scan.progress",
            subject_type="scan",
            subject_id=str(scan.id),
            outcome="one",
        )

        def insert_second():
            with factory() as second:
                ready.set()
                row = record_audit(
                    second,
                    actor="test",
                    action="task.progress",
                    subject_type="task",
                    subject_id="task",
                    outcome="two",
                    detail={"scan_id": str(scan.id)},
                )
                second.commit()
                seqs.append(row.seq)
                finished.set()

        worker = threading.Thread(target=insert_second)
        worker.start()
        assert ready.wait(2)
        assert not finished.wait(0.1)
        first.commit()
        assert finished.wait(5)
        worker.join()
        assert seqs[0] > one.seq


def test_retest_recurrence_reopens_resolved_finding(authed_client, queued_scan, db_session):
    original, _ = queued_scan
    finding = add_finding(db_session, original)
    finding.status = "resolved"
    db_session.commit()
    new_id = uuid.UUID(authed_client.post(f"/api/findings/{finding.id}/retest").json()["scan_id"])
    new_scan = db_session.get(ScanRow, new_id)
    add_finding(db_session, new_scan)
    new_scan.status = "completed"
    reconcile_retests(db_session, new_scan)
    db_session.commit()
    db_session.refresh(finding)
    assert finding.retest_state == "still_present"
    assert finding.status == "open"


def test_existing_other_owner_resources_are_hidden(authed_client, queued_scan, db_session):
    from scopelens.persistence.models import OperatorRow

    scan, _ = queued_scan
    finding = add_finding(db_session, scan)
    other = OperatorRow(username="another-operator", password_hash="unusable-test-hash")
    db_session.add(other)
    db_session.flush()
    scan.operator_id = other.id
    db_session.commit()
    for suffix in [
        "summary",
        "findings",
        "categories",
        "hosts",
        "export.json",
        "export.html",
        "events",
    ]:
        assert authed_client.get(f"/api/scans/{scan.id}/{suffix}").status_code == 404
    assert authed_client.get(f"/api/findings/{finding.id}").status_code == 404
    assert authed_client.post(f"/api/findings/{finding.id}/retest").status_code == 404


def test_sse_header_cursor_and_typed_contract(authed_client, queued_scan, monkeypatch):
    scan, _ = queued_scan
    observed = []

    async def stream(request, factory, scan_id, cursor):
        observed.append(cursor)
        yield 'event: stream.limit\ndata: {"reconnect":true}\n\n'

    monkeypatch.setattr("scopelens.api.dashboard._event_stream", stream)
    response = authed_client.get(
        f"/api/scans/{scan.id}/events?cursor=5", headers={"Last-Event-ID": "9"}
    )
    assert response.status_code == 200 and observed == [9]
    assert response.headers["cache-control"] == "no-store"
    assert (
        authed_client.get(
            f"/api/scans/{scan.id}/events", headers={"Last-Event-ID": "-1"}
        ).status_code
        == 400
    )
    spec = authed_client.get("/openapi.json").json()
    endpoint = spec["paths"]["/api/scans/{scan_id}/events"]["get"]
    assert "x-sse-event-schema" in endpoint


def test_m3_views_and_evidence_download_are_owned_and_hashed(
    authed_client, queued_scan, db_session, settings
):
    from scopelens.domain.evidence import EvidenceOrigin
    from scopelens.evidence.intake import record_json_evidence
    from scopelens.evidence.store import LocalDiskEvidenceStore

    scan, task = queued_scan
    assert authed_client.get(f"/api/scans/{scan.id}/browser").json()["status"] == "not_tested"
    assert authed_client.get(f"/api/scans/{scan.id}/scanners").json() == []
    store = LocalDiskEvidenceStore(settings.evidence_store_path)
    record = record_json_evidence(
        db_session,
        settings=settings,
        store=store,
        scan=scan,
        origin=EvidenceOrigin.SUPERVISOR,
        producer="reviewed_browser_capture",
        tool_version="sha256:" + "a" * 64,
        payload={"authorization": "Bearer synthetic-secret-value", "kind": "browser_state"},
        task_id=task.id,
        run_id="browser-test",
        summary="test capture",
    )
    db_session.commit()
    url = f"/api/scans/{scan.id}/evidence/{record.id}/download"
    response = authed_client.get(url)
    assert response.status_code == 200
    assert b"synthetic-secret-value" not in response.content
    assert response.headers["content-security-policy"] == "sandbox"
    assert (
        authed_client.get(f"/api/scans/{uuid.uuid4()}/evidence/{record.id}/download").status_code
        == 404
    )
    store.put(record.content_ref, b"tampered")
    assert authed_client.get(url).status_code == 409


def test_summary_exposes_discovery_limit_without_full_export(
    authed_client, queued_scan, monkeypatch
):
    from scopelens.api import dashboard

    original = dashboard._report

    def with_surface(session, scan):
        report = original(session, scan)
        report["attack_surface"] = {
            "stats": {"pages_fetched": 110, "stopped_by": "crawl time budget reached (120s)"}
        }
        return report

    monkeypatch.setattr(dashboard, "_report", with_surface)
    scan, _ = queued_scan
    response = authed_client.get(f"/api/scans/{scan.id}/summary")
    assert response.status_code == 200
    assert response.json()["discovery"] == {
        "pages_fetched": 110,
        "stopped_by": "crawl time budget reached (120s)",
    }


def test_host_priority_plan_is_read_only_owner_filtered_and_typed(
    authed_client, queued_scan, db_session, settings, monkeypatch
):
    from datetime import UTC, datetime, timedelta
    from urllib.parse import urlsplit

    from scopelens.api import dashboard
    from scopelens.persistence.models import OperatorRow

    scan, _ = queued_scan
    scan.status = "completed_partial"
    scan.finished_at = datetime.now(UTC)
    host = urlsplit(scan.target_origin).hostname
    settings.discovery_owned_domains = (host,)
    other = OperatorRow(username="other-priority-owner", password_hash="unused")
    db_session.add(other)
    db_session.flush()
    foreign = ScanRow(
        operator_id=other.id,
        scope_version_id=scan.scope_version_id,
        target_origin=scan.target_origin,
        profile=scan.profile,
        score_version=scan.score_version,
        status="completed",
        finished_at=datetime.now(UTC),
        created_at=datetime.now(UTC) + timedelta(seconds=1),
    )
    db_session.add(foreign)
    db_session.commit()
    seen = []

    def saved_report(session, row):
        seen.append(row.operator_id)
        return {
            "scan": {"id": str(row.id), "target_origin": row.target_origin, "status": row.status},
            "host_inventory": [{"host": host, "role": "primary"}],
            "attack_surface": {"endpoints": [{"route": "/"}]},
        }

    monkeypatch.setattr(dashboard, "_report", saved_report)
    before = db_session.query(ScanRow).count()
    result = authed_client.get(f"/api/scans/{scan.id}/host-priorities")
    assert result.status_code == 200, result.text
    plan = result.json()
    assert plan["hosts"][0]["latest_scan_id"] == str(scan.id)
    assert plan["hosts"][0]["owned_domain_match"] is True
    assert set(seen) == {scan.operator_id}
    assert db_session.query(ScanRow).count() == before
    assert authed_client.get(f"/api/scans/{foreign.id}/host-priorities").status_code == 404
    assert (
        "/api/scans/{scan_id}/host-priorities" in authed_client.get("/openapi.json").json()["paths"]
    )


@pytest.mark.parametrize("evidence_status", ["confirmed", "potential"])
def test_plain_copy_supersedes_cached_claim_without_changing_evidence(
    authed_client, queued_scan, db_session, evidence_status
):
    scan, _ = queued_scan
    row = add_finding(db_session, scan)
    row.evidence_status = evidence_status
    scan.assessment_plan = {
        **(scan.assessment_plan or {}),
        "report_prose": {
            str(row.id): {
                "what": "We bypassed every login.",
                "why": "Someone can change all student marks.",
                "fix": "Replace the whole server.",
            }
        },
    }
    db_session.commit()
    response = authed_client.get(f"/api/scans/{scan.id}/findings").json()[0]
    assert response["severity"] == "low"
    assert response["evidence_status"] == evidence_status
    assert response["evidence_refs"] == ["captured"]
    assert "bypassed every login" not in response["what"]
    assert "student marks" not in response["why"]
    assert "not proof" in response["why"]
    if evidence_status == "potential":
        assert response["title"].startswith("Possible issue:")
        assert "still needs verification" in response["what"]
    html = authed_client.get(f"/api/scans/{scan.id}/export.html").text
    assert "What someone could do" in html
    assert "bypassed every login" not in html
