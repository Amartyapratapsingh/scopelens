"""Creation responses must be usable before request-dependency teardown commits."""

import json
import uuid
from collections.abc import Awaitable, Callable

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from tests.integration.test_api import lab_scope_payload

from scopelens.persistence.models import (
    AssessmentConfigurationRow,
    AuditEventRow,
    OutboxEventRow,
    ScanRow,
    ScopeVersionRow,
    TaskRow,
)
from scopelens.persistence.session import get_engine

pytestmark = pytest.mark.db


def observe_creation_body(
    app: ASGIApp, observer: Callable[[str, dict], Awaitable[None]]
) -> ASGIApp:
    """Observe final response bytes while the route's dependency is still open.

    TestClient ordinarily waits for teardown, masking a response-before-commit race.
    An independent connection here sees precisely what an immediate caller can see.
    """

    async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
        response_status = None

        async def observed_send(message: Message) -> None:
            nonlocal response_status
            if message["type"] == "http.response.start":
                response_status = message["status"]
            if (
                scope["type"] == "http"
                and scope["method"] == "POST"
                and message["type"] == "http.response.body"
                and not message.get("more_body", False)
                and response_status in {201, 202}
            ):
                await observer(scope["path"], json.loads(message["body"]))
            await send(message)

        await app(scope, receive, observed_send)

    return wrapped


def test_scope_response_allows_immediate_scan_before_teardown(authed_client):
    observed = {}

    async def immediate_scan(path, body):
        assert path == "/api/scopes"
        with Session(get_engine()) as independent:
            observed["scope_visible"] = (
                independent.get(ScopeVersionRow, uuid.UUID(body["id"])) is not None
            )
            observed["audit_visible"] = independent.scalar(
                select(AuditEventRow.seq).where(
                    AuditEventRow.action == "scope.register",
                    AuditEventRow.subject_id == body["id"],
                )
            )
        # This request runs before the scope response finishes and before its yield
        # dependency exits. No delay and no dispatcher or worker is running on this DB.
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=authed_client.app),
            base_url="http://testserver",
            cookies=dict(authed_client.cookies),
        ) as followup:
            observed["scan"] = await followup.post(
                "/api/scans", json={"scope_version_id": body["id"]}
            )

    with TestClient(observe_creation_body(authed_client.app, immediate_scan)) as caller:
        caller.cookies.update(authed_client.cookies)
        created = caller.post("/api/scopes", json=lab_scope_payload())
    assert created.status_code == 201
    with Session(get_engine()) as independent:
        assert independent.get(ScopeVersionRow, uuid.UUID(created.json()["id"])) is not None
    assert observed["scan"].status_code == 202, observed["scan"].text
    assert observed["scope_visible"]
    assert observed["audit_visible"] is not None
    assert observed["scan"].json()["scope_version_id"] == created.json()["id"]


def test_configuration_and_scan_are_durable_at_their_response_boundary(authed_client):
    visible = []
    models_and_actions = {
        "/api/scopes": (ScopeVersionRow, "scope.register"),
        "/api/assessments/configurations": (
            AssessmentConfigurationRow,
            "assessment.configuration.create",
        ),
        "/api/scans": (ScanRow, "scan.create"),
    }

    async def check_committed(path, body):
        model, action = models_and_actions[path]
        with Session(get_engine()) as independent:
            assert independent.get(model, uuid.UUID(body["id"])) is not None
            assert (
                independent.scalar(
                    select(AuditEventRow.seq).where(
                        AuditEventRow.action == action,
                        AuditEventRow.subject_id == body["id"],
                    )
                )
                is not None
            )
            if path == "/api/scans":
                task = independent.scalar(
                    select(TaskRow).where(TaskRow.scan_id == uuid.UUID(body["id"]))
                )
                assert task is not None
                assert (
                    independent.scalar(
                        select(OutboxEventRow.id).where(
                            OutboxEventRow.payload["scan_id"].astext == body["id"],
                            OutboxEventRow.payload["task_id"].astext == str(task.id),
                        )
                    )
                    is not None
                )
        visible.append(path)

    with TestClient(observe_creation_body(authed_client.app, check_committed)) as caller:
        caller.cookies.update(authed_client.cookies)
        scope = caller.post(
            "/api/scopes", json=lab_scope_payload(allowed_check_profile="external-active-v2")
        )
        assert scope.status_code == 201
        configuration = caller.post(
            "/api/assessments/configurations", json={"scope_version_id": scope.json()["id"]}
        )
        assert configuration.status_code == 201
        scan = caller.post(
            "/api/scans",
            json={
                "scope_version_id": scope.json()["id"],
                "assessment_configuration_id": configuration.json()["id"],
            },
        )
        assert scan.status_code == 202
    assert visible == list(models_and_actions)


def test_scope_commit_failure_does_not_return_created_or_persist_rows(authed_client, monkeypatch):
    original_commit = Session.commit
    failed_commits = []

    def fail_scope_commit(session):
        if session.scalar(select(ScopeVersionRow.id)) is not None:
            failed_commits.append(True)
            raise RuntimeError("simulated scope commit failure")
        original_commit(session)

    with monkeypatch.context() as patched:
        patched.setattr(Session, "commit", fail_scope_commit)
        with TestClient(authed_client.app, raise_server_exceptions=False) as caller:
            caller.cookies.update(authed_client.cookies)
            created = caller.post("/api/scopes", json=lab_scope_payload())
        assert failed_commits == [True]
        assert created.status_code == 500

    with Session(get_engine()) as independent:
        assert independent.scalar(select(ScopeVersionRow.id)) is None
        assert (
            independent.scalar(
                select(AuditEventRow.seq).where(AuditEventRow.action == "scope.register")
            )
            is None
        )
