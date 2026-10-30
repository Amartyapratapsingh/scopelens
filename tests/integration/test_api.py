"""API integration tests: auth, scope registration, and the queued scan intent.

These run against a real PostgreSQL migrated by the real Alembic migration, so they
cover the persistence layer and the migration rather than a model-only approximation.
They skip with a clear reason when no database is reachable.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import yaml
from fastapi.testclient import TestClient
from tests.conftest import LAB_BAD_ADDRESS

from scopelens.config import Settings
from scopelens.domain.enums import AuthorityDomain, ScanStatus
from scopelens.persistence.session import session_scope
from scopelens.scope.dns import StaticResolver

pytestmark = pytest.mark.db


def lab_scope_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "authority_domain": "lab",
        "lab_service": "labs-bad",
        "authorization_expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
    }
    payload.update(overrides)
    return payload


# --- Authentication ----------------------------------------------------------------


class TestAuthentication:
    def test_login_succeeds_with_seeded_credentials(self, client: TestClient) -> None:
        response = client.post(
            "/api/auth/login",
            json={"username": "operator", "password": "test-operator-password"},
        )
        assert response.status_code == 200
        assert response.json()["username"] == "operator"
        assert "scopelens_session" in response.cookies

    def test_session_cookie_is_httponly_and_samesite(self, client: TestClient) -> None:
        response = client.post(
            "/api/auth/login",
            json={"username": "operator", "password": "test-operator-password"},
        )
        header = response.headers["set-cookie"].lower()
        assert "httponly" in header
        assert "samesite=lax" in header

    @pytest.mark.parametrize(
        ("username", "password"),
        [("operator", "wrong"), ("nobody", "test-operator-password"), ("operator", "")],
    )
    def test_bad_credentials_are_rejected_identically(
        self, client: TestClient, username: str, password: str
    ) -> None:
        """The same message for every failure, so login is not an enumeration oracle."""
        response = client.post("/api/auth/login", json={"username": username, "password": password})
        assert response.status_code in {401, 422}
        if response.status_code == 401:
            assert response.json()["detail"] == "invalid username or password"

    def test_unauthenticated_scope_access_is_refused(self, client: TestClient) -> None:
        assert client.get("/api/scopes").status_code == 401
        assert client.get("/api/scans").status_code == 401
        assert client.get("/api/lab-services").status_code == 401

    def test_no_signup_route_exists(self, client: TestClient) -> None:
        for path in ("/api/auth/signup", "/api/auth/register", "/api/operators"):
            assert client.post(path, json={}).status_code == 404, path

    def test_logout_clears_the_session(self, authed_client: TestClient) -> None:
        assert authed_client.post("/api/auth/logout").status_code == 204
        assert authed_client.get("/api/scopes").status_code == 401

    def test_a_forged_cookie_is_rejected(self, client: TestClient) -> None:
        client.cookies.set("scopelens_session", "forged.token.value")
        assert client.get("/api/scopes").status_code == 401

    def test_login_is_audited_including_failures(self, client: TestClient) -> None:
        from scopelens.persistence.repositories import list_audit_events

        client.post("/api/auth/login", json={"username": "operator", "password": "wrong"})
        client.post(
            "/api/auth/login",
            json={"username": "operator", "password": "test-operator-password"},
        )

        with session_scope() as session:
            outcomes = {
                event.outcome
                for event in list_audit_events(session)
                if event.action == "auth.login"
            }
        assert outcomes == {"denied", "success"}


# --- Scope registration -------------------------------------------------------------


class TestScopeRegistration:
    def test_lab_scope_binds_to_the_allowlist(self, authed_client: TestClient) -> None:
        response = authed_client.post(
            "/api/scopes", json=lab_scope_payload(scheme="https", lab_port=8443)
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["authority_domain"] == AuthorityDomain.LAB
        assert body["host"] == LAB_BAD_ADDRESS
        assert body["port"] == 8443
        assert body["lab_binding"]["service"] == "labs-bad"
        assert body["origin"] == f"https://{LAB_BAD_ADDRESS}:8443"
        assert body["expired"] is False
        assert body["content_hash"]

    def test_lab_scope_defaults_to_the_first_approved_address_and_port(
        self, authed_client: TestClient
    ) -> None:
        response = authed_client.post("/api/scopes", json=lab_scope_payload())
        assert response.status_code == 201, response.text
        assert response.json()["host"] == LAB_BAD_ADDRESS
        assert response.json()["port"] == 80

    @pytest.mark.parametrize(
        "overrides",
        [
            {"lab_service": "not-a-service"},
            {"lab_address": "10.0.0.99"},
            {"lab_port": 22},
            {"lab_port": 9999},
        ],
    )
    def test_lab_scope_cannot_escape_the_allowlist(
        self, authed_client: TestClient, overrides: dict
    ) -> None:
        response = authed_client.post("/api/scopes", json=lab_scope_payload(**overrides))
        assert response.status_code == 400, response.text

    def test_lab_scope_rejects_a_host_field(self, authed_client: TestClient) -> None:
        """Two competing port/host sources would let a request contradict its binding."""
        response = authed_client.post(
            "/api/scopes", json=lab_scope_payload(host="evil.example.com")
        )
        assert response.status_code == 422

    def test_a_lab_scope_cannot_reach_the_metadata_address(self, authed_client: TestClient) -> None:
        response = authed_client.post(
            "/api/scopes",
            json=lab_scope_payload(lab_service="labs-bad", lab_address="169.254.169.254"),
        )
        assert response.status_code == 400

    def test_missing_allowlist_denies_lab_registration(
        self, db_session, seeded_operator, settings: Settings, tmp_path
    ) -> None:
        """Fail closed: an absent allowlist must not permit lab addresses."""
        from scopelens.domain.scope import LabScopeCreate
        from scopelens.scope.service import ScopeRegistrationError, register_scope

        operator_id, username = seeded_operator
        absent = settings.model_copy(update={"lab_services_file": tmp_path / "absent.yaml"})

        with pytest.raises(ScopeRegistrationError, match="not in the deployment allowlist"):
            register_scope(
                db_session,
                operator_id=operator_id,
                actor=username,
                payload=LabScopeCreate(
                    lab_service="labs-bad",
                    authorization_expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
                settings=absent,
                resolver=StaticResolver({}),
            )

    def test_expired_authorization_is_refused(self, authed_client: TestClient) -> None:
        response = authed_client.post(
            "/api/scopes",
            json=lab_scope_payload(
                authorization_expires_at=(datetime.now(UTC) - timedelta(days=1)).isoformat()
            ),
        )
        assert response.status_code == 400
        assert "in the past" in response.json()["detail"]

    def test_naive_expiry_is_refused(self, authed_client: TestClient) -> None:
        response = authed_client.post(
            "/api/scopes",
            json=lab_scope_payload(authorization_expires_at="2027-01-01T00:00:00"),
        )
        assert response.status_code == 422

    def test_scope_listing_returns_only_this_operators_scopes(
        self, authed_client: TestClient, db_session
    ) -> None:
        authed_client.post("/api/scopes", json=lab_scope_payload())
        response = authed_client.get("/api/scopes")
        assert response.status_code == 200
        assert len(response.json()) == 1
        assert response.json()[0]["scan_count"] == 0

    def test_registration_is_audited(self, authed_client: TestClient, db_session) -> None:
        from scopelens.persistence.repositories import list_audit_events

        authed_client.post("/api/scopes", json=lab_scope_payload())
        with session_scope() as session:
            actions = [e.action for e in list_audit_events(session)]
        assert "scope.register" in actions


class TestProductionScopeRegistration:
    def test_private_destination_is_refused(
        self, client: TestClient, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_resolver(monkeypatch, {"internal.example.com": ["10.1.2.3"]})
        client.post(
            "/api/auth/login",
            json={"username": "operator", "password": "test-operator-password"},
        )
        response = client.post(
            "/api/scopes",
            json={
                "authority_domain": "production",
                "host": "internal.example.com",
                "authorization_expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
        )
        assert response.status_code == 400
        assert "private address" in response.json()["detail"]

    def test_metadata_destination_is_refused(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_resolver(monkeypatch, {"metadata.example.com": ["169.254.169.254"]})
        client.post(
            "/api/auth/login",
            json={"username": "operator", "password": "test-operator-password"},
        )
        response = client.post(
            "/api/scopes",
            json={
                "authority_domain": "production",
                "host": "metadata.example.com",
                "authorization_expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
        )
        assert response.status_code == 400
        assert "metadata" in response.json()["detail"]

    def test_public_destination_is_accepted(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _force_resolver(monkeypatch, {"owned.example.com": ["93.184.216.34"]})
        client.post(
            "/api/auth/login",
            json={"username": "operator", "password": "test-operator-password"},
        )
        response = client.post(
            "/api/scopes",
            json={
                "authority_domain": "production",
                "host": "owned.example.com",
                "authorization_expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["authority_domain"] == AuthorityDomain.PRODUCTION
        assert body["lab_binding"] is None
        assert body["origin"] == "https://owned.example.com"


def _force_resolver(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]) -> None:
    """Replace the production DNS resolver with a deterministic one."""
    monkeypatch.setattr(
        "scopelens.api.scopes.SystemResolver", lambda *a, **k: StaticResolver(mapping)
    )


# --- Scans --------------------------------------------------------------------------


class TestScanCreation:
    def _register(self, client: TestClient) -> str:
        response = client.post("/api/scopes", json=lab_scope_payload())
        assert response.status_code == 201, response.text
        return response.json()["id"]

    def test_creating_a_scan_stores_a_queued_intent(self, authed_client: TestClient) -> None:
        scope_id = self._register(authed_client)
        response = authed_client.post("/api/scans", json={"scope_version_id": scope_id})

        assert response.status_code == 202, response.text
        body = response.json()
        assert body["status"] == ScanStatus.QUEUED
        assert body["progress_percent"] == 0
        assert body["findings_count"] == 0
        assert body["started_at"] is None
        assert body["finished_at"] is None
        assert body["execution"]["execution"] == "enabled"
        assert body["execution"]["dispatch_implemented"] is True
        assert body["cancel_epoch"] == 0
        assert body["budget_spent"]["requests"] == 0

    def test_creating_a_scan_writes_task_and_outbox_in_one_transaction(
        self, authed_client: TestClient
    ) -> None:
        """Build Plan §5.2: Scan + initial Task + outbox event, together or not at all."""
        from scopelens.persistence.models import OutboxEventRow, TaskRow
        from scopelens.persistence.session import session_scope

        scope_id = self._register(authed_client)
        scan_id = authed_client.post("/api/scans", json={"scope_version_id": scope_id}).json()["id"]

        with session_scope() as session:
            tasks = session.query(TaskRow).filter(TaskRow.scan_id == uuid.UUID(scan_id)).all()
            events = (
                session.query(OutboxEventRow)
                .filter(OutboxEventRow.payload["scan_id"].astext == scan_id)
                .all()
            )

        assert len(tasks) == 1
        assert tasks[0].state == "planned"
        assert tasks[0].logical_id == "fetch-origin"
        assert len(events) == 1
        assert events[0].topic == "scan.task.dispatch"
        assert events[0].dispatched_at is None

    def test_the_intent_persists(self, authed_client: TestClient) -> None:
        scope_id = self._register(authed_client)
        scan_id = authed_client.post("/api/scans", json={"scope_version_id": scope_id}).json()["id"]

        fetched = authed_client.get(f"/api/scans/{scan_id}")
        assert fetched.status_code == 200
        assert fetched.json()["status"] == ScanStatus.QUEUED

    def test_the_scan_carries_its_task_in_the_detail_view(self, authed_client: TestClient) -> None:
        scope_id = self._register(authed_client)
        scan_id = authed_client.post("/api/scans", json={"scope_version_id": scope_id}).json()["id"]

        detail = authed_client.get(f"/api/scans/{scan_id}").json()
        assert len(detail["tasks"]) == 1
        assert detail["tasks"][0]["state"] in {"planned", "admitted", "running"}

    def test_scan_creation_is_refused_while_execution_is_disabled(
        self, authed_client: TestClient, settings
    ) -> None:
        """Refusing beats queueing work nothing will ever dispatch."""
        from fastapi.testclient import TestClient as FreshClient

        from scopelens.main import create_app

        disabled = settings.model_copy(update={"scanner_execution_enabled": False})
        with FreshClient(create_app(disabled)) as fresh:
            fresh.post(
                "/api/auth/login",
                json={"username": "operator", "password": "test-operator-password"},
            )
            scope = fresh.post("/api/scopes", json=lab_scope_payload(scheme="https", lab_port=8443))
            assert scope.status_code == 201, scope.text
            refused = fresh.post("/api/scans", json={"scope_version_id": scope.json()["id"]})

        assert refused.status_code == 503
        assert "execution is disabled" in refused.json()["detail"]

    def test_target_comes_from_the_scope_not_the_request(self, authed_client: TestClient) -> None:
        """A scan request cannot name an origin the operator never authorized."""
        response = authed_client.post(
            "/api/scans",
            json={"scope_version_id": str(uuid.uuid4()), "target_origin": "https://evil.test"},
        )
        assert response.status_code == 422

    def test_unknown_scope_is_a_404(self, authed_client: TestClient) -> None:
        response = authed_client.post("/api/scans", json={"scope_version_id": str(uuid.uuid4())})
        assert response.status_code == 404

    def test_non_uuid_scope_id_is_refused(self, authed_client: TestClient) -> None:
        response = authed_client.post("/api/scans", json={"scope_version_id": "not-a-uuid"})
        assert response.status_code == 422

    def test_expired_scope_cannot_be_scanned(
        self, authed_client: TestClient, db_session, seeded_operator
    ) -> None:
        """Admission re-checks authorization, so an expired scope is refused at scan time.

        The scope is created directly through the repository because the registration
        service correctly refuses to create an already-expired scope — this test is about
        the *admission* check, not the registration check.
        """
        from scopelens.domain.lab import LabBinding
        from scopelens.domain.scope import LabScopeCreate
        from scopelens.persistence.models import ScanRow
        from scopelens.persistence.repositories import create_scope_version

        operator_id, _ = seeded_operator
        row = create_scope_version(
            db_session,
            operator_id=operator_id,
            payload=LabScopeCreate(
                lab_service="labs-bad",
                authorization_expires_at=datetime.now(UTC) - timedelta(days=1),
            ),
            scheme="http",
            host=LAB_BAD_ADDRESS,
            port=80,
            lab_binding=LabBinding(
                service="labs-bad",
                address=LAB_BAD_ADDRESS,
                port=80,
                environment="docker-compose-labs",
            ),
        )
        db_session.commit()

        response = authed_client.post("/api/scans", json={"scope_version_id": str(row.id)})

        assert response.status_code == 400
        assert "expired" in response.json()["detail"]
        with session_scope() as session:
            assert session.query(ScanRow).count() == 0

    def test_creating_a_scan_is_audited(self, authed_client: TestClient, db_session) -> None:
        from scopelens.persistence.repositories import list_audit_events

        scope_id = self._register(authed_client)
        authed_client.post("/api/scans", json={"scope_version_id": scope_id})

        with session_scope() as session:
            events = [e for e in list_audit_events(session) if e.action == "scan.create"]
        assert len(events) == 1
        assert events[0].outcome == "queued"
        assert events[0].detail["dispatch"] == "outbox"
        assert events[0].detail["logical_id"] == "fetch-origin"


class TestScopeImmutability:
    def test_a_scope_version_cannot_be_updated(self, authed_client: TestClient, db_session) -> None:
        """The record a scan relied on must not be rewritable."""
        from scopelens.persistence.models import ScopeVersionRow

        scope_id = authed_client.post("/api/scopes", json=lab_scope_payload()).json()["id"]
        row = db_session.get(ScopeVersionRow, uuid.UUID(scope_id))
        assert row is not None

        row.host = "10.0.0.1"
        with pytest.raises(ValueError, match="immutable"):
            db_session.commit()
        db_session.rollback()

    def test_registering_the_same_origin_creates_a_new_version(
        self, authed_client: TestClient
    ) -> None:
        # The same payload object is reused deliberately: the authorization expiry is
        # part of the hashed content, so a second payload built with a fresh
        # `datetime.now()` would legitimately produce a different hash.
        payload = lab_scope_payload()
        first = authed_client.post("/api/scopes", json=payload).json()
        second = authed_client.post("/api/scopes", json=payload).json()
        assert first["id"] != second["id"]
        assert second["version"] == first["version"] + 1
        assert second["origin"] == first["origin"]
        assert first["content_hash"] == second["content_hash"]

    def test_different_content_yields_a_different_hash(self, authed_client: TestClient) -> None:
        payload = lab_scope_payload()
        first = authed_client.post("/api/scopes", json=payload).json()
        second = authed_client.post(
            "/api/scopes",
            json={**payload, "allowed_path_prefixes": ["/app", "/api"]},
        ).json()
        assert first["content_hash"] != second["content_hash"]


# --- System -------------------------------------------------------------------------


class TestSystemEndpoints:
    def test_healthz(self, client: TestClient) -> None:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_readyz_reports_the_schema_revision(self, client: TestClient) -> None:
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json()["schema_revision"] == "0009"

    def test_execution_endpoint_states_the_milestone(self, client: TestClient) -> None:
        body = client.get("/api/system/execution").json()
        assert body["execution"] == "enabled"
        assert body["execution_enabled"] is True
        assert body["dispatch_implemented"] is True
        assert body["responsible_milestone"] == "M1"


# --- Lab fixture pairing -------------------------------------------------------------


class TestShippedLabAllowlistMatchesFixtures:
    def test_compose_addresses_match_the_allowlist(self) -> None:
        """The allowlist and the compose file must not drift apart."""
        from scopelens.config import REPO_ROOT
        from scopelens.domain.lab import load_lab_services

        allowlist = load_lab_services(REPO_ROOT / "deploy" / "lab_services.yaml")
        compose = yaml.safe_load(
            (REPO_ROOT / "labs" / "docker-compose.yml").read_text(encoding="utf-8")
        )
        services = dict(compose["services"])
        for filename in [
            "academic-workflows.compose.yml",
            "academic-faults.compose.yml",
            "session-expiry.compose.yml",
            "holdout.compose.yml",
        ]:
            extra = yaml.safe_load((REPO_ROOT / "labs" / filename).read_text(encoding="utf-8"))
            assert not set(services) & set(extra["services"])
            services.update(extra["services"])

        for service in allowlist.services:
            definition = services[service.id]
            network = "labs" if service.id.startswith("labs-holdout-") else "labs_net"
            compose_address = definition["networks"][network]["ipv4_address"]
            assert compose_address in service.addresses, service.id
