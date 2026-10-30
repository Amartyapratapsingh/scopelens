"""Shared test fixtures.

Database-backed tests use a separate ``scopelens_test`` database, created on demand
and migrated with the real Alembic migration — so the tests exercise the migration
rather than a ``create_all`` shortcut that could drift from it.

When PostgreSQL is unreachable the DB-backed tests **skip with a clear reason**. They
never silently pass: a skipped boundary test that looked green would be exactly the
kind of false confidence Build Plan §0.3 forbids.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session

from scopelens.config import REPO_ROOT, Settings, get_settings
from scopelens.domain.enums import AuthorityDomain
from scopelens.domain.lab import LabBinding, LabService, LabServiceAllowlist
from scopelens.persistence import session as persistence_session
from scopelens.persistence.base import Base
from scopelens.scope.dns import StaticResolver

TEST_DB_NAME = "scopelens_test"

DB_SKIP_REASON = (
    "PostgreSQL is not reachable; run `make db-up` (or `make test-all`) to include "
    "database-backed tests"
)


def _base_url() -> str:
    """The database the tests should connect to.

    Reads ``.env`` through the application's own Settings so the suite uses the same
    credentials ``make run`` does. Reading ``os.environ`` alone silently falls back to a
    default password, which turns every database-backed test into a skip while the
    suite still reports green.
    """
    if override := os.environ.get("SCOPELENS_DATABASE_URL"):
        return override
    return Settings(_env_file=REPO_ROOT / ".env").database_url


def _admin_url() -> str:
    return _base_url().rsplit("/", 1)[0] + "/postgres"


def _test_url() -> str:
    override = os.environ.get("SCOPELENS_TEST_DATABASE_URL")
    if override:
        return override
    return _base_url().rsplit("/", 1)[0] + f"/{TEST_DB_NAME}"


def _try_engine(url: str, *, isolation_level: str | None = None) -> Engine | None:
    try:
        engine = create_engine(
            url,
            pool_pre_ping=True,
            isolation_level=isolation_level,
            connect_args={"connect_timeout": 3},
        )
        with engine.connect():
            pass
    except Exception:  # noqa: BLE001 - any failure means "no database here"
        return None
    return engine


@pytest.fixture(scope="session")
def database_url() -> str:
    """Resolve and prepare the test database, or skip.

    Only resolved when a test actually needs it. Nothing here is autouse, so the pure
    unit tests run with no database present at all.
    """
    admin = _try_engine(_admin_url(), isolation_level="AUTOCOMMIT")
    if admin is None:
        pytest.skip(DB_SKIP_REASON)

    with admin.connect() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": TEST_DB_NAME}
        ).scalar()
        if not exists:
            conn.execute(text(f'CREATE DATABASE "{TEST_DB_NAME}"'))
    admin.dispose()

    url = _test_url()
    engine = _try_engine(url)
    if engine is None:
        pytest.skip(DB_SKIP_REASON)

    _run_migrations(url)
    engine.dispose()
    return url


def _run_migrations(url: str) -> None:
    from alembic import command
    from alembic.config import Config

    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option(
        "script_location", str(REPO_ROOT / "backend" / "scopelens" / "persistence" / "migrations")
    )
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")


@pytest.fixture(scope="session")
def engine(database_url: str) -> Iterator[Engine]:
    eng = create_engine(database_url, pool_pre_ping=True, future=True)
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def _clean_tables(request: pytest.FixtureRequest) -> Iterator[None]:
    """Truncate every table before each database-backed test.

    Keyed off the ``db`` marker rather than being unconditionally autouse: an autouse
    fixture that requests ``engine`` would make *every* test depend on PostgreSQL and
    turn the whole suite into skips when it is unavailable.
    """
    if request.node.get_closest_marker("db") is None:
        yield
        return

    engine: Engine = request.getfixturevalue("engine")
    with engine.begin() as conn:
        # Every table is named explicitly rather than relying on CASCADE.
        #
        # `outbox_events` deliberately has no foreign key to `scans` — its payload is a
        # generic reference — so `TRUNCATE scans ... CASCADE` does not reach it. Leaving it
        # out silently leaked rows between tests, and a leaked outbox row makes a dispatch
        # test examine stale work instead of its own.
        conn.execute(
            text(
                "TRUNCATE outbox_events, evidence, tasks, coordinator_leases, scans, "
                "scope_versions, audit_events, operators RESTART IDENTITY CASCADE"
            )
        )
    yield


@pytest.fixture
def db_session(engine: Engine) -> Iterator[Session]:
    with Session(engine, expire_on_commit=False, future=True) as session:
        yield session
        session.rollback()


@pytest.fixture
def settings(database_url: str, tmp_path: Path) -> Iterator[Settings]:
    """Settings pointed at the test database, with a deterministic session secret."""
    previous = {k: os.environ.get(k) for k in _MANAGED_ENV}

    ca_file = tmp_path / "mitmproxy-ca-cert.pem"
    ca_file.write_text(FAKE_CA_PEM, encoding="utf-8")

    os.environ.update(
        {
            "SCOPELENS_PROXY_CA_PATH": str(ca_file),
            "SCOPELENS_DATABASE_URL": database_url,
            "SCOPELENS_SESSION_SECRET": "test-session-secret-not-used-outside-tests",
            "SCOPELENS_OPERATOR_USERNAME": "operator",
            "SCOPELENS_OPERATOR_PASSWORD": "test-operator-password",
            # Execution is enabled in tests: scan creation now refuses when it is off,
            # and almost every M1 assertion depends on a scan existing.
            "SCOPELENS_SCANNER_EXECUTION_ENABLED": "true",
            # Optional callback authority is enabled explicitly in its own tests,
            # never inherited from an operator's local deployed environment.
            "SCOPELENS_CALLBACK_COLLECTOR_ORIGINS": "[]",
            "SCOPELENS_CALLBACK_SIGNING_KEY": "",
            "SCOPELENS_PASSIVE_DISCOVERY_ENABLED": "false",
        }
    )
    get_settings.cache_clear()
    persistence_session.reset_engine_cache()
    resolved = get_settings()
    yield resolved
    get_settings.cache_clear()
    persistence_session.reset_engine_cache()
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


#: A placeholder CA. The coordinator refuses to start a worker without one, because a
#: worker that cannot verify the proxy fails with a confusing TLS error instead of a clear
#: message — so the tests supply one rather than skipping that path.
FAKE_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAJ8testfixtureplaceholderCA0000000000000000000000MA0GCSqGSIb3DQEB
CwUAMBExDzANBgNVBAMMBnRlc3RjYTAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEw
MDAwMDBaMBExDzANBgNVBAMMBnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgC
QQDB0pLACEHOLDERNOTAKEYplaceholderplaceholderplaceholderplaceholderplaceholder
-----END CERTIFICATE-----
"""

_MANAGED_ENV = (
    "SCOPELENS_DATABASE_URL",
    "SCOPELENS_PROXY_CA_PATH",
    "SCOPELENS_SESSION_SECRET",
    "SCOPELENS_OPERATOR_USERNAME",
    "SCOPELENS_OPERATOR_PASSWORD",
    "SCOPELENS_SCANNER_EXECUTION_ENABLED",
    "SCOPELENS_CALLBACK_COLLECTOR_ORIGINS",
    "SCOPELENS_CALLBACK_SIGNING_KEY",
    "SCOPELENS_PASSIVE_DISCOVERY_ENABLED",
)


@pytest.fixture
def seeded_operator(db_session: Session) -> tuple[uuid.UUID, str]:
    """Create the operator account. Returns (id, username)."""
    from scopelens.persistence.repositories import upsert_operator
    from scopelens.security.passwords import hash_password

    row, _ = upsert_operator(
        db_session,
        username="operator",
        password_hash=hash_password("test-operator-password", rounds=4),
    )
    db_session.commit()
    return row.id, row.username


@pytest.fixture
def client(settings: Settings, seeded_operator: tuple[uuid.UUID, str]) -> Iterator[TestClient]:
    from scopelens.main import create_app

    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def authed_client(client: TestClient) -> TestClient:
    response = client.post(
        "/api/auth/login",
        json={"username": "operator", "password": "test-operator-password"},
    )
    assert response.status_code == 200, response.text
    return client


# --- Lab allowlist helpers --------------------------------------------------------

LAB_BAD_ADDRESS = "172.28.0.11"
LAB_GOOD_ADDRESS = "172.28.0.12"


@pytest.fixture
def lab_allowlist() -> LabServiceAllowlist:
    return LabServiceAllowlist(
        services=(
            LabService(
                id="labs-bad",
                description="bad fixture",
                environment="docker-compose-labs",
                addresses=(LAB_BAD_ADDRESS,),
                ports=(80, 8443),
            ),
            LabService(
                id="labs-good",
                description="good fixture",
                environment="docker-compose-labs",
                addresses=(LAB_GOOD_ADDRESS,),
                ports=(80, 8443),
            ),
        )
    )


@pytest.fixture
def lab_binding() -> LabBinding:
    return LabBinding(
        service="labs-bad",
        address=LAB_BAD_ADDRESS,
        port=80,
        environment="docker-compose-labs",
    )


@pytest.fixture
def resolver() -> StaticResolver:
    return StaticResolver(
        {
            "owned.example.com": ["93.184.216.34"],
            "dual.example.com": ["93.184.216.34", "10.0.0.5"],
            "private.example.com": ["10.1.2.3"],
            "loopback.example.com": ["127.0.0.1"],
            "metadata.example.com": ["169.254.169.254"],
        }
    )


@pytest.fixture
def future_expiry() -> datetime:
    return datetime.now(UTC) + timedelta(days=30)


def write_lab_services(tmp_path: Path, *, services: list[dict] | None = None) -> Path:
    import yaml

    payload = {
        "schema_version": "lab-services-v1",
        "services": services
        if services is not None
        else [
            {
                "id": "labs-bad",
                "description": "bad fixture",
                "environment": "docker-compose-labs",
                "addresses": [LAB_BAD_ADDRESS],
                "ports": [80, 8443],
                "schemes": ["http", "https"],
            },
            {
                "id": "labs-good",
                "description": "good fixture",
                "environment": "docker-compose-labs",
                "addresses": [LAB_GOOD_ADDRESS],
                "ports": [80, 8443],
                "schemes": ["http", "https"],
            },
        ],
    }
    path = tmp_path / "lab_services.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


__all__ = [
    "LAB_BAD_ADDRESS",
    "LAB_GOOD_ADDRESS",
    "AuthorityDomain",
    "Base",
    "make_task",
    "write_lab_services",
]


# --- M1 fixtures -------------------------------------------------------------------


@pytest.fixture
def lab_scope(db_session: Session, seeded_operator: tuple[uuid.UUID, str]):
    """A registered lab scope version, ready to be scanned."""
    from scopelens.domain.lab import LabBinding
    from scopelens.domain.scope import LabScopeCreate
    from scopelens.persistence.repositories import create_scope_version

    operator_id, _ = seeded_operator
    row = create_scope_version(
        db_session,
        operator_id=operator_id,
        payload=LabScopeCreate(
            lab_service="labs-bad",
            scheme="http",
            lab_port=80,
            authorization_expires_at=datetime.now(UTC) + timedelta(days=30),
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
    return row


@pytest.fixture
def queued_scan(db_session: Session, lab_scope, seeded_operator: tuple[uuid.UUID, str], settings):
    """A scan with its first task and outbox event, exactly as scan creation writes them."""
    from scopelens.domain.task import TaskType
    from scopelens.execution.ledger import create_scan_with_task

    operator_id, _ = seeded_operator
    scan, task = create_scan_with_task(
        db_session,
        operator_id=operator_id,
        scope_version=lab_scope,
        score_version=settings.score_version,
        task_type=TaskType.FETCH_ORIGIN,
        actor="test",
    )
    db_session.commit()
    return scan, task


@pytest.fixture
def evidence_store(tmp_path: Path):
    from scopelens.evidence.store import LocalDiskEvidenceStore

    return LocalDiskEvidenceStore(tmp_path / "evidence")


def make_task(scan_id: uuid.UUID, *, logical_id: str = "fetch-origin", attempt_id: str = "a1"):
    """Build an unsaved TaskRow with sensible defaults."""
    from scopelens.domain.task import TaskState, TaskType
    from scopelens.persistence.models import TaskRow

    return TaskRow(
        scan_id=scan_id,
        logical_id=logical_id,
        attempt_id=attempt_id,
        task_type=str(TaskType.FETCH_ORIGIN),
        state=str(TaskState.PLANNED),
        lease_token=0,
        reserved_budget={},
        spent_budget={},
    )
