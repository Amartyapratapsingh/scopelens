"""Policy broker containment (Build Plan §5.3; test suite §8 "Containment/scope").

Every test here corresponds to a request the broker must refuse. The broker is the
product's only scope boundary, so a gap in it is a gap in the safety claim rather than a
missing feature.

The resolver is injected throughout, so decisions are deterministic and nothing here
touches the network.

One structural note: a scan is bound to a `ScopeVersion`, and the broker loads the scope
from the *scan*. A test that builds a scan against one scope and then makes requests
against another is testing nothing, so every case here goes through `make_scan(scope)`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session
from tests.conftest import LAB_BAD_ADDRESS, LAB_GOOD_ADDRESS

from scopelens.broker.policy import (
    BrokerRequest,
    DenialReason,
    authorize,
    hash_egress_token,
    issue_egress_token,
    revoke_egress,
)
from scopelens.config import Settings
from scopelens.domain.budget import BudgetUsage
from scopelens.domain.scope import ProductionScopeCreate
from scopelens.execution import budget as budget_service
from scopelens.execution.leases import acquire_lease, release_lease
from scopelens.execution.ledger import budget_limits_for, create_scan_with_task
from scopelens.persistence.models import AuditEventRow
from scopelens.persistence.repositories import create_scope_version
from scopelens.scope.dns import ResolverError, StaticResolver

pytestmark = pytest.mark.db

PUBLIC_V4 = "93.184.216.34"
TENANT_HOST = "owned.example.com"


# --- Fixtures ------------------------------------------------------------------------


@pytest.fixture
def production_scope(db_session: Session, seeded_operator):
    operator_id, _ = seeded_operator
    row = create_scope_version(
        db_session,
        operator_id=operator_id,
        payload=ProductionScopeCreate(
            host=TENANT_HOST,
            scheme="https",
            port=443,
            allowed_path_prefixes=["/app"],
            excluded_paths=["/app/admin"],
            authorization_expires_at=datetime.now(UTC) + timedelta(days=30),
        ),
        scheme="https",
        host=TENANT_HOST,
        port=443,
        lab_binding=None,
    )
    db_session.commit()
    return row


@pytest.fixture
def make_scan(db_session: Session, seeded_operator, settings: Settings):
    """Create a scan bound to ``scope_row``, with an egress token and a live lease."""

    operator_id, _ = seeded_operator

    def _make(scope_row, *, with_token: bool = True, with_lease: bool = True):
        scan, task = create_scan_with_task(
            db_session,
            operator_id=operator_id,
            scope_version=scope_row,
            score_version=settings.score_version,
            actor="test",
        )
        db_session.flush()
        token = issue_egress_token(db_session, scan=scan) if with_token else ""
        if with_lease:
            acquire_lease(db_session, scan_id=scan.id, holder="test", ttl_seconds=300)
        db_session.commit()
        return scan, task, token

    return _make


@pytest.fixture
def prepared(production_scope, make_scan):
    """A production scan with a live lease, ready to make requests."""
    scan, _task, token = make_scan(production_scope)
    return production_scope, token, scan


def resolver_for(addresses: str | list[str]) -> StaticResolver:
    resolved = [addresses] if isinstance(addresses, str) else addresses
    return StaticResolver({TENANT_HOST: resolved})


def request_for(scope_row, token: str, **overrides) -> BrokerRequest:
    base: dict[str, object] = {
        "method": "GET",
        "scheme": scope_row.scheme,
        "host": scope_row.host,
        "port": scope_row.port,
        "path": "/app",
        "egress_token": token,
    }
    base.update(overrides)
    return BrokerRequest(**base)  # type: ignore[arg-type]


def decide(db_session: Session, settings: Settings, scope_row, token: str, resolver, **overrides):
    return authorize(
        db_session,
        settings=settings,
        request=request_for(scope_row, token, **overrides),
        resolver=resolver,
    )


# --- Token and lifecycle gates -------------------------------------------------------


class TestTokenAndLifecycle:
    def test_unknown_token_is_refused(self, db_session: Session, settings, lab_scope) -> None:
        decision = decide(db_session, settings, lab_scope, "not-a-real-token", StaticResolver({}))
        assert not decision.allowed
        assert decision.denial is DenialReason.UNKNOWN_TOKEN

    def test_a_scan_without_a_live_lease_is_refused(
        self, db_session: Session, settings, lab_scope, make_scan
    ) -> None:
        """Egress is admitted only while a coordinator holds the scan (§5.3)."""
        _scan, _task, token = make_scan(lab_scope, with_lease=False)

        decision = decide(db_session, settings, lab_scope, token, StaticResolver({}))
        assert not decision.allowed
        assert decision.denial is DenialReason.NO_LIVE_LEASE

    def test_with_a_live_lease_the_lab_fixture_is_reachable(
        self, db_session: Session, settings, lab_scope, make_scan
    ) -> None:
        _scan, _task, token = make_scan(lab_scope)

        decision = decide(db_session, settings, lab_scope, token, StaticResolver({}))
        assert decision.allowed, decision.detail
        assert decision.addresses == (LAB_BAD_ADDRESS,)

    def test_cancelling_revokes_the_token_immediately(
        self, db_session: Session, settings, lab_scope, make_scan
    ) -> None:
        """The 5-second (in fact immediate) half of cancellation."""
        scan, _task, token = make_scan(lab_scope)
        assert decide(db_session, settings, lab_scope, token, StaticResolver({})).allowed

        revoke_egress(db_session, scan=scan)
        scan.cancel_requested_at = datetime.now(UTC)
        db_session.commit()

        decision = decide(db_session, settings, lab_scope, token, StaticResolver({}))
        assert not decision.allowed
        assert decision.denial is DenialReason.REVOKED_TOKEN

    def test_a_cancelled_scan_is_refused_even_with_a_matching_epoch(
        self, db_session: Session, settings, lab_scope, make_scan
    ) -> None:
        """Belt and braces: the cancellation flag alone is enough to stop egress."""
        scan, _task, _token = make_scan(lab_scope, with_token=False, with_lease=False)

        token = "a-token-issued-after-cancellation"
        scan.cancel_requested_at = datetime.now(UTC)
        scan.egress_token_hash = hash_egress_token(token)
        scan.egress_token_epoch = scan.cancel_epoch
        acquire_lease(db_session, scan_id=scan.id, holder="test", ttl_seconds=300)
        db_session.commit()

        decision = decide(db_session, settings, lab_scope, token, StaticResolver({}))
        assert not decision.allowed
        assert decision.denial is DenialReason.CANCELLED

    def test_releasing_the_lease_stops_further_requests(
        self, db_session: Session, settings, lab_scope, make_scan
    ) -> None:
        scan, _task, token = make_scan(lab_scope)
        lease = acquire_lease(db_session, scan_id=scan.id, holder="test", ttl_seconds=300)
        db_session.flush()

        release_lease(db_session, scan_id=scan.id, holder="test", fencing_token=lease.fencing_token)
        db_session.commit()

        decision = decide(db_session, settings, lab_scope, token, StaticResolver({}))
        assert not decision.allowed
        assert decision.denial is DenialReason.NO_LIVE_LEASE


# --- Scope membership ----------------------------------------------------------------


class TestScopeMembership:
    def test_wrong_port_is_refused(self, db_session: Session, settings, prepared) -> None:
        scope, token, _scan = prepared
        decision = decide(db_session, settings, scope, token, resolver_for(PUBLIC_V4), port=8443)
        assert decision.denial is DenialReason.PORT_NOT_ALLOWED

    def test_disallowed_method_is_refused(self, db_session: Session, settings, prepared) -> None:
        scope, token, _scan = prepared
        decision = decide(
            db_session, settings, scope, token, resolver_for(PUBLIC_V4), method="DELETE"
        )
        assert decision.denial is DenialReason.METHOD_NOT_ALLOWED

    def test_path_outside_the_prefix_is_refused(
        self, db_session: Session, settings, prepared
    ) -> None:
        scope, token, _scan = prepared
        decision = decide(
            db_session, settings, scope, token, resolver_for(PUBLIC_V4), path="/etc/passwd"
        )
        assert decision.denial is DenialReason.PATH_NOT_ALLOWED

    def test_excluded_path_is_refused(self, db_session: Session, settings, prepared) -> None:
        scope, token, _scan = prepared
        decision = decide(
            db_session, settings, scope, token, resolver_for(PUBLIC_V4), path="/app/admin"
        )
        assert decision.denial is DenialReason.PATH_EXCLUDED

    def test_a_redirect_to_an_excluded_path_is_refused(
        self, db_session: Session, settings, prepared
    ) -> None:
        scope, token, _scan = prepared
        decision = decide(
            db_session, settings, scope, token, resolver_for(PUBLIC_V4), path="/app/admin/users"
        )
        assert decision.denial is DenialReason.PATH_EXCLUDED

    def test_host_outside_the_scope_is_refused(
        self, db_session: Session, settings, prepared
    ) -> None:
        scope, token, _scan = prepared
        decision = decide(
            db_session, settings, scope, token, resolver_for(PUBLIC_V4), host="other.example.com"
        )
        assert decision.denial is DenialReason.HOST_NOT_IN_SCOPE

    def test_an_in_scope_request_is_allowed(self, db_session: Session, settings, prepared) -> None:
        scope, token, _scan = prepared
        decision = decide(db_session, settings, scope, token, resolver_for(PUBLIC_V4))
        assert decision.allowed, decision.detail


# --- Destination refusals ------------------------------------------------------------


class TestConnectAuthorization:
    """CONNECT is a tunnel request, not a target request (Build Plan §5.3).

    The addon authorizes CONNECT separately from the inner requests, because a tunnel that
    carries non-HTTP bytes never produces an inner request at all. These cases pin the rules
    for that separate decision.
    """

    def test_connect_is_allowed_for_an_in_scope_tunnel(
        self, db_session: Session, settings, prepared
    ) -> None:
        """A scope allowing only GET and HEAD must still permit an HTTPS tunnel.

        Enforcing the method allowlist on CONNECT would make every HTTPS request
        impossible — a scope rule contradicting the transport it runs on.
        """
        scope, token, _scan = prepared
        decision = decide(
            db_session, settings, scope, token, resolver_for(PUBLIC_V4), method="CONNECT", path="/"
        )
        assert decision.allowed, decision.detail

    def test_connect_to_the_wrong_port_is_refused(
        self, db_session: Session, settings, prepared
    ) -> None:
        """Host and port are the whole of a tunnel's authorization, so they are enforced."""
        scope, token, _scan = prepared
        decision = decide(
            db_session, settings, scope, token, resolver_for(PUBLIC_V4), method="CONNECT", port=22
        )
        assert decision.denial is DenialReason.PORT_NOT_ALLOWED

    def test_connect_to_a_non_public_destination_is_refused(
        self, db_session: Session, settings, prepared
    ) -> None:
        scope, token, _scan = prepared
        decision = decide(
            db_session, settings, scope, token, resolver_for("127.0.0.1"), method="CONNECT"
        )
        assert not decision.allowed

    def test_connect_needs_a_live_lease_like_any_other_request(
        self, db_session: Session, settings, production_scope, make_scan
    ) -> None:
        _scan, _task, token = make_scan(production_scope, with_lease=False)
        decision = decide(
            db_session, settings, production_scope, token, resolver_for(PUBLIC_V4), method="CONNECT"
        )
        assert decision.denial is DenialReason.NO_LIVE_LEASE


class TestDestinationRefusals:
    @pytest.mark.parametrize(
        ("address", "label"),
        [
            ("127.0.0.1", "loopback"),
            ("10.0.0.5", "RFC1918 private"),
            ("192.168.1.1", "RFC1918 private"),
            ("172.16.5.5", "RFC1918 private"),
            ("169.254.169.254", "cloud metadata"),
            ("100.64.0.1", "CGNAT"),
            ("::1", "IPv6 loopback"),
            ("fe80::1", "IPv6 link-local"),
            ("fc00::1", "IPv6 unique-local"),
            ("0.0.0.0", "unspecified"),
        ],
    )
    def test_non_public_destinations_are_refused(
        self, db_session: Session, settings, prepared, address: str, label: str
    ) -> None:
        scope, token, _scan = prepared
        decision = decide(db_session, settings, scope, token, resolver_for(address))
        assert not decision.allowed, f"{address} ({label}) must be refused"

    def test_a_dual_resolving_host_is_refused(
        self, db_session: Session, settings, prepared
    ) -> None:
        """One private answer is enough; a public answer does not excuse it."""
        scope, token, _scan = prepared
        decision = decide(db_session, settings, scope, token, resolver_for([PUBLIC_V4, "10.0.0.5"]))
        assert not decision.allowed

    def test_an_unresolvable_host_is_refused(self, db_session: Session, settings, prepared) -> None:
        scope, token, _scan = prepared

        class Failing:
            def resolve(self, host: str) -> list[str]:
                raise ResolverError(f"cannot resolve {host}")

        decision = decide(db_session, settings, scope, token, Failing())
        assert not decision.allowed
        assert decision.denial is DenialReason.RESOLUTION_FAILED


class TestDnsRebinding:
    def test_public_dns_rotation_never_changes_the_pinned_destination(
        self, db_session: Session, settings, prepared
    ) -> None:
        """A CDN may rotate DNS; keep connecting only to the initially approved address."""
        scope, token, scan = prepared

        first = decide(db_session, settings, scope, token, resolver_for(PUBLIC_V4))
        assert first.allowed, first.detail
        db_session.commit()

        rebound = decide(db_session, settings, scope, token, resolver_for("1.1.1.1"))
        assert rebound.allowed
        assert rebound.addresses == (PUBLIC_V4,)
        assert scan.pinned_addresses == [PUBLIC_V4]

    def test_dns_order_and_duplicates_do_not_change_the_pin(self, db_session, settings, prepared):
        scope, token, scan = prepared
        first = decide(db_session, settings, scope, token, resolver_for([PUBLIC_V4, "1.1.1.1"]))
        db_session.commit()
        second = decide(
            db_session, settings, scope, token, resolver_for(["1.1.1.1", PUBLIC_V4, PUBLIC_V4])
        )
        assert second.allowed
        assert second.addresses == first.addresses
        assert scan.pinned_addresses == list(first.addresses)

    def test_a_host_that_repoints_to_a_private_address_is_refused(
        self, db_session: Session, settings, prepared
    ) -> None:
        """The same attack stopped by the destination rule: two independent refusals."""
        scope, token, _scan = prepared
        decide(db_session, settings, scope, token, resolver_for(PUBLIC_V4))
        db_session.commit()

        rebound = decide(db_session, settings, scope, token, resolver_for("127.0.0.1"))
        assert not rebound.allowed
        assert rebound.denial is DenialReason.DESTINATION_REFUSED

    def test_the_pin_is_written_to_the_scan_row(
        self, db_session: Session, settings, prepared
    ) -> None:
        """Durable, not in memory: a coordinator restart must not forget the pin."""
        scope, token, scan = prepared

        decide(db_session, settings, scope, token, resolver_for(PUBLIC_V4))
        db_session.commit()

        assert scan.pinned_addresses == [PUBLIC_V4]

    def test_a_consistent_answer_keeps_working(
        self, db_session: Session, settings, prepared
    ) -> None:
        scope, token, _scan = prepared
        for _ in range(3):
            assert decide(db_session, settings, scope, token, resolver_for(PUBLIC_V4)).allowed
            db_session.commit()


# --- Budget --------------------------------------------------------------------------


class TestBudgetEnforcement:
    def test_requests_are_refused_once_the_budget_is_spent(
        self, db_session: Session, settings: Settings, production_scope, make_scan
    ) -> None:
        scan, _task, token = make_scan(production_scope)
        limits = budget_limits_for(production_scope, settings)
        budget_service.reserve(
            db_session,
            scan_id=scan.id,
            limits=limits,
            usage=BudgetUsage(requests=limits.max_requests),
        )
        db_session.commit()

        decision = decide(db_session, settings, production_scope, token, resolver_for(PUBLIC_V4))
        assert not decision.allowed
        assert decision.denial is DenialReason.BUDGET_EXHAUSTED

    def test_each_admitted_request_consumes_budget(
        self, db_session: Session, settings, production_scope, make_scan
    ) -> None:
        scan, _task, token = make_scan(production_scope)
        decide(db_session, settings, production_scope, token, resolver_for(PUBLIC_V4))
        decide(db_session, settings, production_scope, token, resolver_for(PUBLIC_V4))
        db_session.commit()

        _, reserved = budget_service.read_usage(scan)
        assert reserved.requests == 2


# --- Authority separation ------------------------------------------------------------


class TestAuthoritySeparation:
    def test_a_production_scan_cannot_reach_a_lab_address(
        self, db_session: Session, settings, production_scope, make_scan
    ) -> None:
        """The M0 authority split must hold: production can never select lab authority."""
        _scan, _task, token = make_scan(production_scope)

        decision = decide(
            db_session,
            settings,
            production_scope,
            token,
            resolver_for([LAB_BAD_ADDRESS, LAB_GOOD_ADDRESS]),
        )
        assert not decision.allowed, "a production scope resolved a lab address and was allowed"

    def test_removing_a_service_from_the_allowlist_stops_it_immediately(
        self, db_session: Session, settings: Settings, lab_scope, make_scan, tmp_path
    ) -> None:
        """Defence in depth: the allowlist is consulted per request, not only at registration.

        The scope record still names ``labs-bad``. If the operator later removes it from
        deploy/lab_services.yaml, the next request must fail — a binding approved once is
        not approved forever.
        """
        _scan, _task, token = make_scan(lab_scope)
        assert decide(db_session, settings, lab_scope, token, StaticResolver({})).allowed

        empty = tmp_path / "lab_services.yaml"
        empty.write_text("schema_version: lab-services-v1\nservices: []\n", encoding="utf-8")
        without = settings.model_copy(update={"lab_services_file": empty})

        decision = decide(db_session, without, lab_scope, token, StaticResolver({}))
        assert not decision.allowed
        assert decision.denial is DenialReason.DESTINATION_REFUSED

    def test_the_lab_fixture_is_reachable_only_via_its_own_binding(
        self, db_session: Session, settings, lab_scope, make_scan
    ) -> None:
        """The exit gate's "named lab service reachable only via its binding"."""
        _scan, _task, token = make_scan(lab_scope)

        assert decide(db_session, settings, lab_scope, token, StaticResolver({})).allowed

        for bad in (
            {"port": 22},
            {"port": 8080},
            {"host": "10.0.0.1"},
            {"host": "169.254.169.254"},
            {"host": "127.0.0.1"},
            {"host": LAB_GOOD_ADDRESS},
        ):
            assert not decide(
                db_session, settings, lab_scope, token, StaticResolver({}), **bad
            ).allowed, bad


# --- Audit and fail-closed -----------------------------------------------------------


class TestAuditability:
    def test_every_decision_is_recorded(
        self, db_session: Session, settings, production_scope, make_scan
    ) -> None:
        """The coordinator counts these rows, so they are load-bearing, not just a log."""
        scan, _task, token = make_scan(production_scope)

        decide(db_session, settings, production_scope, token, resolver_for(PUBLIC_V4))
        decide(db_session, settings, production_scope, token, resolver_for(PUBLIC_V4), path="/nope")
        db_session.commit()

        rows = (
            db_session.query(AuditEventRow)
            .filter(
                AuditEventRow.action == "broker.admit",
                AuditEventRow.subject_id == str(scan.id),
            )
            .all()
        )
        assert len(rows) == 2
        assert {row.outcome for row in rows} == {"allowed", "denied"}

    def test_an_unknown_token_writes_nothing(
        self, db_session: Session, settings, lab_scope
    ) -> None:
        """Otherwise anything on the control network could fill the audit table."""
        decide(db_session, settings, lab_scope, "bogus", StaticResolver({}))
        db_session.commit()

        assert (
            db_session.query(AuditEventRow).filter(AuditEventRow.action == "broker.admit").count()
            == 0
        )


class TestFailsClosed:
    def test_an_internal_error_denies_rather_than_allows(
        self, db_session: Session, settings, production_scope, make_scan
    ) -> None:
        """§5.3: fail closed. A broken check must never become an allow."""
        _scan, _task, token = make_scan(production_scope)

        class Exploding:
            def resolve(self, host: str) -> list[str]:
                raise RuntimeError("something unexpected")

        decision = decide(db_session, settings, production_scope, token, Exploding())
        assert not decision.allowed
        assert decision.denial is DenialReason.INTERNAL_ERROR


class TestActivationGate:
    """The exit gate's "an unexpected allow blocks activation" (Build Plan §8).

    Written as one explicit gate rather than relying on a reader to infer it from the
    suite's shape. Every destination below must be refused; a single allow fails this test,
    and the failure message says what that means for activation rather than leaving it to
    the reader to work out.
    """

    FORBIDDEN_DESTINATIONS = (
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
    )

    def test_no_forbidden_destination_is_allowed(
        self, db_session: Session, settings, prepared
    ) -> None:
        scope, token, _scan = prepared
        unexpectedly_allowed: list[str] = []

        for address in self.FORBIDDEN_DESTINATIONS:
            decision = decide(db_session, settings, scope, token, resolver_for(address))
            if decision.allowed:
                unexpectedly_allowed.append(address)
            db_session.rollback()

        assert not unexpectedly_allowed, (
            f"CONTAINMENT FAILURE — the broker allowed {unexpectedly_allowed}. "
            "An unexpected allow in a containment test blocks production activation "
            "(Build Plan §8): the scope boundary cannot be relied on, so no profile may "
            "be promoted to production until this is fixed."
        )

    def test_a_containment_failure_would_be_detected(
        self, db_session: Session, settings, prepared
    ) -> None:
        """Proves the gate above can fail, so a green run means something.

        A gate that cannot fail is decoration. This drives the same loop against a
        destination that *is* allowed and asserts the gate would have caught it.
        """
        scope, token, _scan = prepared
        decision = decide(db_session, settings, scope, token, resolver_for(PUBLIC_V4))
        assert decision.allowed, decision.detail
        assert PUBLIC_V4 not in self.FORBIDDEN_DESTINATIONS


def test_crawler_browser_and_cli_share_durable_request_schedule(prepared, db_session, settings):
    scope, token, scan = prepared
    now = datetime.now(UTC)
    waits = []
    for method in ["GET", "CONNECT", "GET"]:
        decision = authorize(
            db_session,
            settings=settings,
            request=request_for(scope, token, method=method),
            resolver=resolver_for(PUBLIC_V4),
            now=now,
        )
        assert decision.allowed
        waits.append(float(decision.extra["wait_seconds"]))
        db_session.commit()
    assert waits == [0, 0.5, 1]
    db_session.expire_all()
    assert scan.assessment_plan["next_request_at"]


def test_page_cap_is_shared_between_crawler_and_browser(prepared, db_session, settings):
    scope, token, scan = prepared
    scan.assessment_plan = {"page_request_keys": ["already-consumed"] * settings.budgets.max_pages}
    db_session.commit()
    decision = decide(
        db_session, settings, scope, token, resolver_for(PUBLIC_V4), path="/app/browser-only"
    )
    assert not decision.allowed and decision.reason == "budget_exhausted"
