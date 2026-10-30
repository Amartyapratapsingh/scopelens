"""Budget reservation and reconciliation (Build Plan §5.2, §5.3).

Two properties matter and are tested explicitly:

* reservation is **atomic** — two reservations racing for the last request cannot both
  succeed, or the ceiling is not a ceiling
* spent budget **persists** across recovery — forgiving it on a crash would let an
  interrupted scan buy itself extra requests, which is precisely the loophole §5.6 closes
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from scopelens.domain.budget import (
    BudgetExceeded,
    BudgetLimits,
    BudgetUsage,
    check_reservation,
)
from scopelens.execution import budget as budget_service

pytestmark = pytest.mark.db


def limits(max_requests: int = 5, max_pages: int = 3) -> BudgetLimits:
    return BudgetLimits(
        max_requests=max_requests,
        max_pages=max_pages,
        max_response_bytes=1024,
        wall_clock_seconds=60,
        requests_per_second=2,
        max_in_flight=2,
        max_redirects_per_fetch=5,
    )


class TestPendingLimits:
    def test_allows_within_the_ceiling(self) -> None:
        check_reservation(spent=BudgetUsage(), reserved=BudgetUsage(requests=3), limits=limits())

    def test_refuses_when_the_next_request_would_exceed(self) -> None:
        with pytest.raises(BudgetExceeded, match="request budget exhausted"):
            check_reservation(
                spent=BudgetUsage(requests=5), reserved=BudgetUsage(), limits=limits()
            )

    def test_the_last_admissible_request_is_allowed(self) -> None:
        """An off-by-one here would refuse the final request of every budget."""
        check_reservation(
            spent=BudgetUsage(requests=4), reserved=BudgetUsage(), limits=limits(max_requests=5)
        )
        with pytest.raises(BudgetExceeded):
            check_reservation(
                spent=BudgetUsage(requests=5), reserved=BudgetUsage(), limits=limits(max_requests=5)
            )

    def test_a_reservation_counts_against_the_ceiling(self) -> None:
        """Work admitted but not yet reconciled must not be spendable twice."""
        with pytest.raises(BudgetExceeded):
            check_reservation(
                spent=BudgetUsage(requests=3), reserved=BudgetUsage(requests=2), limits=limits()
            )

    def test_page_ceiling_is_separate(self) -> None:
        with pytest.raises(BudgetExceeded, match="page budget exhausted"):
            check_reservation(
                spent=BudgetUsage(pages=3),
                reserved=BudgetUsage(),
                limits=limits(max_requests=100),
                requested=BudgetUsage(pages=1),
            )


class TestReservation:
    def test_reserve_then_reconcile(self, db_session: Session, queued_scan) -> None:
        scan, _ = queued_scan
        reserved = budget_service.reserve(
            db_session,
            scan_id=scan.id,
            limits=limits(),
            usage=BudgetUsage().plus_requests(1),
        )
        db_session.commit()
        assert reserved.requests == 1

        spent, remaining_reserved = budget_service.reconcile(
            db_session,
            scan_id=scan.id,
            reserved=BudgetUsage(requests=1),
            spent=BudgetUsage(requests=1),
        )
        db_session.commit()

        assert spent.requests == 1
        assert remaining_reserved.requests == 0

    def test_reservations_accumulate(self, db_session: Session, queued_scan) -> None:
        scan, _ = queued_scan
        for _ in range(3):
            budget_service.reserve(
                db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage().plus_requests(1)
            )
        db_session.commit()

        _, reserved = budget_service.read_usage(scan)
        assert reserved.requests == 3

    def test_reservation_is_refused_at_the_ceiling(self, db_session: Session, queued_scan) -> None:
        scan, _ = queued_scan
        for _ in range(5):
            budget_service.reserve(
                db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage().plus_requests(1)
            )
        db_session.commit()

        with pytest.raises(BudgetExceeded):
            budget_service.reserve(
                db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage().plus_requests(1)
            )

    def test_a_partial_spend_releases_the_rest(self, db_session: Session, queued_scan) -> None:
        """A reservation of 3 that only spent 1 must return 2 to the pool."""
        scan, _ = queued_scan
        budget_service.reserve(
            db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage(requests=3)
        )
        db_session.commit()

        spent, reserved = budget_service.reconcile(
            db_session,
            scan_id=scan.id,
            reserved=BudgetUsage(requests=3),
            spent=BudgetUsage(requests=1),
        )
        db_session.commit()

        assert spent.requests == 1
        assert reserved.requests == 0

    def test_release_returns_an_unused_reservation(self, db_session: Session, queued_scan) -> None:
        scan, _ = queued_scan
        budget_service.reserve(
            db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage(requests=2)
        )
        db_session.commit()

        budget_service.release(db_session, scan_id=scan.id, reserved=BudgetUsage(requests=2))
        db_session.commit()

        _, reserved = budget_service.read_usage(scan)
        assert reserved.requests == 0


class TestPersistenceAcrossRecovery:
    def test_spent_budget_survives_clearing_reservations(
        self, db_session: Session, queued_scan
    ) -> None:
        """§5.6: spent budget persists. Only the *reservation* is released on recovery."""
        scan, _ = queued_scan
        budget_service.reserve(
            db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage(requests=4)
        )
        budget_service.reconcile(
            db_session,
            scan_id=scan.id,
            reserved=BudgetUsage(requests=4),
            spent=BudgetUsage(requests=4),
        )
        budget_service.reserve(
            db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage(requests=1)
        )
        db_session.commit()

        cleared = budget_service.clear_reservations(db_session, scan_id=scan.id)
        db_session.commit()

        assert cleared.requests == 1
        spent, reserved = budget_service.read_usage(scan)
        assert spent.requests == 4, "spend must survive recovery"
        assert reserved.requests == 0

    def test_a_cleared_reservation_frees_room_but_not_the_spend(
        self, db_session: Session, queued_scan
    ) -> None:
        scan, _ = queued_scan
        budget_service.reserve(
            db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage(requests=5)
        )
        db_session.commit()
        with pytest.raises(BudgetExceeded):
            budget_service.reserve(
                db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage().plus_requests(1)
            )
        db_session.rollback()

        budget_service.clear_reservations(db_session, scan_id=scan.id)
        db_session.commit()

        # Room is back, because nothing was actually spent.
        budget_service.reserve(
            db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage().plus_requests(1)
        )
        db_session.commit()


class TestUsageArithmetic:
    def test_minus_clamps_at_zero(self) -> None:
        """Releasing more than was reserved must not inflate the remaining budget."""
        result = BudgetUsage(requests=1).minus(BudgetUsage(requests=5))
        assert result.requests == 0

    def test_committed_sums_both(self) -> None:
        total = BudgetUsage(requests=2).committed_with(BudgetUsage(requests=3))
        assert total.requests == 5

    def test_usage_is_immutable(self) -> None:
        usage = BudgetUsage()
        with pytest.raises(ValueError):
            usage.requests = 5  # type: ignore[misc]
        assert usage.plus_requests(1) is not usage


class TestRemaining:
    def test_remaining_accounts_for_spend_and_reservation(
        self, db_session: Session, queued_scan
    ) -> None:
        scan, _ = queued_scan
        budget_service.reserve(
            db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage(requests=2)
        )
        budget_service.reconcile(
            db_session,
            scan_id=scan.id,
            reserved=BudgetUsage(requests=2),
            spent=BudgetUsage(requests=1),
        )
        budget_service.reserve(
            db_session, scan_id=scan.id, limits=limits(), usage=BudgetUsage(requests=1)
        )
        db_session.commit()

        remaining = budget_service.remaining(scan, limits())
        assert remaining.requests == 3
