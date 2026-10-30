"""Coordinator leases and fencing tokens (Build Plan §5.2, §5.6).

The property under test throughout is that a superseded coordinator cannot act. That is
the difference between "one coordinator per scan" being a fact and being a hope.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from scopelens.execution.leases import (
    LeaseLost,
    acquire_lease,
    assert_lease_held,
    expire_stale_leases,
    lease_is_live,
    release_lease,
    renew_lease,
)

pytestmark = pytest.mark.db

TTL = 30


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)


class TestAcquire:
    def test_first_acquire_creates_the_lease(self, db_session: Session, queued_scan, now) -> None:
        scan, _ = queued_scan
        lease = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        db_session.commit()

        assert lease is not None
        assert lease.fencing_token == 1
        assert lease.holder == "A"

    def test_a_live_lease_is_not_granted_to_another_holder(
        self, db_session: Session, queued_scan, now
    ) -> None:
        """The core guarantee: two coordinators cannot both hold one scan."""
        scan, _ = queued_scan
        acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        db_session.commit()

        second = acquire_lease(db_session, scan_id=scan.id, holder="B", ttl_seconds=TTL, now=now)
        assert second is None

    def test_taking_over_an_expired_lease_bumps_the_fencing_token(
        self, db_session: Session, queued_scan, now
    ) -> None:
        """This increment is what invalidates the previous holder, who may still be alive."""
        scan, _ = queued_scan
        first = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        db_session.commit()

        later = now + timedelta(seconds=TTL + 1)
        second = acquire_lease(db_session, scan_id=scan.id, holder="B", ttl_seconds=TTL, now=later)
        db_session.commit()

        assert second is not None
        assert first is not None
        assert second.fencing_token == first.fencing_token + 1

    def test_taking_over_a_released_lease_also_bumps_the_token(
        self, db_session: Session, queued_scan, now
    ) -> None:
        scan, _ = queued_scan
        first = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert first is not None
        db_session.commit()

        release_lease(
            db_session, scan_id=scan.id, holder="A", fencing_token=first.fencing_token, now=now
        )
        db_session.commit()

        second = acquire_lease(db_session, scan_id=scan.id, holder="B", ttl_seconds=TTL, now=now)
        assert second is not None
        assert second.fencing_token > first.fencing_token


class TestRenew:
    def test_renews_with_the_current_token(self, db_session: Session, queued_scan, now) -> None:
        scan, _ = queued_scan
        lease = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert lease is not None
        db_session.commit()

        later = now + timedelta(seconds=10)
        renewed = renew_lease(
            db_session,
            scan_id=scan.id,
            holder="A",
            fencing_token=lease.fencing_token,
            ttl_seconds=TTL,
            now=later,
        )
        db_session.commit()

        assert renewed.expires_at > lease.expires_at

    def test_a_stale_token_cannot_renew(self, db_session: Session, queued_scan, now) -> None:
        """The superseded coordinator's renewal fails, so it learns it has lost the scan."""
        scan, _ = queued_scan
        first = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert first is not None
        db_session.commit()

        later = now + timedelta(seconds=TTL + 1)
        acquire_lease(db_session, scan_id=scan.id, holder="B", ttl_seconds=TTL, now=later)
        db_session.commit()

        with pytest.raises(LeaseLost, match="superseded"):
            renew_lease(
                db_session,
                scan_id=scan.id,
                holder="A",
                fencing_token=first.fencing_token,
                ttl_seconds=TTL,
                now=later,
            )

    def test_an_expired_lease_cannot_be_renewed(
        self, db_session: Session, queued_scan, now
    ) -> None:
        scan, _ = queued_scan
        lease = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert lease is not None
        db_session.commit()

        with pytest.raises(LeaseLost, match="expired"):
            renew_lease(
                db_session,
                scan_id=scan.id,
                holder="A",
                fencing_token=lease.fencing_token,
                ttl_seconds=TTL,
                now=now + timedelta(seconds=TTL + 1),
            )


class TestAssertHeld:
    def test_passes_for_the_current_token(self, db_session: Session, queued_scan, now) -> None:
        scan, _ = queued_scan
        lease = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert lease is not None
        db_session.commit()

        assert_lease_held(db_session, scan_id=scan.id, fencing_token=lease.fencing_token, now=now)

    def test_rejects_a_stale_token(self, db_session: Session, queued_scan, now) -> None:
        """This is the check every executor makes before touching the target."""
        scan, _ = queued_scan
        first = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert first is not None
        db_session.commit()

        later = now + timedelta(seconds=TTL + 1)
        acquire_lease(db_session, scan_id=scan.id, holder="B", ttl_seconds=TTL, now=later)
        db_session.commit()

        with pytest.raises(LeaseLost, match="stale fencing token"):
            assert_lease_held(
                db_session, scan_id=scan.id, fencing_token=first.fencing_token, now=later
            )

    def test_rejects_without_a_lease(self, db_session: Session, queued_scan, now) -> None:
        scan, _ = queued_scan
        with pytest.raises(LeaseLost, match="no lease"):
            assert_lease_held(db_session, scan_id=scan.id, fencing_token=1, now=now)

    def test_rejects_after_release(self, db_session: Session, queued_scan, now) -> None:
        scan, _ = queued_scan
        lease = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert lease is not None
        db_session.commit()

        release_lease(
            db_session, scan_id=scan.id, holder="A", fencing_token=lease.fencing_token, now=now
        )
        db_session.commit()

        with pytest.raises(LeaseLost):
            assert_lease_held(
                db_session, scan_id=scan.id, fencing_token=lease.fencing_token, now=now
            )


class TestReleaseAndExpiry:
    def test_release_bumps_the_token_so_the_releaser_cannot_keep_acting(
        self, db_session: Session, queued_scan, now
    ) -> None:
        scan, _ = queued_scan
        lease = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert lease is not None
        db_session.commit()

        assert release_lease(
            db_session, scan_id=scan.id, holder="A", fencing_token=lease.fencing_token, now=now
        )
        db_session.commit()

        with pytest.raises(LeaseLost):
            assert_lease_held(
                db_session, scan_id=scan.id, fencing_token=lease.fencing_token, now=now
            )

    def test_a_releaser_who_is_no_longer_the_holder_gets_false(
        self, db_session: Session, queued_scan, now
    ) -> None:
        scan, _ = queued_scan
        lease = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert lease is not None
        db_session.commit()

        assert not release_lease(
            db_session, scan_id=scan.id, holder="B", fencing_token=lease.fencing_token, now=now
        )

    def test_expire_stale_leases_releases_only_expired_ones(
        self, db_session: Session, queued_scan, now
    ) -> None:
        scan, _ = queued_scan
        acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        db_session.commit()

        assert expire_stale_leases(db_session, now=now + timedelta(seconds=5)) == []
        expired = expire_stale_leases(db_session, now=now + timedelta(seconds=TTL + 1))
        db_session.commit()

        assert len(expired) == 1
        assert not lease_is_live(db_session, scan.id, now=now + timedelta(seconds=TTL + 1))


class TestLeasePayload:
    def test_dispatch_payload_carries_identity_not_authority(
        self, db_session: Session, queued_scan, now
    ) -> None:
        """Queue work carries references, not authority (§5.2)."""
        scan, _ = queued_scan
        lease = acquire_lease(db_session, scan_id=scan.id, holder="A", ttl_seconds=TTL, now=now)
        assert lease is not None

        payload = lease.as_payload()
        assert set(payload) == {"scan_id", "holder", "fencing_token"}
        assert "scope" not in payload
        assert "token" not in payload
