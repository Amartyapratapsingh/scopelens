"""Coordinator leases and fencing tokens (Build Plan §5.2, §5.6).

One renewable lease per scan. The fencing token is the whole point: it lets a new
coordinator take over a scan from a predecessor that is *still alive*, and lets every
executor detect that its authority is stale and refuse to act.

The failure this prevents is specific and expensive. Without fencing, a coordinator
paused by a long GC or a network partition can wake up believing it still owns the scan,
while a replacement is already running — producing two concurrent runs against the same
target, spending the same budget twice, and duplicating side effects.

Everything here takes `now` as an argument rather than reading the clock, so lease
expiry is testable without sleeping.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from scopelens.persistence.models import CoordinatorLeaseRow, ScanRow


class LeaseLost(RuntimeError):
    """The caller no longer holds the lease it is acting under.

    Always fatal to the current attempt. The caller must stop, revoke its egress and let
    the reconciler decide what happens next — it must **not** retry, because a
    replacement may already be running (§5.2).
    """


@dataclass(frozen=True)
class Lease:
    """A held lease, as presented by its holder."""

    scan_id: uuid.UUID
    holder: str
    fencing_token: int
    expires_at: datetime

    def as_payload(self) -> dict[str, str | int]:
        """The subset carried in a dispatch message.

        Only the identity is carried — never authority. A queue message can propose work
        but cannot grant it (§5.2: "Queue work carries references, not authority").
        """
        return {
            "scan_id": str(self.scan_id),
            "holder": self.holder,
            "fencing_token": self.fencing_token,
        }


def now_utc() -> datetime:
    return datetime.now(UTC)


def _locked_lease(session: Session, scan_id: uuid.UUID) -> CoordinatorLeaseRow | None:
    """Load the lease row under a row lock so acquire/renew cannot race.

    ``FOR UPDATE`` serialises two coordinators competing for the same scan. Without it,
    both could read "expired" and both proceed to take over.
    """
    return session.scalar(
        select(CoordinatorLeaseRow).where(CoordinatorLeaseRow.scan_id == scan_id).with_for_update()
    )


def acquire_lease(
    session: Session,
    *,
    scan_id: uuid.UUID,
    holder: str,
    ttl_seconds: int,
    now: datetime | None = None,
) -> Lease | None:
    """Take the lease, or return None if a live holder already has it.

    Taking over an expired or released lease **increments the fencing token**, which is
    what invalidates the previous holder's authority even if it is still running.
    """
    now = now or now_utc()
    row = _locked_lease(session, scan_id)

    if row is None:
        row = CoordinatorLeaseRow(
            scan_id=scan_id,
            holder=holder,
            fencing_token=1,
            acquired_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            released_at=None,
        )
        session.add(row)
        session.flush()
        return Lease(scan_id, holder, row.fencing_token, row.expires_at)

    still_held = row.released_at is None and now < row.expires_at
    if still_held and row.holder != holder:
        return None

    # Free, expired, or our own to renew into a fresh take-over.
    row.holder = holder
    row.fencing_token = row.fencing_token + 1
    row.acquired_at = now
    row.expires_at = now + timedelta(seconds=ttl_seconds)
    row.released_at = None
    session.flush()
    return Lease(scan_id, holder, row.fencing_token, row.expires_at)


def renew_lease(
    session: Session,
    *,
    scan_id: uuid.UUID,
    holder: str,
    fencing_token: int,
    ttl_seconds: int,
    now: datetime | None = None,
) -> Lease:
    """Extend the lease. Raises :class:`LeaseLost` if it is no longer ours to extend."""
    now = now or now_utc()
    row = _locked_lease(session, scan_id)

    if row is None:
        raise LeaseLost(f"scan {scan_id} has no lease to renew")
    if row.fencing_token != fencing_token:
        raise LeaseLost(
            f"scan {scan_id} lease fencing token moved from {fencing_token} to "
            f"{row.fencing_token}; this run has been superseded"
        )
    if row.holder != holder:
        raise LeaseLost(f"scan {scan_id} lease is held by {row.holder!r}, not {holder!r}")
    if row.released_at is not None:
        raise LeaseLost(f"scan {scan_id} lease was released")
    if now >= row.expires_at:
        raise LeaseLost(
            f"scan {scan_id} lease expired at {row.expires_at.isoformat()} and was not "
            "renewed in time"
        )

    row.expires_at = now + timedelta(seconds=ttl_seconds)
    session.flush()
    return Lease(scan_id, holder, row.fencing_token, row.expires_at)


def release_lease(
    session: Session,
    *,
    scan_id: uuid.UUID,
    holder: str,
    fencing_token: int,
    now: datetime | None = None,
) -> bool:
    """Voluntarily give up the lease. Returns False if it was no longer ours.

    Also bumps the token, so even a voluntary release invalidates the releasing run's
    remaining authority. A run that releases and then keeps acting is the same bug as a
    run that lost its lease and kept acting.
    """
    now = now or now_utc()
    row = _locked_lease(session, scan_id)
    if row is None or row.fencing_token != fencing_token or row.holder != holder:
        return False

    row.fencing_token = row.fencing_token + 1
    row.released_at = now
    row.expires_at = now
    session.flush()
    return True


def assert_lease_held(
    session: Session,
    *,
    scan_id: uuid.UUID,
    fencing_token: int,
    now: datetime | None = None,
) -> None:
    """Raise :class:`LeaseLost` unless ``fencing_token`` is the current, live token.

    This is the check every executor performs before touching the target. A stale token
    means the work this caller is about to do has already been reassigned.
    """
    now = now or now_utc()
    row = session.get(CoordinatorLeaseRow, scan_id)

    if row is None:
        raise LeaseLost(f"scan {scan_id} has no lease; refusing to act without one")
    if row.fencing_token != fencing_token:
        raise LeaseLost(
            f"stale fencing token for scan {scan_id}: presented {fencing_token}, "
            f"current is {row.fencing_token}"
        )
    if row.released_at is not None:
        raise LeaseLost(f"scan {scan_id} lease was released at {row.released_at.isoformat()}")
    if now >= row.expires_at:
        raise LeaseLost(f"scan {scan_id} lease expired at {row.expires_at.isoformat()}")


def expire_stale_leases(
    session: Session, *, now: datetime | None = None
) -> list[CoordinatorLeaseRow]:
    """Mark expired leases released and return them.

    Used by the reconciler. Releasing is what makes the next acquire take over cleanly
    and bump the token, so the previous holder's authority is retired even if its
    process is still alive somewhere.
    """
    now = now or now_utc()
    stale = list(
        session.scalars(
            select(CoordinatorLeaseRow).where(
                CoordinatorLeaseRow.released_at.is_(None),
                CoordinatorLeaseRow.expires_at <= now,
            )
        )
    )
    for row in stale:
        row.released_at = now
    session.flush()
    return stale


def lease_is_live(session: Session, scan_id: uuid.UUID, *, now: datetime | None = None) -> bool:
    """Whether a live, unreleased lease exists for the scan."""
    now = now or now_utc()
    row = session.get(CoordinatorLeaseRow, scan_id)
    return row is not None and row.released_at is None and now < row.expires_at


def scan_exists(session: Session, scan_id: uuid.UUID) -> bool:
    return session.get(ScanRow, scan_id) is not None
