"""Coordinator lease heartbeat (Build Plan §5.2, §5.6).

A lease that is only acquired and released is a lease that expires during any long run.
The scanner's work is bounded in minutes, not seconds, so the lease must be renewed while
the run is in progress.

The heartbeat is a background thread for one reason: the coordinator's foreground thread
is blocked waiting on a worker container, and a renewal that waits for the worker to
finish is not a renewal.

**When the heartbeat loses the lease, the coordinator must stop immediately.** Build Plan
§5.2 is specific about why: a replacement coordinator may already be running, so
continuing would put two runs on the same target, spending the same budget twice. The
heartbeat therefore does not merely log the loss — it sets a flag the coordinator checks,
and stops trying to renew.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from scopelens.config import Settings
from scopelens.execution.leases import Lease, LeaseLost, renew_lease
from scopelens.persistence.session import session_scope

logger = logging.getLogger(__name__)


@dataclass
class HeartbeatStatus:
    """What the heartbeat observed. Read by the coordinator after the worker returns."""

    renewals: int = 0
    lost: bool = False
    lost_reason: str = ""

    @property
    def healthy(self) -> bool:
        return not self.lost


class LeaseHeartbeat:
    """Renews a coordinator lease on an interval, in a daemon thread."""

    def __init__(
        self,
        settings: Settings,
        lease: Lease,
        *,
        interval_seconds: float | None = None,
    ) -> None:
        self._settings = settings
        self._lease = lease
        self._known_expiry = lease.expires_at
        self._last_error_class: str | None = None
        self._interval = interval_seconds or settings.lease_renew_interval_seconds
        self._status = HeartbeatStatus()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def status(self) -> HeartbeatStatus:
        return self._status

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name=f"lease-heartbeat-{self._lease.scan_id}", daemon=True
        )
        self._thread.start()

    def stop(self, *, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            if not self._renew_once():
                return

    def _renew_once(self) -> bool:
        """Renew once. Returns False when the heartbeat should stop."""
        attempt_at = datetime.now(UTC)
        started = time.monotonic()
        try:
            with session_scope(self._settings) as session:
                renewed = renew_lease(
                    session,
                    scan_id=self._lease.scan_id,
                    holder=self._lease.holder,
                    fencing_token=self._lease.fencing_token,
                    ttl_seconds=self._settings.lease_ttl_seconds,
                )
        except LeaseLost as exc:
            # Terminal for this run. Not retried: the lease is gone, and a retry loop
            # here would hammer the database while a replacement coordinator works.
            self._status.lost = True
            self._status.lost_reason = str(exc)
            if self._last_error_class is not None:
                self._status.lost_reason += f"; last renewal error: {self._last_error_class}"
            self._log_renewal(attempt_at, started, error_class=type(exc).__name__, lost=True)
            return False
        except Exception as exc:  # noqa: BLE001 - a transient DB error is not lease loss
            # A blip is not a loss of authority. Record it and keep renewing; if the
            # database stays down the lease will expire and the next `renew_lease` will
            # raise LeaseLost, which is the correct way to find out.
            self._last_error_class = type(exc).__name__
            self._status.lost_reason = f"transient renewal error: {self._last_error_class}"
            self._log_renewal(attempt_at, started, error_class=self._last_error_class)
            return True

        # Track only committed expiry for diagnostics; this grants no authority.
        self._known_expiry = renewed.expires_at
        self._log_renewal(attempt_at, started)
        self._status.renewals += 1
        return True

    def _log_renewal(
        self,
        attempt_at: datetime,
        started: float,
        *,
        error_class: str | None = None,
        lost: bool = False,
    ) -> None:
        duration = time.monotonic() - started
        if error_class is None and duration <= self._interval / 2:
            return
        remaining = (self._known_expiry - datetime.now(UTC)).total_seconds()
        fields = {
            "scan_id": str(self._lease.scan_id),
            "attempt_at": attempt_at.isoformat(),
            "duration_seconds": duration,
            "error_class": error_class,
            "remaining_ttl_seconds": remaining,
        }
        logger.log(
            logging.ERROR if lost else logging.WARNING,
            "heartbeat renewal scan_id=%s attempt_at=%s duration_seconds=%.3f "
            "error_class=%s remaining_ttl_seconds=%.3f",
            fields["scan_id"],
            fields["attempt_at"],
            duration,
            error_class,
            remaining,
            extra=fields,
        )

    def __enter__(self) -> LeaseHeartbeat:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


class NullHeartbeat:
    """A heartbeat that does nothing, for callers whose run cannot outlive the lease.

    Not a way to skip renewal silently: `LeaseHeartbeat` is the default everywhere, and
    this is only used where a caller has already bounded the run below the lease TTL.
    """

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        self.status = HeartbeatStatus()

    def start(self) -> None: ...

    def stop(self, *, timeout: float = 5.0) -> None: ...

    def __enter__(self) -> NullHeartbeat:
        return self

    def __exit__(self, *exc_info: object) -> None: ...


def holder_identity() -> str:
    """A stable-ish name for whoever holds the lease. Used in audit trails."""
    import os
    import socket

    return f"{socket.gethostname()}:{os.getpid()}"


def new_run_id() -> str:
    return uuid.uuid4().hex
