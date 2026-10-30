"""Task ledger records (Build Plan §5.2).

The state set is exactly the one §5.2 names: ``{planned, admitted, running, succeeded,
failed, outcome_unknown}``. Cancellation is deliberately **not** a task state — it is a
property of the scan, and a task cut short by cancellation resolves to ``failed`` (it
provably sent nothing) or ``outcome_unknown`` (a request may have reached the target).
Adding a `cancelled` state would blur the one distinction the ledger exists to make.
"""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from scopelens.domain.budget import BudgetUsage


class TaskState(enum.StrEnum):
    PLANNED = "planned"
    ADMITTED = "admitted"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    #: A request may have reached the target and its result was lost. Never blindly
    #: retried (Build Plan §5.6).
    OUTCOME_UNKNOWN = "outcome_unknown"

    @property
    def is_terminal(self) -> bool:
        return self in {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.OUTCOME_UNKNOWN}

    @property
    def is_live(self) -> bool:
        return self in {TaskState.ADMITTED, TaskState.RUNNING}


class TaskType(enum.StrEnum):
    """The kinds of work the M1 execution path can run.

    ``fetch_origin`` was M1's single bounded request: it proved the execution path. M2 adds
    ``crawl``, which is a real scan — it walks the site, and the deterministic checks run over
    what it collected. Scanner adapters and browsing are M3 and are not listed here until
    they exist.
    """

    FETCH_ORIGIN = "fetch_origin"
    CRAWL = "crawl"
    CLEANUP_RECOVERY_VERIFY = "cleanup_recovery_verify"


class TaskRecord(BaseModel):
    """One logical unit of work, with its attempt and fencing identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    scan_id: str

    #: Stable across retries — identifies the *work*, not an attempt at it.
    logical_id: str
    #: Changes on every dispatch. Distinguishes the third attempt from the first.
    attempt_id: str

    task_type: TaskType
    state: TaskState
    #: Monotonic fencing counter. An executor holding a stale token must refuse to act
    #: (§5.2). This is what makes "the old coordinator is still alive" survivable.
    lease_token: int = Field(ge=0)
    reserved_budget: BudgetUsage = Field(default_factory=BudgetUsage)
    spent_budget: BudgetUsage = Field(default_factory=BudgetUsage)

    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    outcome_reason: str | None = None

    @property
    def idempotency_key(self) -> str:
        """``(scan_id, logical_id, attempt intent)`` from Build Plan §5.2."""
        return f"{self.scan_id}:{self.logical_id}:{self.attempt_id}"


class OutboxEventRecord(BaseModel):
    """A dispatch record written in the same transaction as the scan and task (§5.2).

    The outbox exists so that "the scan was created" and "the scan will be dispatched"
    cannot disagree: either both rows commit or neither does.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: int
    topic: str
    payload: dict[str, object]
    created_at: datetime
    dispatched_at: datetime | None = None
    attempts: int = 0
    last_error: str | None = None


class CoordinatorLeaseRecord(BaseModel):
    """One renewable lease per scan, held by the coordinator driving its run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scan_id: str
    holder: str
    fencing_token: int = Field(ge=1)
    acquired_at: datetime
    expires_at: datetime
    released_at: datetime | None = None

    def is_expired(self, now: datetime) -> bool:
        return self.released_at is None and now >= self.expires_at

    def is_held(self, now: datetime) -> bool:
        return self.released_at is None and now < self.expires_at
