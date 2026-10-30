"""Budget accounting (Build Plan §5.2, §5.3; Project Specification §12).

Budgets are **reserved before execution and reconciled afterwards**, and spent budget
persists across recovery. That ordering matters: reserving after the fact would let a
crash lose the spend, and a lost spend is a budget that silently refills itself.

The ceilings are the pilot defaults from Project Specification §12. Note that the byte
cap is **per response**, not a running total — the spec sets a 1 MiB collection cap on
each response, and inventing a total-byte ceiling here would be adding a limit nobody
asked for. Total bytes are still *tracked*, for reporting.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from scopelens.config import Budgets


class BudgetUsage(BaseModel):
    """Counters for one scan. Immutable; produce new instances rather than mutating."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    requests: int = Field(default=0, ge=0)
    bytes: int = Field(default=0, ge=0)
    pages: int = Field(default=0, ge=0)
    redirects: int = Field(default=0, ge=0)

    def plus_requests(self, count: int = 1) -> BudgetUsage:
        return self.model_copy(update={"requests": self.requests + count})

    def plus_bytes(self, count: int) -> BudgetUsage:
        return self.model_copy(update={"bytes": self.bytes + count})

    def plus_pages(self, count: int = 1) -> BudgetUsage:
        return self.model_copy(update={"pages": self.pages + count})

    def plus_redirects(self, count: int = 1) -> BudgetUsage:
        return self.model_copy(update={"redirects": self.redirects + count})

    def minus(self, other: BudgetUsage) -> BudgetUsage:
        """Release a reservation that was never spent.

        Cannot go below zero: releasing more than was reserved would be a way to inflate
        the remaining budget, so it clamps instead.
        """
        return BudgetUsage(
            requests=max(0, self.requests - other.requests),
            bytes=max(0, self.bytes - other.bytes),
            pages=max(0, self.pages - other.pages),
            redirects=max(0, self.redirects - other.redirects),
        )

    def committed_with(self, other: BudgetUsage) -> BudgetUsage:
        return BudgetUsage(
            requests=self.requests + other.requests,
            bytes=self.bytes + other.bytes,
            pages=self.pages + other.pages,
            redirects=self.redirects + other.redirects,
        )


class BudgetLimits(BaseModel):
    """The ceilings in force for one scan, after any scope override."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_requests: int = Field(gt=0)
    max_pages: int = Field(gt=0)
    max_response_bytes: int = Field(gt=0)
    wall_clock_seconds: int = Field(gt=0)
    requests_per_second: float = Field(gt=0)
    max_in_flight: int = Field(gt=0)
    max_redirects_per_fetch: int = Field(gt=0)

    @classmethod
    def from_budgets(cls, budgets: Budgets) -> BudgetLimits:
        return cls(
            max_requests=budgets.max_total_requests,
            max_pages=budgets.max_pages,
            max_response_bytes=budgets.max_body_bytes,
            wall_clock_seconds=budgets.wall_clock_seconds,
            requests_per_second=budgets.requests_per_second,
            max_in_flight=budgets.max_in_flight,
            max_redirects_per_fetch=budgets.max_redirects_per_fetch,
        )


class BudgetExceeded(RuntimeError):
    """Raised when a reservation would exceed a ceiling.

    A *normal* outcome, not a defect: Build Plan §5.3 lists "exhausted budget" among the
    things that must never become a pass or an N/A (Project Specification §9.7). Callers
    record it as a blocked outcome.
    """


def check_reservation(
    *,
    spent: BudgetUsage,
    reserved: BudgetUsage,
    limits: BudgetLimits,
    requested: BudgetUsage | None = None,
) -> None:
    """Raise :class:`BudgetExceeded` if ``requested`` cannot be admitted.

    ``spent + reserved`` is the conservative baseline: work already admitted but not yet
    reconciled is counted as though it will consume its whole reservation. The proposed
    ``requested`` usage is then added, so the question answered is "does this specific
    reservation fit", not "has the ceiling already been passed" — the latter would let the
    final request of a budget through and only object afterwards.
    """
    requested = requested or BudgetUsage().plus_requests(1)
    committed = spent.committed_with(reserved)

    if committed.requests + requested.requests > limits.max_requests:
        raise BudgetExceeded(
            f"request budget exhausted: {committed.requests} already committed of "
            f"{limits.max_requests}, and {requested.requests} more were requested"
        )
    if committed.pages + requested.pages > limits.max_pages:
        raise BudgetExceeded(
            f"page budget exhausted: {committed.pages} already committed of "
            f"{limits.max_pages}, and {requested.pages} more were requested"
        )
    if committed.redirects + requested.redirects > limits.max_requests:
        raise BudgetExceeded(
            f"redirect budget exhausted: {committed.redirects} committed, "
            f"{requested.redirects} more requested"
        )
