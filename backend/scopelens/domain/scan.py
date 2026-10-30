"""Scan records (Project Specification §6, Build Plan §5.1).

M0 can only ever produce a ``queued`` scan. The record exists so that the ledger has
one definition from the start; the states it may legally reach are declared here so
that M1 does not redefine them.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from scopelens.domain.enums import ProfileName, ScanStatus


class ScanCreateRequest(BaseModel):
    """Operator request to start a scan.

    The target is *not* a parameter: it comes from the referenced ``ScopeVersion``.
    This is what stops a scan request from naming an origin the operator never
    authorized (Build Plan §5.1).
    """

    model_config = ConfigDict(extra="forbid")

    scope_version_id: str = Field(min_length=1)
    adaptive: bool | None = None
    assessment_configuration_id: str | None = None


class ScanRecord(BaseModel):
    """A durable scan intent / run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    operator_id: str
    scope_version_id: str
    target_origin: str
    profile: ProfileName
    score_version: str
    status: ScanStatus
    status_reason: str | None = None
    progress_percent: int = Field(default=0, ge=0, le=100)
    findings_count: int = Field(default=0, ge=0)
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None


# ``Scan`` is the name used for this record in Build Plan §4.
Scan = ScanRecord


class ExecutionState(BaseModel):
    """Why a queued scan is not running.

    One definition, returned alongside every scan and by the system endpoint, so the
    dashboard never has to interpret a permanently queued scan as a bug or as progress.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    execution: str
    execution_enabled: bool
    dispatch_implemented: bool
    responsible_milestone: str
    detail: str

    @property
    def is_disabled(self) -> bool:
        return self.execution == "disabled_m0"
