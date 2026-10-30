"""Check outcomes and proof results (Build Plan §5.8, §5.14).

A check observes; a proof rule decides. Keeping them as separate records is what makes
"never fabricate results" a structural property rather than a discipline:

* A :class:`ControlOutcome` records what a check *saw* and what it *proposes*. A proposed
  finding is a candidate, and its ``status`` cannot be ``CONFIRMED_ISSUE`` without a
  satisfied proof rule.
* A :class:`ProofResult` records whether the registered criteria were met **against trusted
  evidence**, and names the evidence. Build Plan §5.14 lists what is insufficient on its own
  — a scanner match, a screenshot, a process exit, a model's opinion — so ``reasons``
  carries the positive justification, not a restatement of the signal.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from scopelens.domain.enums import (
    Category,
    Confidence,
    EvidenceStatus,
    Severity,
)
from scopelens.domain.enums import ControlOutcome as OutcomeStatus


class Location(BaseModel):
    """Where an observation applies. Spec §9.7 scores a field against its own work."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    route: str = Field(min_length=1)
    parameter: str | None = None
    header: str | None = None
    detail: str = ""

    def key(self) -> str:
        """Stable identity for deduplication: route + the specific input or header."""
        return f"{self.route}|{self.parameter or ''}|{self.header or ''}"


class ProofResult(BaseModel):
    """The verdict of a registered proof rule against trusted evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    satisfied: bool
    status: EvidenceStatus
    reasons: tuple[str, ...] = ()
    #: Evidence record ids the proof rests on. Empty means the rule could not be satisfied,
    #: which is exactly what a missing artifact should produce.
    evidence_refs: tuple[str, ...] = ()

    @property
    def is_confirmed(self) -> bool:
        return self.satisfied and self.status is EvidenceStatus.CONFIRMED


class ControlOutcome(BaseModel):
    """What one check produced for one control.

    ``status`` is the §9.7 vocabulary. Only ``PASS`` and ``CONFIRMED_ISSUE`` are conclusive
    assessed outcomes; everything else leaves the control unassessed, which is why missing
    credentials, WAF blocks, tool errors and exhausted budgets can never flatter a score.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    check_id: str
    canonical_control: str
    category: Category
    status: OutcomeStatus
    summary: str = ""

    locations: tuple[Location, ...] = ()
    proposed_severity: Severity | None = None
    proof: ProofResult | None = None

    #: Required when the status is NOT_APPLICABLE: Spec §9.7 demands a recorded reason with
    #: evidence of absence. Failing to discover a feature is explicitly insufficient.
    na_reason: str | None = None
    na_evidence_ref: str | None = None
    required_instances: tuple[str, ...] = ()
    completed_instances: tuple[str, ...] = ()
    incomplete_reasons: tuple[str, ...] = ()

    @property
    def is_conclusive(self) -> bool:
        return self.status.is_conclusive

    @property
    def is_fully_assessed(self) -> bool:
        """Only conclusive outcomes with every required instance complete earn coverage."""
        return (
            self.status.is_conclusive
            and not self.incomplete_reasons
            and set(self.required_instances) <= set(self.completed_instances)
        )

    @property
    def evidence_status(self) -> EvidenceStatus:
        if self.proof is not None:
            return self.proof.status
        return EvidenceStatus.INCONCLUSIVE

    def confidence(self) -> tuple[Confidence, tuple[str, ...]]:
        """Confidence and its reasons, derived from the proof rather than asserted.

        A confirmed observation whose proof rule required two independent responses is
        better evidence than one that needed a single header, and this is where that
        difference shows up instead of being flattened into a single number.
        """
        if self.proof is None:
            return Confidence.LOW, ("no proof rule was evaluated",)
        if self.proof.is_confirmed:
            reasons = self.proof.reasons or ("the registered confirmation criteria were met",)
            return Confidence.HIGH, reasons
        if self.proof.status is EvidenceStatus.POTENTIAL:
            return Confidence.MEDIUM, self.proof.reasons or ("criteria were only partly met",)
        return Confidence.LOW, self.proof.reasons or ("the criteria were not met",)


def not_applicable(
    *, check_id: str, canonical_control: str, category: Category, reason: str, evidence_ref: str
) -> ControlOutcome:
    """Build an evidence-backed N/A. Both the reason and the evidence are mandatory."""
    return ControlOutcome(
        check_id=check_id,
        canonical_control=canonical_control,
        category=category,
        status=OutcomeStatus.NOT_APPLICABLE,
        summary=reason,
        na_reason=reason,
        na_evidence_ref=evidence_ref,
    )


def inconclusive(
    *, check_id: str, canonical_control: str, category: Category, reason: str
) -> ControlOutcome:
    """Build an inconclusive outcome.

    Used where the engine *could* have assessed the control but the data was not good
    enough — a truncated body, a route that was never reached. Distinct from ``error``,
    which means the check itself failed.
    """
    return ControlOutcome(
        check_id=check_id,
        canonical_control=canonical_control,
        category=category,
        status=OutcomeStatus.INCONCLUSIVE,
        summary=reason,
    )


def potential(
    *,
    check_id: str,
    canonical_control: str,
    category: Category,
    summary: str,
    proof: ProofResult,
    locations: tuple[Location, ...],
    severity: Severity,
) -> ControlOutcome:
    """A candidate that is not conclusively assessed.

    This is the shape a FLAG-stance control produces (Spec §10.5): something was observed
    worth keeping, but the class is not actively confirmed in the production profile. Its
    assessment status is ``INCONCLUSIVE`` — so it does not count toward coverage and cannot
    be mistaken for a completed check — while the finding stays visible as an unresolved
    candidate, and an unresolved Potential High/Critical holds the overall score at
    ``Verification pending`` (Spec §9.6).
    """
    return ControlOutcome(
        check_id=check_id,
        canonical_control=canonical_control,
        category=category,
        status=OutcomeStatus.INCONCLUSIVE,
        summary=summary,
        locations=locations,
        proposed_severity=severity,
        proof=proof,
    )


def blocked(
    *, check_id: str, canonical_control: str, category: Category, reason: str
) -> ControlOutcome:
    """The broker refused the request this control needed.

    Never a pass and never an N/A (Spec §9.7): the check did not run, so nothing is known.
    """
    return ControlOutcome(
        check_id=check_id,
        canonical_control=canonical_control,
        category=category,
        status=OutcomeStatus.BLOCKED,
        summary=reason,
    )
