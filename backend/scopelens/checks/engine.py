"""Check engine (Build Plan §5.8, §5.15).

Runs the registry's controls against collected data and enforces the invariants that make
"never fabricate results" structural:

* a ``CONFIRMED_ISSUE`` must carry a **satisfied** proof with at least one evidence
  reference — a check cannot assert a confirmation on its own authority
* a ``NOT_APPLICABLE`` must carry a recorded reason *and* the evidence of absence, because
  Spec §9.7 treats "we did not find the feature" as insufficient
* a ``PASS`` must not carry finding locations — a pass with locations is a contradiction,
  and it would let a real observation be filed as clean

These are checked in one place, on the way out, rather than trusted to each control. A
control with a bug gets an ``error`` outcome and fails the invariant check loudly, instead
of quietly producing a finding that nothing can justify.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from scopelens.domain.check import ControlOutcome
from scopelens.domain.collection import CollectedData
from scopelens.domain.enums import ControlOutcome as OutcomeStatus
from scopelens.domain.enums import EvidenceStatus, ProfileName
from scopelens.domain.registry import CheckRegistry, CheckRegistryEntry
from scopelens.domain.surface import AttackSurfaceMap


@dataclass(frozen=True)
class CheckContext:
    """Everything a control may read. No I/O, so every control is a pure function."""

    data: CollectedData
    surface: AttackSurfaceMap
    profile: ProfileName
    #: Maps a logical artifact name to the evidence record id the supervisor stored. Proof
    #: rules name what they rest on, so an empty bundle means nothing can be confirmed.
    evidence: dict[str, str]
    advisory_snapshot: dict[str, Any] = field(default_factory=dict)
    active_captures: list[dict] = field(default_factory=list)

    def evidence_ref(self, name: str) -> str | None:
        return self.evidence.get(name)

    @property
    def default_evidence_ref(self) -> str | None:
        for key in ("crawl", "responses", "fetch"):
            if ref := self.evidence.get(key):
                return ref
        return None


#: A control's evaluation. Declared as a callable so controls stay plain functions.
Evaluate = Callable[[CheckContext], ControlOutcome]


@dataclass(frozen=True)
class Control:
    """One implemented check, keyed by its registry id."""

    check_id: str
    evaluate: Evaluate


class ControlInvariantError(RuntimeError):
    """A control produced an outcome that violates the reporting rules."""


def validate_outcome(outcome: ControlOutcome) -> None:
    """Enforce the invariants. Raises rather than repairing: a bug must be visible."""
    if outcome.status is OutcomeStatus.CONFIRMED_ISSUE:
        if outcome.proof is None:
            raise ControlInvariantError(f"{outcome.check_id}: confirmed without a proof rule")
        if not outcome.proof.satisfied:
            raise ControlInvariantError(
                f"{outcome.check_id}: confirmed with an unsatisfied proof rule"
            )
        if not outcome.proof.evidence_refs:
            raise ControlInvariantError(
                f"{outcome.check_id}: confirmed without naming the evidence it rests on"
            )
        if outcome.proof.status is not EvidenceStatus.CONFIRMED:
            raise ControlInvariantError(
                f"{outcome.check_id}: confirmed with evidence status {outcome.proof.status.value!r}"
            )
        if not outcome.locations:
            raise ControlInvariantError(f"{outcome.check_id}: confirmed with no location")

    if outcome.status is OutcomeStatus.NOT_APPLICABLE:
        if not outcome.na_reason:
            raise ControlInvariantError(f"{outcome.check_id}: N/A without a recorded reason")
        if not outcome.na_evidence_ref:
            raise ControlInvariantError(f"{outcome.check_id}: N/A without evidence of absence")

    if outcome.status is OutcomeStatus.PASS and outcome.locations:
        raise ControlInvariantError(
            f"{outcome.check_id}: a pass carrying finding locations is a contradiction"
        )


@dataclass
class EngineResult:
    outcomes: tuple[ControlOutcome, ...]
    errors: tuple[str, ...] = ()

    def by_check(self) -> dict[str, ControlOutcome]:
        return {outcome.check_id: outcome for outcome in self.outcomes}


def run_controls(
    *,
    registry: CheckRegistry,
    controls: Iterable[Control],
    context: CheckContext,
) -> EngineResult:
    """Run every implemented control that the profile enables.

    A control in the registry with no implementation is **not** silently skipped: it yields
    an ``error`` outcome, because a planned control with no code is unassessed work and
    silently dropping it would raise coverage.
    """
    implemented = {control.check_id: control for control in controls}
    outcomes: list[ControlOutcome] = []
    errors: list[str] = []

    for entry in registry.for_profile(context.profile):
        outcome = _run_one(entry, implemented.get(entry.id), context, errors)
        if outcome is not None:
            outcomes.append(outcome)

    return EngineResult(outcomes=tuple(outcomes), errors=tuple(errors))


def _run_one(
    entry: CheckRegistryEntry,
    control: Control | None,
    context: CheckContext,
    errors: list[str],
) -> ControlOutcome | None:
    if control is None:
        errors.append(f"{entry.id}: planned in the registry but not implemented")
        return ControlOutcome(
            check_id=entry.id,
            canonical_control=entry.canonical_control,
            category=entry.category,
            status=OutcomeStatus.ERROR,
            summary="planned control has no implementation; it was not assessed",
        )

    try:
        outcome = control.evaluate(context)
    except Exception as exc:  # noqa: BLE001 - a broken control must not take the scan down
        errors.append(f"{entry.id}: {exc.__class__.__name__}: {exc}")
        return ControlOutcome(
            check_id=entry.id,
            canonical_control=entry.canonical_control,
            category=entry.category,
            status=OutcomeStatus.ERROR,
            summary=f"the check failed: {exc.__class__.__name__}",
        )

    try:
        outcome = _record_instances(outcome, context)
        validate_outcome(outcome)
    except ControlInvariantError as exc:
        errors.append(str(exc))
        return ControlOutcome(
            check_id=entry.id,
            canonical_control=entry.canonical_control,
            category=entry.category,
            status=OutcomeStatus.ERROR,
            summary=f"the check produced an invalid outcome and was discarded: {exc}",
        )

    return outcome


def _record_instances(outcome: ControlOutcome, context: CheckContext) -> ControlOutcome:
    """Retain the declared complete-crawl sample and every known gap in that sample."""
    is_tls = outcome.check_id == "SL-C01-TLS-01"
    is_redirect = outcome.check_id == "SL-C01-REDIR-01"
    ref = context.evidence_ref("tls" if is_tls else "cleartext" if is_redirect else "crawl")
    if outcome.status is OutcomeStatus.NOT_APPLICABLE:
        if outcome.na_evidence_ref not in context.evidence.values():
            raise ControlInvariantError(f"{outcome.check_id}: N/A references unknown evidence")
        return outcome
    if outcome.proof and any(
        r not in context.evidence.values() for r in outcome.proof.evidence_refs
    ):
        raise ControlInvariantError(f"{outcome.check_id}: proof references unknown evidence")
    if outcome.status.is_conclusive and not ref:
        raise ControlInvariantError(
            f"{outcome.check_id}: conclusive result has no captured evidence"
        )

    incomplete = list(outcome.incomplete_reasons)
    if is_tls or is_redirect:
        required = ("tls" if is_tls else "transport-http:/",)
        complete = required if outcome.status.is_conclusive and not incomplete else ()
    elif outcome.required_instances:
        required, complete = outcome.required_instances, outcome.completed_instances
    else:
        responses = [r for r in context.data.responses if r.route != "transport-http:/"]
        required = tuple(
            sorted(
                {r.route for r in responses}
                | set(context.data.unreachable)
                | {e.route for e in context.surface.endpoints}
            )
        )
        missing = set(required) - {r.route for r in responses}
        incomplete.extend(f"{route}: response capture missing" for route in sorted(missing))
        complete = tuple(
            sorted(
                {
                    r.route
                    for r in responses
                    if r.status not in {401, 403, 429}
                    and r.status < 500
                    and not r.truncated
                    and r.route not in context.data.unreachable
                }
            )
        )
        incomplete.extend(f"{path}: {reason}" for path, reason in context.data.unreachable.items())
        incomplete.extend(
            f"{r.route}: truncated or blocked response"
            for r in responses
            if r.truncated or r.status in {401, 403, 429} or r.status >= 500
        )
        if not responses:
            incomplete.append("No target response was collected")
        if context.surface.stats.stopped_by:
            incomplete.append(context.surface.stats.stopped_by)
    if outcome.status is OutcomeStatus.PASS and incomplete:
        outcome = outcome.model_copy(update={"status": OutcomeStatus.INCONCLUSIVE})
    proof = outcome.proof
    if proof is None and outcome.status is OutcomeStatus.PASS:
        from scopelens.domain.check import ProofResult

        proof = ProofResult(
            satisfied=False,
            status=EvidenceStatus.CONFIRMED,
            reasons=(outcome.summary,),
            evidence_refs=(ref,),
        )
    return outcome.model_copy(
        update={
            "required_instances": required,
            "completed_instances": complete,
            "incomplete_reasons": tuple(dict.fromkeys(incomplete)),
            "proof": proof,
        }
    )


def build_evidence_refs(records: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Turn ``(name, evidence_id)`` pairs into the bundle a context carries."""
    return {name: ref for name, ref in records}


def new_run_id() -> str:
    return uuid.uuid4().hex
