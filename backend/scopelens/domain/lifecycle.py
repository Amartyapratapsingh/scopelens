"""Scan lifecycle transitions (Project Specification §6).

The legal-transition map lives here rather than being implied by whichever status an
endpoint happens to write. That matters because two of the terminal states mean very
different things: ``completed`` claims the assessment finished, while
``completed_partial`` records that a limit or a gap stopped it. Letting a caller move a
scan straight to ``completed`` after a budget exhaustion would be the single easiest way
to overstate a result.
"""

from __future__ import annotations

from scopelens.domain.enums import ScanStatus

#: Terminal states have no outgoing transitions.
TERMINAL = frozenset(
    {
        ScanStatus.COMPLETED,
        ScanStatus.COMPLETED_PARTIAL,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    }
)

#: Any non-terminal state may be interrupted. These are the edges almost every diagram
#: forgets, and the ones that actually happen: a scan is cancelled while testing, or
#: fails during recon.
_INTERRUPTIONS = frozenset({ScanStatus.FAILED, ScanStatus.CANCELLED, ScanStatus.COMPLETED_PARTIAL})

#: Forward progress.
#:
#: ``queued -> testing`` and ``testing -> completed`` exist because M1 runs a single
#: bounded read-only check and has no recon, planning or reporting phase. M2 inserts
#: those, at which point these edges stop being used — written down rather than implied,
#: so that "the reporting phase was skipped" is a visible, deliberate decision instead of
#: something a reader has to infer from a diagram that does not match the code.
_FORWARD: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.QUEUED: frozenset({ScanStatus.RECON, ScanStatus.TESTING}),
    ScanStatus.RECON: frozenset({ScanStatus.PLANNING}),
    ScanStatus.PLANNING: frozenset({ScanStatus.TESTING}),
    ScanStatus.TESTING: frozenset(
        {ScanStatus.CONFIRMING, ScanStatus.REPORTING, ScanStatus.COMPLETED}
    ),
    ScanStatus.CONFIRMING: frozenset({ScanStatus.REPORTING, ScanStatus.COMPLETED}),
    ScanStatus.REPORTING: frozenset({ScanStatus.COMPLETED}),
    ScanStatus.PAUSED: frozenset(
        {
            ScanStatus.RECON,
            ScanStatus.PLANNING,
            ScanStatus.TESTING,
            ScanStatus.CONFIRMING,
            ScanStatus.REPORTING,
        }
    ),
}


class IllegalTransition(RuntimeError):
    """Raised when a caller attempts a transition the lifecycle does not permit."""


def allowed_transitions(status: ScanStatus) -> frozenset[ScanStatus]:
    if status in TERMINAL:
        return frozenset()
    return _FORWARD.get(status, frozenset()) | _INTERRUPTIONS


def can_transition(current: ScanStatus, target: ScanStatus) -> bool:
    return target in allowed_transitions(current)


def assert_transition(current: ScanStatus, target: ScanStatus) -> None:
    if current is target:
        # Idempotent re-application is allowed: at-least-once dispatch means a handler
        # may legitimately run its terminal step twice.
        return
    if not can_transition(current, target):
        raise IllegalTransition(
            f"{current.value} -> {target.value} is not a legal transition; "
            f"allowed from {current.value}: {sorted(s.value for s in allowed_transitions(current))}"
        )


def is_terminal(status: ScanStatus) -> bool:
    return status in TERMINAL
