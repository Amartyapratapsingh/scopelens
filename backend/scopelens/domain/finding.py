"""Findings and deduplication (Build Plan §5.15, Spec §9.8).

Spec §9.8 governs the merge rule and it is deliberately conservative:

    Deduplicate by canonical control/root cause, affected component and remediation
    boundary. Two tools observing the same weakness count once. Independent weaknesses
    with different fixes count separately. Similar descriptions alone are insufficient
    to merge findings.

So the dedup key is **not** the title and **not** the category. It is the quadruple below,
and a finding carries every location and every source observation that fed it — merging must
never discard evidence. A merge that dropped a location would understate the affected surface,
which is the failure mode §9.8 is written against.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from scopelens.domain.check import Location
from scopelens.domain.enums import (
    Category,
    Confidence,
    EvidenceStatus,
    Severity,
)


class Finding(BaseModel):
    """One root cause, with every location and evidence reference behind it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    check_id: str
    canonical_control: str
    root_cause: str
    category: Category

    title: str
    severity: Severity
    evidence_status: EvidenceStatus
    confidence: Confidence
    confidence_reasons: tuple[str, ...] = ()

    locations: tuple[Location, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    detail: str = ""

    #: Lifecycle. ``open`` is the only state a fresh scan produces; the retest flow moves it.
    status: str = "open"
    retest_state: str | None = None

    @property
    def dedup_key(self) -> str:
        """The §9.8 merge key: canonical control/root cause + affected component + fix.

        ``root_cause`` is the canonical control's root cause, and the *component* is the
        check's canonical control string — which is what fixes to. Two observations of the
        same weakness from different sources produce the same key; two weaknesses with
        different remediation do not.
        """
        return f"{self.root_cause}|{self.canonical_control}"

    @property
    def is_confirmed(self) -> bool:
        return self.evidence_status is EvidenceStatus.CONFIRMED

    @property
    def is_unresolved_serious_candidate(self) -> bool:
        """Whether this holds the overall score at ``Verification pending`` (Spec §9.6).

        An unresolved *potential* finding at High or Critical does. A confirmed one does not
        hold the score — it deducts from it, and applies its cap.
        """
        return self.evidence_status is EvidenceStatus.POTENTIAL and self.severity in {
            Severity.CRITICAL,
            Severity.HIGH,
        }

    def location_keys(self) -> set[str]:
        return {location.key() for location in self.locations}


def finding_id(root_cause: str, canonical_control: str) -> str:
    """Stable id from the dedup key, so the same weakness keeps its identity across scans."""
    import hashlib

    return hashlib.sha256(f"{root_cause}|{canonical_control}".encode()).hexdigest()[:16]


class DedupResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    findings: tuple[Finding, ...]
    #: How many source findings were merged away, so a report can disclose it rather than
    #: presenting a merged count as if it were the number of observations.
    merged_away: int = 0

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts


def deduplicate(findings: list[Finding]) -> DedupResult:
    """Merge findings that share a root cause and remediation boundary.

    Locations and evidence references are **unioned**, never replaced: Spec §9.8 requires one
    deduction per root cause while retaining all affected locations and source evidence. When
    merged findings disagree on severity, the highest wins — Spec §9.5: *"For a root-cause
    group, deduct the highest evidence-supported severity among its unresolved instances."*
    """
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.dedup_key, []).append(finding)

    merged: list[Finding] = []
    merged_away = 0
    for members in groups.values():
        if len(members) == 1:
            merged.append(
                members[0].model_copy(
                    update={
                        "locations": tuple(
                            {loc.key(): loc for loc in members[0].locations}.values()
                        )
                    }
                )
            )
            continue

        merged_away += len(members) - 1
        primary = max(members, key=lambda f: (f.severity.deduction, f.confidence.value))

        locations: dict[str, Location] = {}
        for member in members:
            for location in member.locations:
                locations.setdefault(location.key(), location)

        evidence: list[str] = []
        for member in members:
            for ref in member.evidence_refs:
                if ref not in evidence:
                    evidence.append(ref)

        reasons: list[str] = []
        for member in members:
            for reason in member.confidence_reasons:
                if reason not in reasons:
                    reasons.append(reason)
        reasons.append(
            f"{len(members)} observation(s) of the same root cause were merged into one "
            "finding; every location and evidence reference is retained"
        )

        merged.append(
            primary.model_copy(
                update={
                    "locations": tuple(locations.values()),
                    "evidence_refs": tuple(evidence),
                    "confidence_reasons": tuple(reasons),
                }
            )
        )

    ranked = sorted(merged, key=lambda f: (-f.severity.deduction, f.root_cause))
    return DedupResult(findings=tuple(ranked), merged_away=merged_away)


def findings_from_outcomes(outcomes: list, registry) -> list[Finding]:  # type: ignore[no-untyped-def]
    """Turn conclusive and candidate control outcomes into findings.

    Only two shapes produce a finding: a ``CONFIRMED_ISSUE`` and an ``INCONCLUSIVE`` outcome
    that nevertheless carries locations — which is how a FLAG-stance candidate is represented.
    A pass, a block, an error and an N/A produce nothing, because none of them observed a
    weakness.

    Titles and root causes come from the registry so they cannot drift from the entry a
    finding is attributed to.
    """
    produced: list[Finding] = []
    for outcome in outcomes:
        if not outcome.locations or outcome.proposed_severity is None:
            continue
        if outcome.status.value not in {"confirmed_issue", "inconclusive"}:
            continue

        entry = registry.get(outcome.check_id)
        root_cause = entry.root_cause if entry else outcome.check_id
        title = entry.title if entry else outcome.canonical_control

        confidence, reasons = outcome.confidence()
        produced.append(
            Finding(
                id=finding_id(root_cause, outcome.canonical_control),
                check_id=outcome.check_id,
                canonical_control=outcome.canonical_control,
                root_cause=root_cause,
                category=outcome.category,
                title=title,
                severity=outcome.proposed_severity,
                evidence_status=outcome.evidence_status,
                confidence=confidence,
                confidence_reasons=reasons,
                locations=outcome.locations,
                evidence_refs=(outcome.proof.evidence_refs if outcome.proof else ()),
                detail=outcome.summary,
            )
        )
    # Separate approved input locations can require independent fixes. Never collapse
    # two vulnerable parameters merely because they share the same vulnerability class.
    expanded = []
    for finding in produced:
        entry = registry.get(finding.check_id)
        if entry and entry.availability.phase == "M4":
            for location in {loc.key(): loc for loc in finding.locations}.values():
                root = finding.root_cause + "|" + location.key()
                expanded.append(
                    finding.model_copy(
                        update={
                            "root_cause": root,
                            "id": finding_id(root, finding.canonical_control),
                            "locations": (location,),
                        }
                    )
                )
        else:
            expanded.append(finding)
    return expanded
