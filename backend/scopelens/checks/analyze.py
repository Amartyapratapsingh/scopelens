"""Analysis: collected artifacts to findings, coverage and a score (Build Plan §5.8, §5.15).

Runs in the trusted supervisor, after the worker has finished and its artifacts have been
stored as evidence. Everything here is a pure function of those artifacts plus the registry —
no target traffic, no clock, no model — which is what makes a score reproducible from a
stored scan.

Order matters and is deliberate:

1. **Rebuild the collected data** from the stored artifacts, not from anything the worker
   said about itself. The artifact is the capture; a summary is a claim about it.
2. **Measure TLS through the constrained lane.** The assessment lane is intercepted, so a
   certificate read through it would be the proxy's own.
3. **Run the controls**, then **deduplicate**, then **score**. Scoring reads findings, so it
   must run after dedup or a weakness observed twice would deduct twice.
4. **Persist every outcome**, including the inconclusive and blocked ones. Coverage is
   computed from them, and a control that did not run has to stay visible as unassessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from scopelens.checks.controls import CONTROLS
from scopelens.checks.engine import CheckContext, EngineResult, run_controls
from scopelens.config import Settings
from scopelens.domain.check import ControlOutcome
from scopelens.domain.collection import CollectedData, CollectedResponse, TLSMeasurement
from scopelens.domain.enums import ProfileName
from scopelens.domain.finding import Finding, deduplicate, findings_from_outcomes
from scopelens.domain.registry import CheckRegistry, load_registry
from scopelens.domain.surface import AttackSurfaceMap, EndpointRecord
from scopelens.persistence.models import (
    CheckOutcomeRow,
    CrawlSurfaceRow,
    FindingRow,
    ScanRow,
    ScoreSnapshotRow,
)
from scopelens.persistence.repositories import record_audit
from scopelens.scoring.score import ScoreSnapshot, score


@dataclass
class AnalysisResult:
    surface: AttackSurfaceMap
    engine: EngineResult
    findings: tuple[Finding, ...]
    merged_away: int
    snapshot: ScoreSnapshot
    tls_measurement: TLSMeasurement | None = None
    unreachable: dict[str, str] = field(default_factory=dict)

    @property
    def errors(self) -> tuple[str, ...]:
        return self.engine.errors


def surface_from_artifacts(artifacts: list[dict[str, Any]]) -> AttackSurfaceMap | None:
    for artifact in artifacts:
        if artifact.get("kind") == "surface" and isinstance(artifact.get("data"), dict):
            try:
                return AttackSurfaceMap.model_validate(artifact["data"])
            except Exception:  # noqa: BLE001 - a malformed artifact is a gap, not a crash
                return None
    return None


def responses_from_artifacts(artifacts: list[dict[str, Any]]) -> list[CollectedResponse]:
    collected: list[CollectedResponse] = []
    for artifact in artifacts:
        if artifact.get("kind") != "response" or not isinstance(artifact.get("data"), dict):
            continue
        try:
            collected.append(CollectedResponse.model_validate(artifact["data"]))
        except Exception:  # noqa: BLE001 - skip an unreadable record, keep the rest
            continue
    return collected


def unreachable_from_artifacts(artifacts: list[dict[str, Any]], *, origin: str) -> dict[str, str]:
    # Keep third-party dependency gaps in the browser report, without turning their
    # paths into missing routes on the assessed origin.
    def origin_key(url):
        parts = urlsplit(url)
        return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)

    target = origin_key(origin)
    unreachable = {}
    for artifact in artifacts:
        if artifact.get("kind") == "unreachable" and isinstance(artifact.get("data"), dict):
            unreachable.update({str(k): str(v) for k, v in artifact["data"].items()})
        if artifact.get("kind") == "browser_summary":
            for gap in artifact.get("data", {}).get("gaps", []):
                if gap.get("url") and origin_key(gap["url"]) == target:
                    unreachable[urlsplit(gap["url"]).path or "/"] = gap["reason"]
    return unreachable


def analyze(
    *,
    settings: Settings,
    session: Session,
    scan: ScanRow,
    artifacts: list[dict[str, Any]],
    evidence_refs: dict[str, str],
    tls_measurement: TLSMeasurement | None = None,
    registry: CheckRegistry | None = None,
    scan_interrupted: bool = False,
) -> AnalysisResult | None:
    """Run every control and produce findings, coverage and a score.

    Returns None when the crawl artifact is missing: without it there is nothing to assess,
    and inventing an empty surface would report a clean scan that never happened.
    """
    surface = surface_from_artifacts(artifacts)
    if surface is None:
        return None

    frozen = scan.assessment_plan or {}
    loaded = registry or (
        CheckRegistry.model_validate(frozen["registry"])
        if "registry" in frozen
        else load_registry(settings.checks_registry_dir)
    )
    profile = ProfileName(scan.profile)

    data = CollectedData(
        origin=surface.origin,
        scheme=scan.target_origin.split("://", 1)[0],
        host=urlsplit(scan.target_origin).hostname or "",
        port=_port_of(scan.target_origin),
        responses=tuple(
            r for r in responses_from_artifacts(artifacts) if r.route != "transport-http:/"
        ),
        tls=tls_measurement,
        unreachable=unreachable_from_artifacts(artifacts, origin=scan.target_origin),
        cleartext_probe=next(
            (
                CollectedResponse.model_validate(a["data"])
                for a in artifacts
                if a.get("kind") == "cleartext"
            ),
            None,
        ),
        transport_http_authorized=scan.scope_version.transport_http_port is not None,
    )

    sample = sorted(
        {r.route for r in data.responses}
        | set(data.unreachable)
        | {endpoint.route for endpoint in surface.endpoints}
    )
    scan.assessment_plan = {
        **frozen,
        "discovered_instances": sample,
        "capture_manifest_ref": evidence_refs.get("crawl"),
        "discovery_complete": not bool(surface.stats.stopped_by),
    }
    session.flush()
    browser_responses = [
        a["data"] for a in artifacts if a.get("kind") == "response" and a.get("source") == "browser"
    ]
    extra = [
        EndpointRecord(
            url=r["url"],
            route=r["route"],
            status=r["status"],
            content_type=r.get("content_type"),
            discovered_via="browser",
            depth=0,
        )
        for r in browser_responses
    ]
    if extra:
        surface = surface.model_copy(update={"endpoints": (*surface.endpoints, *extra)})
    scan.assessment_plan = {
        **scan.assessment_plan,
        "browser": next((a["data"] for a in artifacts if a.get("kind") == "browser_summary"), None),
    }
    controls = CONTROLS
    if profile.expanded:
        from scopelens.expansion.analysis import expansion_controls
        from scopelens.expansion.cleanup_history import cleanup_states_for_scan
        from scopelens.expansion.components import expanded_component_surface

        surface = expanded_component_surface(profile, surface, data.responses)
        cleanup_states = cleanup_states_for_scan(session, scan)
        expanded = expansion_controls(
            artifacts,
            scan.assessment_plan,
            loaded,
            trusted_refs=set(evidence_refs.values()),
            cleanup_states=cleanup_states,
        )
        if frozen.get("expansion_config"):
            from scopelens.callbacks.deployment import runtime_from_settings
            from scopelens.callbacks.integration import callback_controls
            from scopelens.domain.expansion import AssessmentConfiguration
            from scopelens.persistence.session import build_session_factory

            configuration = AssessmentConfiguration.model_validate(frozen["expansion_config"])
            if configuration.callback_recipes:
                from scopelens.checks.engine import Control

                runtime = runtime_from_settings(
                    settings, session_factory=build_session_factory(session.get_bind())
                )
                callback_outcomes = callback_controls(
                    runtime,
                    configuration,
                    owner_id=scan.operator_id,
                    scan_id=scan.id,
                    artifacts=artifacts,
                    trusted_refs=set(evidence_refs.values()),
                )
                expanded += tuple(
                    Control(check_id=row.check_id, evaluate=lambda context, value=row: value)
                    for row in callback_outcomes
                )
        scan.assessment_plan = {
            **scan.assessment_plan,
            "cleanup_status": [
                {"recipe_id": recipe_id, "state": state}
                for recipe_id, state in sorted(cleanup_states.items())
            ],
        }
        replaced = {c.check_id for c in expanded}
        controls = tuple(c for c in CONTROLS if c.check_id not in replaced) + expanded
    engine = run_controls(
        registry=loaded,
        controls=controls,
        context=CheckContext(
            data=data,
            surface=surface,
            profile=profile,
            evidence=evidence_refs,
            advisory_snapshot=frozen.get("advisories", {}),
            active_captures=[a for a in artifacts if a.get("kind") == "active_probe"],
        ),
    )

    produced = findings_from_outcomes(list(engine.outcomes), loaded)
    deduped = deduplicate(produced)

    mandatory = {entry.id for entry in loaded.for_profile(profile) if entry.mandatory}
    snapshot = score(
        outcomes=list(engine.outcomes),
        findings=list(deduped.findings),
        mandatory_controls=mandatory,
        scan_interrupted=scan_interrupted,
        profile_includes_active_pack=profile.includes_active_pack,
        control_weights={entry.id: entry.coverage_weight for entry in loaded.for_profile(profile)},
        profile=profile,
        planned_controls={entry.id: entry.category for entry in loaded.for_profile(profile)},
    )

    from scopelens.adapters.integration import integrate

    scanner_results, snapshot = integrate(artifacts, deduped.findings, snapshot)
    scan.assessment_plan = {**scan.assessment_plan, "scanner_results": scanner_results}

    _persist(
        session=session,
        scan=scan,
        surface=surface,
        engine=engine,
        findings=deduped.findings,
        snapshot=snapshot,
    )

    return AnalysisResult(
        surface=surface,
        engine=engine,
        findings=deduped.findings,
        merged_away=deduped.merged_away,
        snapshot=snapshot,
        tls_measurement=tls_measurement,
        unreachable=data.unreachable,
    )


def _persist(
    *,
    session: Session,
    scan: ScanRow,
    surface: AttackSurfaceMap,
    engine: EngineResult,
    findings: tuple[Finding, ...],
    snapshot: ScoreSnapshot,
) -> None:
    """Write the surface, every outcome, the findings and the score snapshot.

    Idempotent per scan: a re-run replaces the previous rows rather than stacking a second
    set, so a retried analysis cannot leave two contradictory verdicts for one scan.
    """
    from sqlalchemy import delete

    session.execute(delete(CheckOutcomeRow).where(CheckOutcomeRow.scan_id == scan.id))
    session.execute(delete(FindingRow).where(FindingRow.scan_id == scan.id))
    session.execute(delete(CrawlSurfaceRow).where(CrawlSurfaceRow.scan_id == scan.id))
    session.execute(delete(ScoreSnapshotRow).where(ScoreSnapshotRow.scan_id == scan.id))

    session.merge(
        CrawlSurfaceRow(
            scan_id=scan.id,
            origin=surface.origin,
            payload=surface.model_dump(mode="json"),
        )
    )

    for outcome in engine.outcomes:
        session.add(
            CheckOutcomeRow(
                scan_id=scan.id,
                check_id=outcome.check_id,
                canonical_control=outcome.canonical_control,
                category=outcome.category.value,
                status=outcome.status.value,
                summary=outcome.summary,
                na_reason=outcome.na_reason,
                payload=outcome.model_dump(mode="json"),
            )
        )

    import uuid
    from copy import deepcopy

    plan = deepcopy(scan.assessment_plan or {})
    for finding in findings:
        persisted_id = uuid.uuid5(scan.id, finding.id)
        all_refs = set(finding.evidence_refs)
        for tool in plan.get("scanner_results", []):
            for observation in tool["observations"]:
                if observation.get("finding_id") == finding.id:
                    observation["finding_id"] = str(persisted_id)
                    all_refs.update(observation["evidence_refs"])
        session.add(
            FindingRow(
                id=persisted_id,
                scan_id=scan.id,
                check_id=finding.check_id,
                canonical_control=finding.canonical_control,
                root_cause=finding.root_cause,
                dedup_key=finding.dedup_key,
                category=finding.category.value,
                title=finding.title,
                severity=finding.severity.value,
                evidence_status=finding.evidence_status.value,
                confidence=finding.confidence.value,
                confidence_reasons=list(finding.confidence_reasons),
                locations=[location.model_dump(mode="json") for location in finding.locations],
                evidence_refs=sorted(all_refs),
                detail=finding.detail,
                status=finding.status,
            )
        )

    scan.assessment_plan = plan
    session.add(
        ScoreSnapshotRow(
            scan_id=scan.id,
            score_version=snapshot.score_version,
            profile=scan.profile,
            verdict=snapshot.verdict,
            overall_score=snapshot.overall.score,
            coverage_percent=snapshot.coverage_percent,
            payload=_snapshot_payload(snapshot),
        )
    )
    scan.findings_count = len(findings)

    # Emitted last, so the dashboard's stream reports the verdict after the findings it
    # summarises rather than before them.
    record_audit(
        session,
        actor="analysis",
        action="score.ready",
        subject_type="scan",
        subject_id=str(scan.id),
        outcome=snapshot.overall.state.value,
        detail={
            "verdict": snapshot.verdict,
            "coverage_percent": round(snapshot.coverage_percent, 1),
            "status": scan.status,
            "finding_count": len(findings),
        },
    )
    session.flush()


def _snapshot_payload(snapshot: ScoreSnapshot) -> dict[str, Any]:
    """A JSON-serialisable view of the snapshot, including the arithmetic.

    Spec §9.10 requires the deductions and applied caps to be inspectable, so they are stored
    with the score rather than recomputed on read.
    """
    return {
        "score_version": snapshot.score_version,
        "verdict": snapshot.verdict,
        "coverage_percent": snapshot.coverage_percent,
        "overall": {
            "state": snapshot.overall.state.value,
            "score": snapshot.overall.score,
            "raw_score": snapshot.overall.raw_score,
            "caps_applied": list(snapshot.overall.caps_applied),
            "reason": snapshot.overall.reason,
            "label": snapshot.overall.label,
            "excluded_categories": [c.value for c in snapshot.overall.excluded_categories],
            "blocked_categories": [c.value for c in snapshot.overall.blocked_categories],
            "effective_weights": snapshot.overall.effective_weights,
        },
        "categories": [
            {
                "category": entry.category.value,
                "title": entry.category.title,
                "weight": entry.weight,
                "profile_excluded": entry.profile_excluded,
                "state": entry.state.value,
                "score": entry.score,
                "raw_score": entry.raw_score,
                "coverage_percent": entry.coverage_percent,
                "fully_assessed_weight": entry.fully_assessed_weight,
                "total_weight": entry.total_weight,
                "caps_applied": list(entry.caps_applied),
                "reason": entry.reason,
                "mandatory_unassessed": list(entry.mandatory_unassessed),
                "deductions": [
                    {
                        "root_cause": d.root_cause,
                        "severity": d.severity.value,
                        "points": d.points,
                        "finding_id": d.finding_id,
                        "locations": list(d.locations),
                    }
                    for d in entry.deductions
                ],
            }
            for entry in snapshot.categories
        ],
    }


def _port_of(origin: str) -> int:
    remainder = origin.split("://", 1)[-1]
    if ":" in remainder:
        try:
            return int(remainder.rsplit(":", 1)[1])
        except ValueError:
            return 443
    return 443 if origin.startswith("https") else 80


def outcomes_by_check(outcomes: list[ControlOutcome]) -> dict[str, ControlOutcome]:
    return {outcome.check_id: outcome for outcome in outcomes}
