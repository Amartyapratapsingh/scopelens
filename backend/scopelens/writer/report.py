"""Report writer (Build Plan §5.16, Spec §9).

Produces the deliverable: a self-contained HTML report and a JSON export, both from the same
structured data.

The safety rules are enforced here rather than left to careful writing:

* **autoescape is on and there is no ``|safe`` anywhere.** Target-derived text reaches the
  template as data; a page that returned ``<script>`` must render as text.
* **Everything is redacted before it is rendered**, including the JSON export. A JSON file is
  a file a person opens, so it gets the same treatment as the HTML.
* **The empty state says what it is.** Spec §9.3: a scan that found nothing produces
  "No issues found in the checks that completed" together with coverage. It never says the
  site is secure, and the coverage number is printed next to the sentence so the claim cannot
  be read as broader than it is.
* **No weaponized payloads.** The prose comes from static per-control templates that describe
  the weakness and the fix; no exploit string is produced anywhere in this module.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session

from scopelens.domain.check import ControlOutcome, Location
from scopelens.domain.enums import Category
from scopelens.domain.finding import Finding
from scopelens.persistence.models import (
    CheckOutcomeRow,
    CrawlSurfaceRow,
    FindingRow,
    ScanRow,
    ScoreSnapshotRow,
)
from scopelens.scoring.score import (
    CATEGORY_WEIGHTS,
    MIN_COVERAGE_PERCENT,
    OUT_OF_PROFILE,
    OVERALL_LABEL,
)
from scopelens.security.redaction import redact
from scopelens.writer.plain_language import COPY, explain
from scopelens.writer.templates import text_for

TEMPLATE_DIR = Path(__file__).parent

EMPTY_STATE_SENTENCE = "No issues found in the checks that completed"

#: Printed immediately after the empty-state sentence so it cannot be read as a clean bill.
EMPTY_STATE_QUALIFIER = (
    "This is not a statement that the site is secure. It means the checks listed above "
    "completed without finding one of the weaknesses they look for, across the coverage "
    "shown."
)


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


def _finding_view(finding: Finding) -> dict[str, Any]:
    template = text_for(finding.check_id)
    return {
        "id": finding.id,
        "title": finding.title,
        "check_id": finding.check_id,
        "canonical_control": finding.canonical_control,
        "root_cause": finding.root_cause,
        "category": finding.category.value,
        "category_title": finding.category.title,
        "severity": finding.severity.value,
        "evidence_status": finding.evidence_status.value,
        "confidence": finding.confidence.value,
        "confidence_reasons": list(finding.confidence_reasons),
        "status": finding.status,
        "retest_state": finding.retest_state,
        "what": template.what,
        "why": template.why,
        "fix": template.fix,
        "references": list(template.references),
        "locations": [
            {
                "route": location.route,
                "parameter": location.parameter,
                "header": location.header,
                "detail": location.detail,
            }
            for location in finding.locations
        ],
        "evidence_refs": list(finding.evidence_refs),
        "detail": finding.detail,
        **(
            explain(
                finding.check_id,
                finding.evidence_status.value,
                [location.route for location in finding.locations],
            )
            or {}
        ),
    }


def _profile_metadata(
    categories: list[dict[str, Any]],
) -> tuple[dict[str, int], list[dict[str, str]]]:
    """Use frozen score metadata; retain defaults for reports predating snapshots."""
    if not categories:
        return (
            {category.value: weight for category, weight in CATEGORY_WEIGHTS.items()},
            [{"category": category.value, "title": category.title} for category in OUT_OF_PROFILE],
        )
    weights = {
        entry["category"]: entry["weight"] for entry in categories if entry.get("weight", 0) > 0
    }
    excluded = [
        {
            "category": entry["category"],
            "title": entry.get("title", entry["category"]),
        }
        for entry in categories
        if entry.get("profile_excluded", entry.get("weight", 0) == 0)
    ]
    return weights, excluded


def _assessment_summary(
    plan: dict[str, Any], outcomes: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Publish counts and identity declarations, never executable recipes or secrets."""
    config = plan.get("expansion_config")
    if not isinstance(config, dict):
        return None
    checks = []
    for outcome in sorted(outcomes, key=lambda item: item["check_id"]):
        required = set(outcome["required_instances"])
        completed = set(outcome["completed_instances"]) & required
        checks.append(
            {
                "check_id": outcome["check_id"],
                "status": outcome["status"],
                "required": len(required),
                "completed": len(completed),
                "missing": len(required - completed),
                "incomplete_reasons": outcome["incomplete_reasons"],
            }
        )
    return {
        "scope_note": (
            "Identities below were declared for this assessment; declaration does not prove "
            "successful login or complete role coverage. Counts describe planned control "
            "instances, not the percentage of all vulnerabilities found."
        ),
        "identities": [
            {"id": identity.get("id", ""), "role": identity.get("role", "")}
            for identity in config.get("identities", [])
            if isinstance(identity, dict)
        ],
        "checks": checks,
        "required": sum(check["required"] for check in checks),
        "completed": sum(check["completed"] for check in checks),
        "missing": sum(check["missing"] for check in checks),
        "cleanup": [
            {"recipe_id": row.get("recipe_id", ""), "state": row.get("state", "unknown")}
            for row in plan.get("cleanup_status", [])
            if isinstance(row, dict)
        ],
    }


def _capabilities(
    plan: dict[str, Any], profile: str, *, scan_id: str = "", scope_version_id: str = ""
) -> dict[str, Any]:
    """Only persisted measured snapshots establish installation or qualification."""
    from scopelens.domain.capabilities import (
        canonical_sha256,
        capability_inventory,
        snapshot_matches,
    )
    from scopelens.domain.enums import ProfileName
    from scopelens.domain.registry import CheckRegistry
    from scopelens.domain.report_metadata import (
        Capabilities,
        CapabilityCount,
        CapabilitySnapshot,
        QualificationMeasurement,
    )

    try:
        entries = CheckRegistry.model_validate(plan["registry"]).for_profile(ProfileName(profile))
    except (KeyError, ValueError, TypeError):
        entries = []
    try:
        snapshot = CapabilitySnapshot.model_validate(plan.get("capability_snapshot")).model_dump()
    except (ValueError, TypeError):
        snapshot = {}
    provenance = bool(
        snapshot
        and snapshot_matches(
            snapshot,
            plan,
            scan_id=scan_id,
            scope_version_id=scope_version_id,
            profile=profile,
        )
    )
    enabled = {entry.id for entry in entries if entry.is_supported}
    enabled_measurements = {item["control_id"] for item in snapshot.get("runtime_controls", [])}
    complete_controls = enabled_measurements == enabled
    runtime_controls = {
        item["control_id"]
        for item in snapshot.get("runtime_controls", [])
        if provenance
        and item.get("runtime_supported") is True
        and item.get("prerequisites_satisfied") is True
        and item.get("authority_admitted") is True
        and item.get("verification_ref")
        and item.get("control_id") in enabled
    }

    def count(key: str, known: bool, names_key: str) -> CapabilityCount:
        return CapabilityCount(
            count=measured[key]["count"] if known else None,
            names=measured[key][names_key] if known else [],
            evidence_state="measured" if known else "unknown",
            reason="Frozen measurement"
            if known
            else "No complete frozen measurement for this scan",
        )

    try:
        qualification = QualificationMeasurement.model_validate(
            snapshot.get("qualification", {})
        ).model_dump()
    except (ValueError, TypeError):
        qualification = {}
    qualified = bool(
        provenance
        and qualification
        and qualification["partition"] == "holdout"
        and qualification["frozen_before_run"] is True
        and qualification["contaminated"] is False
        and qualification["candidate_fingerprint"] == snapshot["candidate_fingerprint"]
        and qualification["registry_sha256"] == snapshot["registry_sha256"]
        and qualification["image_binding_sha256"] == canonical_sha256(snapshot["image_bindings"])
        and qualification["manifest_sha256"] == plan.get("capability_qualification_manifest_sha256")
        and qualification["verification_ref"]
        == plan.get("capability_qualification_verification_ref")
        and qualification["curator_ref"] == plan.get("capability_qualification_curator_ref")
    )
    measured = capability_inventory(
        installed_tools=snapshot.get("installed_tools", []) if provenance else [],
        executable_control_ids=list(runtime_controls),
        qualification=qualification if qualified else {},
    )
    observed = sorted(
        {
            row["tool"]
            for row in plan.get("scanner_results", [])
            if row.get("tool")
            and row.get("version")
            and row.get("output_hash")
            and row.get("state") in {"completed", "partial"}
        }
    )
    experimental = sorted(
        entry.id for entry in entries if entry.review_state.value == "experimental"
    )
    return Capabilities(
        installed_tools=count(
            "installed_tools",
            bool(provenance and snapshot.get("installation_complete") is True),
            "names",
        ),
        executable_checks=count(
            "executable_checks",
            bool(
                provenance
                and entries
                and complete_controls
                and snapshot.get("runtime_inventory_complete") is True
            ),
            "control_ids",
        ),
        independently_qualified_families=count(
            "independently_qualified_families", qualified, "families"
        ),
        experimental_controls=CapabilityCount(
            count=len(experimental) if entries else None,
            names=experimental,
            evidence_state="frozen_inventory" if entries else "unknown",
            reason="Registry inventory only; no execution or qualification claim",
        ),
        observed_tools=CapabilityCount(
            count=len(observed),
            names=observed,
            evidence_state="observed_lower_bound",
            reason="Tools with captured scanner results; not total installed tools",
        ),
        limitations=[
            "Tool, control and family counts measure different things. Template inventory does not establish family qualification.",
            "Counts do not estimate the percentage of all website vulnerabilities detected.",
        ],
    ).model_dump(mode="json")


def _reach_summary(
    plan: dict[str, Any],
    outcomes: list[dict[str, Any]],
    profile: str,
    out_of_profile: list[dict[str, str]],
) -> dict[str, Any]:
    """Count explicit planned instances; never infer unseen routes or successful identities."""
    from urllib.parse import urlsplit

    from scopelens.domain.report_metadata import (
        DiscoveredReach,
        ReachCounts,
        ReachGap,
        ReachGroup,
        ReachSummary,
    )

    def path(value: str) -> str | None:
        try:
            return urlsplit(value).path or None
        except ValueError:
            return None

    catalogue = plan.get("request_catalogue") or {}
    templates = {row["id"]: row for row in catalogue.get("templates", []) if row.get("id")}
    tasks = (plan.get("input_assessment_plan") or {}).get("tasks", [])
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for task in tasks:
        template = templates.get(task.get("template_id"), {})
        records[(task["control_id"], task["id"])] = {
            "role_id": template.get("role_id"),
            "route": path(template.get("route_template") or template.get("path", "")),
            "state": "blocked" if task.get("state") == "blocked" else "unassessed",
        }
    for outcome in outcomes:
        required = set(outcome.get("required_instances", [])) or {"__control__"}
        completed = set(outcome.get("completed_instances", []))
        for instance in required:
            record = records.setdefault(
                (outcome["check_id"], instance),
                {"role_id": None, "route": None, "state": "unassessed"},
            )
            if record["state"] == "blocked":
                continue
            status = outcome["status"]
            if (
                status == "not_applicable"
                and outcome.get("na_reason")
                and outcome.get("na_evidence_ref")
            ):
                record["state"] = "not_applicable"
            elif (
                status in {"pass", "confirmed_issue"}
                and outcome.get("evidence_refs")
                and (
                    instance in completed
                    or (instance == "__control__" and not outcome.get("incomplete_reasons"))
                )
            ):
                record["state"] = "fully_assessed"
            elif status in {"blocked", "error"}:
                record["state"] = status
    # Preserve missing frozen controls too. No instance list means one explicit control-level
    # placeholder, not a claim that all of that control's possible routes were discovered.
    from scopelens.domain.enums import ProfileName
    from scopelens.domain.registry import CheckRegistry

    try:
        entries = CheckRegistry.model_validate(plan["registry"]).for_profile(ProfileName(profile))
    except (KeyError, ValueError, TypeError):
        entries = []
    recorded_controls = {key[0] for key in records}
    for entry in entries:
        if entry.id not in recorded_controls:
            records[(entry.id, "__control__")] = {
                "role_id": None,
                "route": None,
                "state": "unassessed",
            }
    groups: dict[tuple[str | None, str | None], ReachGroup] = {}
    for record in records.values():
        key = (record["role_id"], record["route"])
        group = groups.setdefault(key, ReachGroup(role_id=key[0], route=key[1]))
        group.planned += 1
        setattr(group, record["state"], getattr(group, record["state"]) + 1)
    gaps = []
    for group in groups.values():
        if group.blocked or group.error or group.unassessed:
            gaps.append(
                ReachGap(
                    kind="completion",
                    role_id=group.role_id,
                    route=group.route,
                    reason_code="planned_instances_incomplete",
                )
            )
    planned_templates = {task.get("template_id") for task in tasks}
    for template_id, template in templates.items():
        if template_id not in planned_templates:
            gaps.append(
                ReachGap(
                    kind="route",
                    role_id=template.get("role_id"),
                    route=path(template.get("route_template") or template.get("path", "")),
                    reason_code="discovered_template_without_input_plan",
                )
            )
    declared = {
        identity.get("id")
        for identity in (plan.get("expansion_config") or {}).get("identities", [])
    }
    planned_roles = {group.role_id for group in groups.values()}
    gaps.extend(
        ReachGap(kind="role", role_id=role, reason_code="declared_identity_without_bound_instance")
        for role in sorted(declared - planned_roles - {None})
    )
    if catalogue.get("gaps"):
        gaps.append(ReachGap(kind="discovery", reason_code="discovery_has_recorded_gaps"))
    totals = {
        field: sum(getattr(group, field) for group in groups.values())
        for field in ReachCounts.model_fields
    }
    ordered_groups = sorted(groups.values(), key=lambda row: (row.role_id or "", row.route or ""))
    unique_gaps = {
        (gap.kind, gap.role_id or "", gap.route or "", gap.reason_code): gap for gap in gaps
    }
    return ReachSummary(
        **totals,
        profile=profile,
        evidence_state="frozen_plan"
        if plan.get("input_assessment_plan")
        else "legacy_outcomes_only",
        discovered=DiscoveredReach(
            routes=len(
                {path(t.get("route_template") or t.get("path", "")) for t in templates.values()}
                - {None}
            ),
            templates=len(templates),
            inputs=sum(len(t.get("inputs", [])) for t in templates.values()),
            roles=len({t.get("role_id") for t in templates.values()} - {None}),
        ),
        groups=ordered_groups,
        gaps=[unique_gaps[key] for key in sorted(unique_gaps)],
        out_of_profile_categories=sorted(row["category"] for row in out_of_profile),
        limitations=[
            "Counts cover recorded planned instances, not all site vulnerabilities or undiscovered routes.",
            "Legacy controls without instance lists contribute one control-level unit; unknown role/route stays null.",
            "Aggregate inconclusive results do not identify which missing instances were blocked or errored; these remain unassessed.",
            "Declared identities and discovered routes do not prove authenticated reach.",
        ],
    ).model_dump(mode="json")


def build_report(
    *,
    session: Session,
    scan: ScanRow,
) -> dict[str, Any]:
    """Assemble the structured report every output format is rendered from.

    Spec §9.3: reports are generated from structured finding data, not free text, so the same
    data can drive the dashboard, the export and future formats.
    """
    surface_row = session.get(CrawlSurfaceRow, scan.id)
    outcome_rows = session.query(CheckOutcomeRow).filter(CheckOutcomeRow.scan_id == scan.id).all()
    finding_rows = session.query(FindingRow).filter(FindingRow.scan_id == scan.id).all()
    snapshot_row = (
        session.query(ScoreSnapshotRow)
        .filter(ScoreSnapshotRow.scan_id == scan.id)
        .order_by(ScoreSnapshotRow.created_at.desc())
        .first()
    )

    findings = [_finding_from_row(row) for row in finding_rows]
    findings.sort(key=lambda f: (-f.severity.deduction, f.title))

    snapshot = snapshot_row.payload if snapshot_row else {}
    overall = snapshot.get("overall", {})
    categories = snapshot.get("categories", [])
    profile_weights, out_of_profile = _profile_metadata(categories)
    outcomes = [_outcome_view(row) for row in outcome_rows]

    from scopelens.adapters.scanners import omitted_active_controls, scanner_profile_view

    public_plan = dict(scan.assessment_plan or {})
    scanner_results = scanner_profile_view(public_plan.get("scanner_results", []), scan.profile)
    if "scanner_results" in public_plan:
        public_plan["scanner_results"] = scanner_results

    coverage = snapshot_row.coverage_percent if snapshot_row else 0.0
    verdict = snapshot_row.verdict if snapshot_row else "Not scored"

    return redact(
        {
            "schema_version": "scoplens-report-v1",
            "score_version": snapshot.get("score_version", "score-v1.0"),
            "profile": scan.profile,
            "overall_label": overall.get("label") or OVERALL_LABEL,
            "scan": {
                "id": str(scan.id),
                "target_origin": scan.target_origin,
                "status": scan.status,
                "status_reason": scan.status_reason,
                "created_at": _iso(scan.created_at),
                "started_at": _iso(scan.started_at),
                "finished_at": _iso(scan.finished_at),
                "scope_version_id": str(scan.scope_version_id),
            },
            "score": {
                "verdict": verdict,
                "score": snapshot_row.overall_score if snapshot_row else None,
                "coverage_percent": round(coverage, 1),
                "state": overall.get("state", "not_assessed"),
                "reason": overall.get("reason", ""),
                "caps_applied": overall.get("caps_applied", []),
                "excluded_categories": overall.get("excluded_categories", []),
                "blocked_categories": overall.get("blocked_categories", []),
                "effective_weights": overall.get("effective_weights", {}),
                "categories": categories,
                "out_of_profile_categories": out_of_profile,
                "minimum_coverage_percent": MIN_COVERAGE_PERCENT,
                "profile_weights": profile_weights,
            },
            "severity_counts": _severity_counts(findings),
            "findings": [
                {
                    **_finding_view(finding),
                    **{
                        k: v
                        for k, v in (scan.assessment_plan or {})
                        .get("report_prose", {})
                        .get(finding.id, {})
                        .items()
                        if k in {"what", "why", "fix"} and finding.check_id not in COPY
                    },
                }
                for finding in findings
            ],
            "empty_state": {
                "applies": not findings,
                "sentence": EMPTY_STATE_SENTENCE,
                "qualifier": EMPTY_STATE_QUALIFIER,
                "coverage_percent": round(coverage, 1),
            },
            "assessment_plan": {
                k: v
                for k, v in public_plan.items()
                if k
                not in {
                    "next_request_at",
                    "page_request_keys",
                    "expansion_config",
                    "related_origin_pins",
                    "expansion_capability_hash",
                    "capability_snapshot",
                    "capability_measurement",
                    "zap_active_grants",
                    "capability_candidate_fingerprint",
                    "capability_expected_images",
                    "capability_execution_plan",
                    "capability_qualification_manifest_sha256",
                    "capability_qualification_verification_ref",
                    "capability_qualification_curator_ref",
                    "request_catalogue",
                    "input_assessment_plan",
                    "assessment_plan_revisions",
                    "assessment_execution_claims",
                }
            },
            "scanner_results": scanner_results,
            "out_of_profile_controls": omitted_active_controls(scan.profile),
            "browser": (scan.assessment_plan or {}).get("browser"),
            "attack_surface": surface_row.payload if surface_row else {},
            "host_inventory": _host_inventory(
                surface_row, discovery=(scan.assessment_plan or {}).get("passive_host_discovery")
            ),
            "host_discovery": {
                k: v
                for k, v in (scan.assessment_plan or {})
                .get(
                    "passive_host_discovery",
                    {"state": "not_run", "coverage_notes": ["passive_discovery_not_run"]},
                )
                .items()
                if k != "hosts"
            },
            "check_outcomes": outcomes,
            "assessment_summary": _assessment_summary(scan.assessment_plan or {}, outcomes),
            "capabilities": _capabilities(
                scan.assessment_plan or {},
                scan.profile,
                scan_id=str(scan.id),
                scope_version_id=str(scan.scope_version_id),
            ),
            "reach": _reach_summary(
                scan.assessment_plan or {}, outcomes, scan.profile, out_of_profile
            ),
            "coverage": {
                "percent": round(coverage, 1),
                "gate_percent": MIN_COVERAGE_PERCENT,
                "met": coverage >= MIN_COVERAGE_PERCENT,
            },
            "generated_at": _iso(datetime.now(UTC)),
        }
    )


def _host_inventory(
    surface_row: CrawlSurfaceRow | None, *, discovery: dict | None = None
) -> list[dict[str, Any]]:
    """Every host the crawl saw, flagged tested or inventory-only (Spec §7.2)."""
    from scopelens.discovery.passive import merge_inventory

    if surface_row is None:
        return merge_inventory([], discovery)
    hosts = surface_row.payload.get("hosts", [])
    inventory = [
        {"host": host.get("host"), "role": host.get("role"), "evidence": host.get("evidence")}
        for host in hosts
    ]
    inventory.insert(
        0,
        {
            "host": urlsplit(surface_row.origin).hostname,
            "role": "primary",
            "evidence": "the registered scope origin; the only host actively tested in this profile",
        },
    )
    return merge_inventory(inventory, discovery)


def _outcome_view(row: CheckOutcomeRow) -> dict[str, Any]:
    payload = row.payload or {}
    return {
        "check_id": row.check_id,
        "canonical_control": row.canonical_control,
        "category": row.category,
        "status": row.status,
        "summary": row.summary,
        "na_reason": row.na_reason,
        "na_evidence_ref": payload.get("na_evidence_ref"),
        "required_instances": payload.get("required_instances", []),
        "completed_instances": payload.get("completed_instances", []),
        "incomplete_reasons": payload.get("incomplete_reasons", []),
        "evidence_refs": (payload.get("proof") or {}).get("evidence_refs", []),
        "is_conclusive": row.status in {"pass", "confirmed_issue"},
        "evidence_status": payload.get("proof", {}).get("status") if payload.get("proof") else None,
    }


def _finding_from_row(row: FindingRow) -> Finding:
    from scopelens.domain.enums import Confidence, EvidenceStatus, Severity

    return Finding(
        id=str(row.id),
        check_id=row.check_id,
        canonical_control=row.canonical_control,
        root_cause=row.root_cause,
        category=Category(row.category),
        title=row.title,
        severity=Severity(row.severity),
        evidence_status=EvidenceStatus(row.evidence_status),
        confidence=Confidence(row.confidence),
        confidence_reasons=tuple(row.confidence_reasons or ()),
        locations=tuple(Location.model_validate(item) for item in (row.locations or [])),
        evidence_refs=tuple(row.evidence_refs or ()),
        detail=row.detail,
        status=row.status,
        retest_state=row.retest_state,
    )


def render_json(report: dict[str, Any]) -> str:
    """The JSON export. Redaction already applied; escaping is the reader's JSON parser."""
    return json.dumps(report, indent=2, sort_keys=False, default=str)


def render_html(report: dict[str, Any]) -> str:
    """The self-contained HTML report.

    ``autoescape`` is on and the template uses no ``|safe``, so every value below is escaped
    by the environment rather than by the template remembering to.
    """
    template = _environment().get_template("report.html.j2")
    return template.render(report=report)


def write_reports(report: dict[str, Any], directory: Path) -> dict[str, Path]:
    """Write both formats into ``directory``. Returns the paths written."""
    directory.mkdir(parents=True, exist_ok=True)
    html_path = directory / "report.html"
    json_path = directory / "report.json"
    html_path.write_text(render_html(report), encoding="utf-8")
    json_path.write_text(render_json(report), encoding="utf-8")
    return {"html": html_path, "json": json_path}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def outcome_summary(outcomes: list[ControlOutcome]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.status.value] = counts.get(outcome.status.value, 0) + 1
    return counts
