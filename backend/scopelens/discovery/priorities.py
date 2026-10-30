"""Evidence-based host triage. Recommendations never grant execution authority."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from scopelens.discovery.host_metadata import HostDiscoveryCoverage, HostMetadata
from scopelens.domain.assessment import stable_id


class Signal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    explanation: str
    scan_id: str | None = None


class NextStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    description: str
    readiness: Literal["ready_to_plan", "needs_review", "needs_test_accounts"]


class HostPriority(HostMetadata):
    model_config = ConfigDict(extra="forbid")
    host: str
    role: str = "inventory_only"
    owned_domain_match: bool
    priority: Literal["focus", "standard", "inventory_only"]
    rank_points: int = Field(ge=0, le=100)
    evidence_level: Literal["observed", "name_hint_only", "unassessed"]
    latest_scan_id: str | None = None
    latest_scan_status: str | None = None
    signals: list[Signal] = Field(default_factory=list)
    next_steps: list[NextStep] = Field(default_factory=list)


class HostPriorityPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "host-priority-v1"
    revision: str
    owned_domains: list[str]
    hosts: list[HostPriority]
    discovery: HostDiscoveryCoverage = Field(default_factory=HostDiscoveryCoverage)
    ordering: str = "Evidence first; every owned host remains in the assessment queue."
    limitation: str = (
        "Priority is an investigation order, not a vulnerability score or scan authorization. "
        "New scans still require their own scope and reviewed actions."
    )


def normalized_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def within_owned_domain(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == root or host.endswith("." + root) for root in domains)


def prioritize_hosts(
    inventory: list[dict],
    reports: dict[str, dict],
    *,
    owned_domains: tuple[str, ...],
    discovery: dict | None = None,
):
    """Rank known hosts from structured observations; page instructions have no authority.

    The caller supplies only owner-visible reports, newest per host. Unknown hosts retain
    a discovery task rather than being classified as low-risk or omitted. Name hints have
    deliberately less influence than a single observed application feature.
    """
    roots = tuple(sorted({normalized_host(root) for root in owned_domains if root.strip()}))
    hosts = sorted({normalized_host(str(row.get("host", ""))) for row in inventory} - {""})
    metadata = {normalized_host(str(row.get("host", ""))): row for row in inventory}
    ranked = []
    for host in hosts:
        owned = within_owned_domain(host, roots)
        row = HostPriority(
            host=host,
            owned_domain_match=owned,
            priority="standard" if owned else "inventory_only",
            rank_points=0,
            evidence_level="unassessed",
            role=metadata[host].get("role", "inventory_only"),
            **HostMetadata.model_validate(metadata[host]).model_dump(),
        )
        if not owned:
            row.signals.append(
                Signal(
                    code="ownership_not_configured",
                    explanation="Outside the explicitly configured owned domains; retain as inventory only.",
                )
            )
            ranked.append(row)
            continue
        report = reports.get(host)
        if (
            report
            and normalized_host(
                urlsplit(report.get("scan", {}).get("target_origin", "")).hostname or ""
            )
            != host
        ):
            raise ValueError("report host does not match inventory host")
        # A small clue can prioritize the first discovery pass, never an exploit claim.
        labels = set(host.split("."))
        if labels & {"portal", "student", "staff", "api", "admin", "apply", "payment", "payments"}:
            row.rank_points += 3
            row.evidence_level = "name_hint_only"
            row.signals.append(
                Signal(
                    code="application_name_hint",
                    explanation="The hostname suggests an application; this is unverified until discovery.",
                )
            )
        if not report:
            row.rank_points += 20
            row.signals.append(
                Signal(
                    code="not_assessed",
                    explanation="No completed assessment is available; exposure is unknown.",
                )
            )
            row.next_steps.append(
                NextStep(
                    code="public_discovery",
                    description="Map public routes, forms, parameters and dependencies in a separately scoped scan.",
                    readiness="ready_to_plan",
                )
            )
        else:
            scan = report.get("scan", {})
            sid = str(scan.get("id") or scan.get("scan_id") or "") or None
            row.latest_scan_id, row.latest_scan_status = sid, scan.get("status")
            row.evidence_level = "observed"
            surface = report.get("attack_surface") or {}
            forms = surface.get("forms") or []
            parameters = surface.get("parameters") or []
            endpoints = surface.get("endpoints") or []

            def signal(code, explanation, points, *, row=row, sid=sid):
                row.signals.append(Signal(code=code, explanation=explanation, scan_id=sid))
                row.rank_points += points

            if forms:
                signal(
                    "observed_forms",
                    f"{len(forms)} forms recorded. Their existence does not prove a vulnerability.",
                    20,
                )
            if parameters:
                signal(
                    "observed_inputs",
                    f"{len(parameters)} input locations recorded for applicability review.",
                    15,
                )
            classification = surface.get("classification") or {}
            if any(classification.get(k) for k in ("has_rest_api", "has_openapi", "has_graphql")):
                signal(
                    "observed_api",
                    "API signals recorded; map operations and their permission boundaries.",
                    15,
                )
            credential_form = any(
                any(
                    str(field.get("input_type", "")).lower() == "password"
                    for field in form.get("inputs", [])
                )
                for form in forms
            )
            if credential_form:
                signal(
                    "login_boundary",
                    "A password form was observed; logged-in coverage needs dedicated test identities.",
                    10,
                )
                row.next_steps.append(
                    NextStep(
                        code="identity_workflows",
                        description="Assess student/staff access boundaries using approved test accounts and disposable records.",
                        readiness="needs_test_accounts",
                    )
                )
            if forms or parameters or classification.get("has_rest_api"):
                row.next_steps.append(
                    NextStep(
                        code="input_plan",
                        description="Match observed inputs to reviewed controls, negative controls and proof rules; classify side effects before execution.",
                        readiness="needs_review",
                    )
                )
            browser = report.get("browser") or {}
            if browser.get("status") in {"incomplete", "failed"}:
                signal(
                    "browser_gap",
                    "Browser exploration did not complete; repair capture before drawing workflow conclusions.",
                    15,
                )
                row.next_steps.insert(
                    0,
                    NextStep(
                        code="browser_recovery",
                        description="Reproduce the browser failure locally, repair it, then repeat the approved exploration.",
                        readiness="ready_to_plan",
                    ),
                )
            if (surface.get("stats") or {}).get("stopped_by"):
                signal(
                    "discovery_limit",
                    "The previous crawl stopped at a recorded limit; unexplored routes remain.",
                    10,
                )
                row.next_steps.append(
                    NextStep(
                        code="extend_discovery",
                        description="Plan another bounded discovery pass over the remaining routes without repeating completed work.",
                        readiness="ready_to_plan",
                    )
                )
            if any(
                f.get("check_id") == "SL-C06-COMPONENT-01"
                and f.get("evidence_status") != "confirmed"
                for f in report.get("findings", [])
            ):
                signal(
                    "advisory_candidate",
                    "A component advisory candidate needs exact-build and affected-path verification.",
                    8,
                )
                row.next_steps.append(
                    NextStep(
                        code="verify_component",
                        description="Corroborate the component build and affected usage against the advisory; a version match alone cannot confirm exploitability.",
                        readiness="needs_review",
                    )
                )
            if any(f.get("severity") in {"high", "critical"} for f in report.get("findings", [])):
                signal(
                    "serious_observation",
                    "A High/Critical observation needs proof review and remediation triage; its confirmation state stays unchanged.",
                    20,
                )
            if not endpoints:
                signal(
                    "missing_surface",
                    "No endpoint inventory is available; a failed scan cannot imply low risk.",
                    20,
                )
                row.next_steps.append(
                    NextStep(
                        code="public_discovery",
                        description="Recover public discovery before assessing application coverage.",
                        readiness="ready_to_plan",
                    )
                )
            if not row.next_steps:
                row.next_steps.append(
                    NextStep(
                        code="coverage_review",
                        description="Review unassessed controls and select the next applicable check; completed baseline checks do not establish full security.",
                        readiness="needs_review",
                    )
                )
            row.rank_points += 10
        row.rank_points = min(100, row.rank_points)
        row.priority = "focus" if row.rank_points >= 40 else "standard"
        ranked.append(row)
    ranked.sort(key=lambda row: (not row.owned_domain_match, -row.rank_points, row.host))
    coverage = HostDiscoveryCoverage.model_validate(
        {k: v for k, v in (discovery or {}).items() if k != "hosts"}
    )
    identity = {
        "version": "host-priority-v1",
        "owned_domains": roots,
        "discovery": coverage.model_dump(mode="json"),
        "hosts": [r.model_dump(mode="json") for r in ranked],
    }
    return HostPriorityPlan(
        revision=stable_id(identity), owned_domains=list(roots), hosts=ranked, discovery=coverage
    )
