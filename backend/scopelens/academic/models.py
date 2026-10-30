"""Public academic readiness contains no executable recipes or private labels."""

from typing import Literal
from uuid import UUID

from pydantic import Field

from scopelens.domain.assessment import Record
from scopelens.domain.report_metadata import ReachCounts


class ActorView(Record):
    id: str
    anonymous: bool
    probe_configured: bool
    login_configured: bool
    credential_reference_count: int = Field(ge=0)
    expired: bool
    identity_evidence: Literal["not_observed", "verified_probe", "failed_probe"]


class CaseView(Record):
    id: str
    kind: Literal["permission", "workflow", "session"]
    family: str
    actor_id: str
    owner_id: str | None = None
    resource_id: str | None = None
    expected_permission: Literal["allowed", "forbidden", "declared_session_policy"]
    control_id: str
    configuration_ready: bool
    blocked_reasons: tuple[str, ...] = ()
    admitted: bool = False
    execution: Literal["not_observed", "observed"] = "not_observed"
    proof: Literal["not_evaluated", "inconclusive", "pass", "confirmed_issue"] = "not_evaluated"
    baseline: Literal["not_observed", "verified"] = "not_observed"
    independent_readback: Literal["not_applicable", "not_proven", "proven"] = "not_applicable"
    restoration: Literal["not_applicable", "not_proven", "verified", "fenced"] = "not_applicable"
    resource_fenced: bool = False
    evidence_refs: tuple[UUID, ...] = ()
    unexecuted_reason: str | None = None


class CoverageView(Record):
    configured: int = Field(ge=0)
    ready: int = Field(ge=0)
    blocked: int = Field(ge=0)
    admitted: int = Field(ge=0)
    executed: int = Field(ge=0)
    proven: int = Field(ge=0)
    fully_assessed: int = Field(ge=0)
    confirmed_issues: int = Field(ge=0)


class FeatureView(Record):
    code: str
    configured_cases: int = Field(ge=0)
    reason_codes: tuple[str, ...] = ()


class CapabilityCounts(Record):
    installed_tools: int | None = None
    executable_checks: int | None = None
    independently_qualified_families: int | None = None
    experimental_controls: int | None = None
    observed_tools: int | None = None


class AcademicReadiness(Record):
    version: Literal["academic-readiness-v1"] = "academic-readiness-v1"
    revision: str
    configuration_id: UUID
    configuration_hash: str
    scope_version_id: UUID
    scan_id: UUID | None = None
    profile: str
    actors: tuple[ActorView, ...]
    cases: tuple[CaseView, ...]
    features: tuple[FeatureView, ...]
    coverage: CoverageView
    capabilities: CapabilityCounts | None = None
    reach: ReachCounts | None = None
    limitations: tuple[str, ...] = (
        "Readiness describes frozen declarations. It grants no execution authority.",
        "An admission claim does not prove execution. Only bound captures establish observed execution.",
        "Proof describes the designated case, not all academic records or all application vulnerabilities.",
        "Role labels and academic meanings are withheld. The operator must supply expected permissions.",
        "Expired credentials, session expiry transitions and role changes require fresh execution evidence.",
    )


class AgendaCase(Record):
    order: int = Field(ge=1)
    case: CaseView
    state: Literal["ready", "blocked"]
    baseline_purpose: Literal[
        "allowed_comparison", "forbidden_comparison", "protected_state_transition", "session_policy"
    ]
    priority: int = Field(ge=0, le=2)
    priority_reasons: tuple[str, ...] = ()
    recommendation: Literal[
        "review_declared_case",
        "resolve_declared_prerequisites",
        "review_confirmed_case",
        "complete_declared_case_proof",
    ]


class FollowupRecommendation(Record):
    case_id: str
    rank: int = Field(ge=1)
    reason: Literal["confirmed_case_review", "observed_case_missing_proof"]
    state: Literal["ready", "blocked"]
    blocked_reasons: tuple[str, ...] = ()
    executed: Literal[False] = False


class PlanBudget(Record):
    unit: Literal["declared_case"] = "declared_case"
    baseline_reserved: int = Field(ge=0)
    baseline_ready: int = Field(ge=0)
    baseline_blocked: int = Field(ge=0)
    followup_limit: int = Field(ge=0, le=20)
    followup_selected: int = Field(ge=0, le=20)
    followup_deferred: int = Field(ge=0)
    execution_budget_reserved: Literal[False] = False


class AcademicPlan(Record):
    version: Literal["academic-plan-v1"] = "academic-plan-v1"
    revision: str
    readiness_revision: str
    configuration_id: UUID
    configuration_hash: str
    scope_version_id: UUID
    scan_id: UUID | None = None
    profile: str
    agenda: tuple[AgendaCase, ...]
    followups: tuple[FollowupRecommendation, ...]
    budget: PlanBudget
    coverage: CoverageView
    features: tuple[FeatureView, ...]
    execution_authority: Literal[False] = False
    limitations: tuple[str, ...] = (
        "This agenda recommends review of declared cases. It dispatches no execution or retest.",
        "Baseline case reservations are presentation counts, not requests or execution budget grants.",
        "Optional follow-ups cannot remove baseline cases or change identities, resources or actions.",
        "Priority is a review order. Severity and findings remain determined by the existing proof evaluators.",
        "The fixed collector retains the frozen operator-declared execution order.",
        "Credential availability and fresh execution authority must be checked by existing admission gates.",
    )
