"""Enumerations shared across the domain, API and persistence layers."""

from __future__ import annotations

import enum


class AuthorityDomain(enum.StrEnum):
    """Which authority domain a scope belongs to (Build Plan §5.1).

    This is chosen by the authenticated operator at registration and is immutable
    once a scan references the scope version. A URL or scan parameter can never
    promote a production scope into the lab domain.
    """

    PRODUCTION = "production"
    LAB = "lab"


class ScanStatus(enum.StrEnum):
    """Scan lifecycle (Project Specification §6).

    ``queued`` is the only status M0 can produce. The remaining states are declared
    so the ledger has one definition from the start, but nothing in M0 transitions
    out of ``queued`` — dispatch is M1.
    """

    QUEUED = "queued"
    RECON = "recon"
    PLANNING = "planning"
    TESTING = "testing"
    CONFIRMING = "confirming"
    REPORTING = "reporting"
    COMPLETED = "completed"
    COMPLETED_PARTIAL = "completed_partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL


_TERMINAL = frozenset(
    {
        ScanStatus.COMPLETED,
        ScanStatus.COMPLETED_PARTIAL,
        ScanStatus.FAILED,
        ScanStatus.CANCELLED,
    }
)


class ProfileName(enum.StrEnum):
    """Assessment profiles (Project Specification §10.3).

    ``external-configuration`` deliberately excludes the conditional active pack, so
    an injection/XSS score can never be derived from a scan run under it.
    """

    EXTERNAL_CONFIGURATION = "external-configuration"
    EXTERNAL_DAST = "external-dast"
    EXTERNAL_DISCOVERY_V2 = "external-discovery-v2"
    EXTERNAL_ACTIVE_V2 = "external-active-v2"
    AUTHENTICATED_API_V1 = "authenticated-api-v1"
    STAGING_STATEFUL_V1 = "staging-stateful-v1"

    @property
    def includes_active_pack(self) -> bool:
        return self in {
            ProfileName.EXTERNAL_DAST,
            ProfileName.EXTERNAL_ACTIVE_V2,
            ProfileName.AUTHENTICATED_API_V1,
            ProfileName.STAGING_STATEFUL_V1,
        }

    @property
    def expanded(self) -> bool:
        return self not in {ProfileName.EXTERNAL_CONFIGURATION, ProfileName.EXTERNAL_DAST}

    @property
    def report_title(self) -> str:
        if self.expanded:
            return {
                ProfileName.EXTERNAL_DISCOVERY_V2: "External discovery assessment v2",
                ProfileName.EXTERNAL_ACTIVE_V2: "External active assessment v2",
                ProfileName.AUTHENTICATED_API_V1: "Authenticated application/API assessment v1",
                ProfileName.STAGING_STATEFUL_V1: "Staging stateful assessment v1",
            }[self]
        if self is ProfileName.EXTERNAL_DAST:
            return "External configuration + conditional active assessment"
        return "External configuration assessment"


class ReviewState(enum.StrEnum):
    """Registry review state (Build Plan §5.19).

    Only ``ENABLED`` controls count as supported. Every control in M0 is
    ``EXPERIMENTAL``: registry entries exist, fixtures have not yet been run.
    """

    EXPERIMENTAL = "experimental"
    VALIDATED = "validated"
    ENABLED = "enabled"
    RETIRED = "retired"

    @property
    def counts_as_supported(self) -> bool:
        return self is ReviewState.ENABLED


class Severity(enum.StrEnum):
    """Confirmed severity, kept separate from evidence status and confidence (Spec §8.4).

    ``INFORMATIONAL`` is a severity tier, not a confidence tier — Spec §8.4 is explicit
    about that, because conflating them is how "we are not sure" turns into "this is fine".
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def deduction(self) -> int:
        """Points deducted per distinct root cause (Spec §9.6)."""
        return _DEDUCTIONS[self]

    @property
    def holds_overall_score(self) -> bool:
        """Whether an unresolved finding at this severity caps the overall score."""
        return self in {Severity.CRITICAL, Severity.HIGH}


_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 65,
    Severity.HIGH: 35,
    Severity.MEDIUM: 15,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 0,
}


class Confidence(enum.StrEnum):
    """How much weight the evidence carries, with reasons recorded alongside (Spec §8.4)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EvidenceStatus(enum.StrEnum):
    """Evidence status, kept separate from confidence and severity (Spec §8.4)."""

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INCONCLUSIVE = "inconclusive"


class ControlOutcome(enum.StrEnum):
    """Per-instance test outcome (Project Specification §9.7).

    Only ``PASS`` and ``CONFIRMED_ISSUE`` are conclusive assessed outcomes. Missing
    credentials, WAF denial, unreachable pages, unsupported technology, tool errors
    and exhausted budgets are never a pass or N/A.
    """

    NOT_STARTED = "not_started"
    RUNNING = "running"
    PASS = "pass"
    CONFIRMED_ISSUE = "confirmed_issue"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    ERROR = "error"
    NOT_TESTED = "not_tested"
    NOT_APPLICABLE = "not_applicable"

    @property
    def is_conclusive(self) -> bool:
        return self in {ControlOutcome.PASS, ControlOutcome.CONFIRMED_ISSUE}


class Category(enum.StrEnum):
    """Scoring categories with fixed profile weights (Project Specification §9.5).

    ``external_weight`` is None for categories outside the v1 external profile;
    those are displayed as ``Not assessed in this profile`` rather than scored.
    """

    C01_TRANSPORT = "C01"
    C02_SERVER_SESSION = "C02"
    C03_INJECTION = "C03"
    C04_BROWSER_CROSS_ORIGIN = "C04"
    C05_DATA_EXPOSURE = "C05"
    C06_COMPONENTS = "C06"
    C07_API = "C07"
    C08_AUTHENTICATION = "C08"
    C09_AUTHORIZATION = "C09"
    C10_FILE_HANDLING = "C10"
    C11_BUSINESS_RULES = "C11"
    C12_DOMAIN_ASSET = "C12"

    @property
    def title(self) -> str:
        return _CATEGORY_TITLES[self]

    @property
    def external_weight(self) -> int | None:
        """Fixed weight in the external unauthenticated v1 profile."""
        return _EXTERNAL_WEIGHTS.get(self)

    @property
    def in_external_profile(self) -> bool:
        return self in _EXTERNAL_WEIGHTS


_CATEGORY_TITLES: dict[Category, str] = {
    Category.C01_TRANSPORT: "Transport and encryption",
    Category.C02_SERVER_SESSION: "Server and session-cookie configuration",
    Category.C03_INJECTION: "Injection resistance",
    Category.C04_BROWSER_CROSS_ORIGIN: "Browser and cross-origin security",
    Category.C05_DATA_EXPOSURE: "Data exposure and privacy",
    Category.C06_COMPONENTS: "Components and dependency exposure",
    Category.C07_API: "API exposure and integration controls",
    Category.C08_AUTHENTICATION: "Authentication and session lifecycle",
    Category.C09_AUTHORIZATION: "Authorization and tenant isolation",
    Category.C10_FILE_HANDLING: "File handling and server-side request controls",
    Category.C11_BUSINESS_RULES: "Business rules, integrity and abuse controls",
    Category.C12_DOMAIN_ASSET: "Domain and asset lifecycle",
}

# Project Specification §9.5 — external unauthenticated v1 weights. These sum to 100
# and are frozen in score-v1.0; changing them creates a new score version.
_EXTERNAL_WEIGHTS: dict[Category, int] = {
    Category.C01_TRANSPORT: 15,
    Category.C02_SERVER_SESSION: 15,
    Category.C03_INJECTION: 20,
    Category.C04_BROWSER_CROSS_ORIGIN: 15,
    Category.C05_DATA_EXPOSURE: 15,
    Category.C06_COMPONENTS: 10,
    Category.C07_API: 10,
}
