"""Additive public report contracts; unknown capability counts are not zero."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class PublicMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CapabilityCount(PublicMetadata):
    count: int | None = None
    names: list[str] = Field(default_factory=list)
    evidence_state: Literal["measured", "unknown", "frozen_inventory", "observed_lower_bound"]
    reason: str = ""


class Capabilities(PublicMetadata):
    version: str = "capabilities-v1"
    installed_tools: CapabilityCount
    executable_checks: CapabilityCount
    independently_qualified_families: CapabilityCount
    experimental_controls: CapabilityCount
    observed_tools: CapabilityCount
    limitations: list[str] = Field(default_factory=list)


class ReachCounts(PublicMetadata):
    planned: int = 0
    fully_assessed: int = 0
    blocked: int = 0
    error: int = 0
    unassessed: int = 0
    not_applicable: int = 0


class ReachGroup(ReachCounts):
    role_id: str | None = None
    route: str | None = None


class ReachGap(PublicMetadata):
    kind: str
    role_id: str | None = None
    route: str | None = None
    reason_code: str


class DiscoveredReach(PublicMetadata):
    routes: int = 0
    templates: int = 0
    inputs: int = 0
    roles: int = 0


class ReachSummary(ReachCounts):
    version: str = "reach-v1"
    profile: str
    evidence_state: Literal["frozen_plan", "legacy_outcomes_only"]
    discovered: DiscoveredReach
    groups: list[ReachGroup] = Field(default_factory=list)
    gaps: list[ReachGap] = Field(default_factory=list)
    out_of_profile_categories: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class MeasuredTool(PublicMetadata):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1)
    measured_version: str = Field(min_length=1)
    verification_ref: str = Field(min_length=1)
    image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    binary_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ImageBinding(PublicMetadata):
    model_config = ConfigDict(extra="forbid", strict=True)
    role: Literal["tool", "kali", "browser"]
    image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    architecture: str = Field(min_length=1)
    probe_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RuntimeControl(PublicMetadata):
    model_config = ConfigDict(extra="forbid", strict=True)
    control_id: str
    runtime_supported: bool
    prerequisites_satisfied: bool
    authority_admitted: bool
    verification_ref: str = Field(min_length=1)


class FamilyQualification(BaseModel):
    # The evaluator also supplies metrics, sample counts and intervals. Only its explicit
    # Boolean decision is consumed here; strings/numbers must not coerce into success.
    model_config = ConfigDict(extra="ignore", strict=True)
    qualified: bool


class QualificationMeasurement(BaseModel):
    """Required provenance and shape before reading a frozen evaluator result."""

    model_config = ConfigDict(extra="ignore", strict=True)
    version: Literal["qualification-v2"]
    partition: Literal["development", "validation", "holdout"]
    verification_ref: str = Field(min_length=1)
    curator_ref: str = Field(min_length=1)
    candidate_fingerprint: str = Field(min_length=1)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    registry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    image_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    frozen_before_run: bool
    contaminated: bool
    families: dict[str, FamilyQualification]


class CapabilitySnapshot(PublicMetadata):
    """Trusted producer contract. Public APIs must never accept this as operator input.

    qualification is the evaluation helper's result plus freeze/curator evidence. Consumers
    publish only names/counts; private measurement locations and authority details stay private.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal["capability-snapshot-v2"]
    profile: str
    scan_id: str = Field(min_length=1)
    scope_version_id: str = Field(min_length=1)
    candidate_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    registry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    image_bindings: list[ImageBinding] = Field(min_length=1)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verification_ref: str = Field(min_length=1)
    measured_at: str = Field(min_length=1)
    installation_complete: bool = False
    runtime_inventory_complete: bool = False
    installed_tools: list[MeasuredTool] = Field(default_factory=list)
    runtime_controls: list[RuntimeControl] = Field(default_factory=list)
    qualification: dict = Field(default_factory=dict)
