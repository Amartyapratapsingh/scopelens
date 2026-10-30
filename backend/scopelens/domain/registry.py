"""Check-registry schema (Build Plan §5.19, Project Specification §10.3).

Every executable check is a registry entry. The schema exists so that a control
cannot be implemented without stating, up front, what it proves, what it is allowed
to do, what would make it wrong, and which fixtures demonstrate both directions.

Nothing in M0 evaluates a proof rule. The schema is defined here so the entries are
reviewable before any check code exists — which is the point of building the registry
before the checks.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scopelens.domain.enums import Category, ProfileName, ReviewState
from scopelens.domain.errors import DomainError

Stance = Literal["OBSERVE", "ACTIVE", "FLAG", "FIXTURE"]
"""Per-family confirmation stance (Project Specification §10.5).

OBSERVE  — may confirm a directly visible configuration/exposure without exercising an exploit.
ACTIVE   — reviewed bounded confirmation on an explicitly approved endpoint, after its gate.
FLAG     — detect and flag a candidate; do not actively confirm in the production profile.
FIXTURE  — later lab/staging or supplied-test-identity profile only.
"""


class StandardsMapping(BaseModel):
    """Versioned standard references.

    Fields are optional and may legitimately be empty. Per Project Specification §10.4
    a mapping is guidance, not a compliance claim, and an identifier that has not been
    checked is left blank rather than guessed (see docs/OPEN_QUESTIONS.md Q-4).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    owasp_top10_2025: tuple[str, ...] = ()
    wstg_v42: tuple[str, ...] = ()
    asvs_500: tuple[str, ...] = ()
    api_top10_2023: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    mapping_review: Literal["pending", "reviewed"] = "pending"


class Availability(BaseModel):
    """Which profiles may run this control, and from which milestone it exists."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    profiles: tuple[ProfileName, ...]
    phase: str = Field(min_length=1, description="Milestone that implements the check, e.g. 'M2'")
    stance: Stance
    family: str | None = Field(default=None, description="Catalogue family ID, e.g. 'F33'")

    @field_validator("profiles")
    @classmethod
    def _at_least_one_profile(cls, value: tuple[ProfileName, ...]) -> tuple[ProfileName, ...]:
        if not value:
            raise ValueError("a control must declare at least one profile")
        if len(set(value)) != len(value):
            raise ValueError("profiles must not repeat")
        return value

    @field_validator("family")
    @classmethod
    def _family_format(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"F\d{2}", value):
            raise ValueError(f"family must look like 'F33', got {value!r}")
        return value


class Applicability(BaseModel):
    """When the control applies, and the evidence that decides it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    description: str = Field(min_length=1)
    evidence_required: str = Field(min_length=1)
    not_applicable_when: str = Field(
        default="",
        description="An evidence-backed N/A needs a recorded reason; failing to discover a "
        "feature is insufficient (Project Specification §9.7).",
    )


class Prerequisites(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    credentials: str = "none"
    fixtures: str = "none"
    notes: str = ""


class AllowedAction(BaseModel):
    """What the control is permitted to do to the target (Build Plan §5.19).

    Defaults are the narrowest thing that works: same-origin, ``GET``/``HEAD``, one
    request. A control that needs more must say so explicitly.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    destinations: str = "scope origin only"
    methods: tuple[str, ...] = ("GET", "HEAD")
    max_requests: int = Field(default=1, ge=0)
    max_response_bytes: int = Field(default=1024 * 1024, ge=0)
    timeout_seconds: float = Field(default=10.0, gt=0)

    @model_validator(mode="after")
    def _methods_are_tokens(self) -> AllowedAction:
        for method in self.methods:
            if not method.isalpha() or method != method.upper():
                raise ValueError(f"method must be an uppercase HTTP token: {method!r}")
        return self


class SideEffects(BaseModel):
    """Expected impact, cleanup and the conditions that stop the check."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    expectation: str = Field(min_length=1)
    cleanup: str = "none required"
    stop_conditions: tuple[str, ...] = Field(min_length=1)


class Detection(BaseModel):
    """Signal, negative controls and the exact bar for confirmation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    signal: str = Field(min_length=1)
    negative_controls: tuple[str, ...] = Field(min_length=1)
    confirmation_criteria: str = Field(
        min_length=1,
        description="Exact criteria for `confirmed`. A scanner match, a screenshot, a process "
        "exit or a model's opinion is not sufficient on its own (Build Plan §5.14).",
    )
    false_positive_considerations: tuple[str, ...] = Field(min_length=1)


class Fixtures(BaseModel):
    """Vulnerable and fixed counterparts. Both are required before a control is enabled."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vulnerable: str = Field(min_length=1)
    fixed: str = Field(min_length=1)
    verified: bool = Field(
        default=False,
        description="True only once positive/negative behaviour has actually been observed. "
        "Never set this to claim completion.",
    )


class CheckRegistryEntry(BaseModel):
    """One executable check."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^SL-[A-Z0-9]{3}-[A-Z0-9]+-\d{2}$")
    title: str = Field(min_length=1)
    canonical_control: str = Field(
        min_length=1,
        description="Stable security requirement. Multiple tool templates may implement one "
        "control; a control is not a template or a request (Project Specification §9.7).",
    )
    root_cause: str = Field(min_length=1)
    category: Category
    standards: StandardsMapping = Field(default_factory=StandardsMapping)

    availability: Availability
    applicability: Applicability
    prerequisites: Prerequisites = Field(default_factory=Prerequisites)
    allowed_action: AllowedAction = Field(default_factory=AllowedAction)
    side_effects: SideEffects
    detection: Detection
    fixtures: Fixtures

    tool_version: str = Field(
        default="not applicable",
        description="Approved tool/configuration version, or 'not applicable' for a check "
        "implemented directly in Python.",
    )
    mandatory: bool = False
    coverage_weight: int = Field(default=1, ge=1)

    review_state: ReviewState = ReviewState.EXPERIMENTAL
    owner: str = Field(min_length=1)
    last_reviewed: date | None = None

    @model_validator(mode="after")
    def _review_consistency(self) -> CheckRegistryEntry:
        if self.review_state in {ReviewState.VALIDATED, ReviewState.ENABLED}:
            if not self.fixtures.verified:
                raise ValueError(
                    f"{self.id}: review_state={self.review_state.value} requires "
                    "fixtures.verified=true; a control cannot be promoted on unverified fixtures"
                )
            if self.standards.mapping_review != "reviewed":
                raise ValueError(
                    f"{self.id}: review_state={self.review_state.value} requires a reviewed "
                    "standards mapping"
                )
            if self.last_reviewed is None:
                raise ValueError(
                    f"{self.id}: review_state={self.review_state.value} requires last_reviewed"
                )
        return self

    @property
    def is_supported(self) -> bool:
        """Only ``enabled`` controls count as supported (Build Plan §5.19)."""
        return self.review_state.counts_as_supported

    @property
    def profiles(self) -> tuple[ProfileName, ...]:
        return self.availability.profiles


class CheckRegistry(BaseModel):
    """The loaded registry: every entry plus the profile definitions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "check-registry-v1"
    entries: tuple[CheckRegistryEntry, ...] = ()

    def get(self, check_id: str) -> CheckRegistryEntry | None:
        for entry in self.entries:
            if entry.id == check_id:
                return entry
        return None

    def for_profile(self, profile: ProfileName) -> list[CheckRegistryEntry]:
        base = (
            (
                ProfileName.EXTERNAL_DAST
                if profile.includes_active_pack
                else ProfileName.EXTERNAL_CONFIGURATION
            )
            if profile.expanded
            else profile
        )
        return [
            entry for entry in self.entries if profile in entry.profiles or base in entry.profiles
        ]

    def supported_for_profile(self, profile: ProfileName) -> list[CheckRegistryEntry]:
        return [entry for entry in self.for_profile(profile) if entry.is_supported]

    def duplicate_ids(self) -> list[str]:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for entry in self.entries:
            if entry.id in seen:
                duplicates.add(entry.id)
            seen.add(entry.id)
        return sorted(duplicates)


class RegistryError(DomainError):
    """Raised when the registry on disk is invalid."""


def load_registry(directory: Path) -> CheckRegistry:
    """Load every ``controls/*.yaml`` entry under ``directory``.

    Fails loudly on an invalid entry. A silently-skipped control would be counted as
    unsupported while appearing present, which is exactly the kind of quiet scope
    reduction Build Plan §7 forbids.
    """
    controls_dir = directory / "controls"
    if not controls_dir.is_dir():
        raise RegistryError(f"no controls directory at {controls_dir}")

    entries: list[CheckRegistryEntry] = []
    errors: list[str] = []
    paths = list(controls_dir.glob("*.yaml"))
    paths += list((directory / "tooling" / "expansion").glob("SL-*.yaml"))
    paths += list((directory / "tooling" / "identity").glob("*.yaml"))
    paths += list((directory / "tooling" / "discovery").glob("*.yaml"))
    paths += list((directory / "tooling" / "workflows").glob("*.yaml"))
    for path in sorted(paths):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise RegistryError("top level must be a YAML mapping")
            entries.append(CheckRegistryEntry.model_validate(raw))
        except Exception as exc:  # noqa: BLE001 - re-raised with file context
            errors.append(f"{path.name}: {exc}")

    if errors:
        raise RegistryError("invalid registry entries:\n  " + "\n  ".join(errors))

    registry = CheckRegistry(entries=tuple(entries))
    if duplicates := registry.duplicate_ids():
        raise RegistryError(f"duplicate control ids: {duplicates}")
    return registry
