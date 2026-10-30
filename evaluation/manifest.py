"""Evaluation records (Implementation Plan §15.4, Build Plan §7).

**Schema and examples only.** There is no runner, no matcher and no benchmark result in
M0 — those are M4 (development/validation comparison) and M5 (frozen held-out
evaluation). Anything in this package that looked like a measurement would be a
fabricated result.

This code is deliberately **outside** the ``scopelens`` application package. Evaluation
labels are an answer key: Build Plan §7 requires that ground-truth and answer-key
interfaces are never reachable by scanner workers or model context, and keeping the
package boundary physical rather than procedural makes that harder to get wrong.

Conventions used throughout:

* ``partition`` — development / validation / holdout (Plan §13.3). Development cases may
  be tuned against freely; holdout cases may not be inspected before the frozen run.
* A label applies **only** to the stated condition. A true weakness elsewhere in the
  same application is not a false positive (Plan §13.2).
* An abstention is not a true negative. It stays visible in the negative-conclusive
  coverage denominator rather than being rewarded as a clean test.
"""

from __future__ import annotations

import enum
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Partition(enum.StrEnum):
    DEVELOPMENT = "development"
    VALIDATION = "validation"
    HOLDOUT = "holdout"


class ExpectedLabel(enum.StrEnum):
    """What the fixture is independently known to be for one named condition."""

    VULNERABLE = "vulnerable"
    FIXED = "fixed"
    ABSENT = "absent"

    @property
    def is_negative(self) -> bool:
        return self is not ExpectedLabel.VULNERABLE


class CaseOutcome(enum.StrEnum):
    """Per-case result vocabulary (Implementation Plan §13.2).

    ``NOT_MEASURABLE`` exists because confirmation precision with zero confirmations is
    undefined, and reporting 100% there would be a fabricated success.
    """

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    TRUE_NEGATIVE = "true_negative"
    NEGATIVE_ABSTENTION = "negative_abstention"
    UNMATCHED = "unmatched"
    NOT_MEASURABLE = "not_measurable"


class TargetBuild(BaseModel):
    """What exactly was run against. Pinned, or explicitly unpinned."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    project: str
    source_url: str
    commit: str | None = None
    image_digest: str | None = None
    architecture: str | None = None
    dependencies: tuple[str, ...] = ()
    license: str | None = None


class FixtureCase(BaseModel):
    """One labelled case: a single condition in a single fixture."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    canonical_control: str = Field(min_length=1)
    family: str | None = None
    route_or_input: str = Field(min_length=1)
    role_or_context: str = "unauthenticated"
    expected_label: ExpectedLabel
    claim_boundary: str = Field(
        min_length=1,
        description="Exactly what the label asserts. A label never means 'this "
        "application is clean'; it means this named condition is present or absent.",
    )


class Lifecycle(BaseModel):
    """How the fixture is brought to a known state, and how that is proven."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seed_method: str = Field(min_length=1)
    reset_method: str = Field(min_length=1)
    readiness_check: str = Field(
        min_length=1,
        description="How the fixture is known to be up before a run. An empty value "
        "would mean the run started against an unchecked target.",
    )
    disposable_volumes: tuple[str, ...] = ()
    cleanup_proof: str = Field(
        default="not established",
        description="Evidence that reset actually restored state. 'not established' is "
        "the honest default; a claimed reset that was never verified is not a reset.",
    )


class Proof(BaseModel):
    """How a case's condition may be established, and what must never happen."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    positive_validation: str = Field(
        default="not established",
        description="Independent demonstration that the vulnerable state really is "
        "vulnerable at this pinned revision.",
    )
    negative_validation: str = Field(
        default="not established",
        description="Independent demonstration that the fixed state really is fixed.",
    )
    permitted_confirmation_method: str
    forbidden_side_effects: tuple[str, ...] = Field(default_factory=tuple)


class Split(BaseModel):
    """Partition membership and contamination history."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    partition: Partition
    scenario_group: str = Field(min_length=1)
    split_version: str = Field(min_length=1)
    exposure_history: str = Field(
        default="never used for tuning",
        description="Once holdout results influence tuning, those cases are no longer "
        "untouched holdouts (Build Plan §7).",
    )
    contaminated: bool = False

    @model_validator(mode="after")
    def _contamination_is_explicit(self) -> Split:
        if self.contaminated and self.exposure_history == "never used for tuning":
            raise ValueError(
                "case marked contaminated but exposure_history claims it was never "
                "used for tuning; state which run influenced it"
            )
        return self


class CaseRecord(BaseModel):
    """A case bound to its fixture build, lifecycle, proof rules and split."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case: FixtureCase
    build: TargetBuild
    lifecycle: Lifecycle
    proof: Proof
    split: Split
    notes: str = ""


class RunRecord(BaseModel):
    """One execution. Empty until there is a runner (M4).

    ``cost`` fields are deliberately unset rather than zero: Plan §16 requires unknown
    cost to be recorded as unknown, never 0.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str
    started_at: str | None = None
    finished_at: str | None = None
    scope_profile: str | None = None
    model_provider: str | None = None
    model_id: str | None = None
    routing_policy: str | None = None
    prompt_versions: dict[str, str] = Field(default_factory=dict)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    budgets: dict[str, int | float] = Field(default_factory=dict)
    target_requests: int | None = None
    model_tokens: int | None = None
    model_cost: float | None = None
    cost_known: bool = False


class EvaluationRecord(BaseModel):
    """The evaluator's verdict for one case in one run.

    Written by the evaluator only. It reads frozen labels and results and never writes
    the agent's findings (Plan §15.4).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str
    run_id: str
    outcome: CaseOutcome
    reason: str = ""
    adjudicated_by: str | None = None
    evaluator_version: str = "not implemented"


class EvaluationManifest(BaseModel):
    """A versioned set of cases plus, optionally, results."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    manifest_version: str = "evaluation-manifest-v1"
    split_version: str = Field(min_length=1)
    created: date | None = None
    # Recorded so a reader cannot mistake this for a completed evaluation.
    status: str = "schema_only"
    cases: tuple[CaseRecord, ...] = ()
    runs: tuple[RunRecord, ...] = ()
    evaluations: tuple[EvaluationRecord, ...] = ()

    def case_ids(self) -> list[str]:
        return [record.case.id for record in self.cases]

    def duplicate_ids(self) -> list[str]:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for case_id in self.case_ids():
            if case_id in seen:
                duplicates.add(case_id)
            seen.add(case_id)
        return sorted(duplicates)

    def by_partition(self, partition: Partition) -> list[CaseRecord]:
        return [record for record in self.cases if record.split.partition is partition]

    def positive_count(self) -> int:
        return sum(1 for r in self.cases if r.case.expected_label is ExpectedLabel.VULNERABLE)

    def negative_count(self) -> int:
        return sum(1 for r in self.cases if r.case.expected_label.is_negative)


class EvaluationManifestError(ValueError):
    """Raised when a manifest on disk is invalid."""


def load_manifest(path: Path) -> EvaluationManifest:
    """Load and validate one manifest file.

    Fails loudly. A silently-skipped case would shrink the denominator of every metric
    computed from this file, which is exactly the direction that flatters a result.
    """
    raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise EvaluationManifestError(f"{path} must contain a YAML mapping at the top level")
    try:
        manifest = EvaluationManifest.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError, with file context added
        raise EvaluationManifestError(f"{path.name}: {exc}") from exc

    if duplicates := manifest.duplicate_ids():
        raise EvaluationManifestError(f"{path.name}: duplicate case ids: {duplicates}")
    return manifest
