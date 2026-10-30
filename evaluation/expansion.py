"""Per-family expansion qualification and equal-budget outcome comparisons.

This evaluator consumes labels and independently replayed proof decisions. It does not
make scanner observations their own answer key or turn development fixtures into holdout.
"""

from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evaluation.metrics import classify, metrics
from scopelens.domain.capabilities import capability_inventory as capability_inventory


class MeasuredCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    family: str
    scenario_group: str
    target: str
    check_id: str
    route: str
    method: str = "GET"
    role_id: str = "anonymous"
    input_key: str | None = None
    label: Literal["vulnerable", "fixed", "absent"]
    confirmed: bool
    conclusive: bool
    proof_valid: bool
    proof_replay_ref: str | None = None

    @model_validator(mode="after")
    def proof_has_provenance(self):
        if self.proof_valid and not self.proof_replay_ref:
            raise ValueError("independent replay reference required")
        return self


class QualificationRun(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    partition: Literal["development", "validation", "holdout"]
    frozen_before_run: bool
    contaminated: bool
    curator_ref: str | None = None
    candidate_fingerprint: str
    frozen_candidate_fingerprint: str
    manifest_sha256: str
    declared_families: tuple[str, ...]
    cases: tuple[MeasuredCase, ...]

    @model_validator(mode="after")
    def distinct_cases(self):
        if len({c.id for c in self.cases}) != len(self.cases):
            raise ValueError("duplicate case IDs")
        if len(
            {(c.target, c.check_id, c.method, c.route, c.role_id, c.input_key) for c in self.cases}
        ) != len(self.cases):
            raise ValueError("duplicate measurements do not increase sample size")
        if set(c.family for c in self.cases) - set(self.declared_families):
            raise ValueError("undeclared family in result")
        return self


def qualify(run: QualificationRun) -> dict:
    grouped = defaultdict(list)
    for case in run.cases:
        grouped[case.family].append(case)
    provenance = []
    if (
        run.partition != "holdout"
        or run.contaminated
        or not run.frozen_before_run
        or not run.curator_ref
    ):
        provenance.append(
            "Independent untouched held-out curation and pre-run freeze not established"
        )
    if run.candidate_fingerprint != run.frozen_candidate_fingerprint:
        provenance.append("Candidate differs from frozen candidate")
    families = {}
    for family in run.declared_families:
        cases = grouped[family]
        measured = metrics(
            [
                classify(
                    c.label,
                    confirmed=c.confirmed,
                    conclusive=c.conclusive,
                    proof_valid=c.proof_valid,
                )
                for c in cases
            ]
        )
        positive = sum(c.label == "vulnerable" for c in cases)
        negative = len(cases) - positive
        groups = len({c.scenario_group for c in cases})
        reasons = list(provenance)
        if positive < 30 or negative < 60 or groups < 3:
            reasons.append(
                f"Insufficient samples: {positive} positive, {negative} negative, {groups} groups; required 30/60/3"
            )
        for key, minimum in (
            ("recall", 0.9),
            ("precision", 0.95),
            ("negative_conclusive_coverage", 0.9),
        ):
            value = measured[key]["value"]
            if value is None or value < minimum:
                reasons.append(f"{key} threshold not met")
        rate = measured["false_positive_rate"]["value"]
        if rate is None or rate > 0.05:
            reasons.append("false_positive_rate threshold not met")
        families[family] = {
            "qualified": not reasons,
            "reasons": reasons,
            "samples": {"positive": positive, "negative": negative, "groups": groups},
            **measured,
        }
    return {
        "version": "qualification-v2",
        "partition": run.partition,
        "candidate_fingerprint": run.candidate_fingerprint,
        "manifest_sha256": run.manifest_sha256,
        "families": families,
        "qualified_families": sorted(f for f, result in families.items() if result["qualified"]),
        "passed": bool(families) and all(r["qualified"] for r in families.values()),
    }


class BudgetedResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    candidate_fingerprint: str
    scope_fingerprint: str
    fixture_fingerprint: str
    profile: str
    ceiling_requests: int = Field(ge=0)
    ceiling_seconds: float = Field(ge=0)
    ceiling_cost: float = Field(ge=0)
    requests: int = Field(ge=0)
    seconds: float = Field(ge=0)
    cost: float | None = Field(default=None, ge=0)
    cases: tuple[MeasuredCase, ...]

    @model_validator(mode="after")
    def unique_case_measurements(self):
        if len({c.id for c in self.cases}) != len(self.cases):
            raise ValueError("duplicate comparison case IDs")
        return self


def compare_runs(baseline: BudgetedResult, adaptive: BudgetedResult) -> dict:
    shared = (
        "candidate_fingerprint",
        "scope_fingerprint",
        "fixture_fingerprint",
        "profile",
        "ceiling_requests",
        "ceiling_seconds",
        "ceiling_cost",
    )
    reasons = [
        f"{name} differs" for name in shared if getattr(baseline, name) != getattr(adaptive, name)
    ]
    if {c.id for c in baseline.cases} != {c.id for c in adaptive.cases}:
        reasons.append("Case sets differ")
    for name, result in (("baseline", baseline), ("adaptive", adaptive)):
        if (
            result.requests > result.ceiling_requests
            or result.seconds > result.ceiling_seconds
            or result.cost is None
            or result.cost > result.ceiling_cost
        ):
            reasons.append(f"{name} exceeded a bound or has unknown model cost")
    if reasons:
        return {"comparable": False, "reasons": reasons}
    old = {c.id: c for c in baseline.cases}
    # Labels remain evaluator inputs; equal IDs with different labels invalidate the pair.
    if any(
        (
            c.family,
            c.scenario_group,
            c.label,
            c.target,
            c.check_id,
            c.method,
            c.route,
            c.role_id,
            c.input_key,
        )
        != (
            old[c.id].family,
            old[c.id].scenario_group,
            old[c.id].label,
            old[c.id].target,
            old[c.id].check_id,
            old[c.id].method,
            old[c.id].route,
            old[c.id].role_id,
            old[c.id].input_key,
        )
        for c in adaptive.cases
    ):
        return {"comparable": False, "reasons": ["Case definitions differ"]}
    families = {}
    for family in sorted({c.family for c in adaptive.cases}):
        prior = [c for c in baseline.cases if c.family == family]
        later = [c for c in adaptive.cases if c.family == family]

        def tp(rows):
            return sum(c.label == "vulnerable" and c.confirmed and c.proof_valid for c in rows)

        def fp(rows):
            return sum(c.label != "vulnerable" and c.confirmed for c in rows)

        families[family] = {
            "baseline_confirmed_true_positives": tp(prior),
            "adaptive_confirmed_true_positives": tp(later),
            "additional_true_positives": tp(later) - tp(prior),
            "additional_false_positives": fp(later) - fp(prior),
        }
    return {
        "comparable": True,
        "families": families,
        "request_difference": adaptive.requests - baseline.requests,
        "cost_difference": adaptive.cost - baseline.cost,
        "runtime_difference": adaptive.seconds - baseline.seconds,
    }
