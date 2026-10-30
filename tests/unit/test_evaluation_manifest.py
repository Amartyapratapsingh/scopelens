"""Evaluation manifest schema (Implementation Plan §15.4).

The schema's job is to make dishonesty awkward: an unmeasured field has to be written
as `not established`, an abstention cannot be recorded as a clean negative, and unknown
cost cannot be recorded as zero.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from evaluation.manifest import (
    CaseOutcome,
    CaseRecord,
    EvaluationManifest,
    EvaluationManifestError,
    ExpectedLabel,
    FixtureCase,
    Lifecycle,
    Partition,
    RunRecord,
    Split,
    TargetBuild,
    load_manifest,
)

from scopelens.config import REPO_ROOT

MANIFESTS = REPO_ROOT / "evaluation" / "manifests"


def case_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "case": {
            "id": "case-1",
            "canonical_control": "transport.hsts.effective_policy",
            "route_or_input": "/",
            "expected_label": "vulnerable",
            "claim_boundary": "asserts only the HSTS header on this origin",
        },
        "build": {"project": "fixtures", "source_url": "local"},
        "lifecycle": {
            "seed_method": "seed.sh",
            "reset_method": "reset.sh",
            "readiness_check": "ready.sh",
        },
        "proof": {
            "permitted_confirmation_method": "direct observation",
            "forbidden_side_effects": ["cleartext request"],
        },
        "split": {
            "partition": "development",
            "scenario_group": "fixtures",
            "split_version": "split-v1",
        },
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = {**base[key], **value}
        else:
            base[key] = value
    return base


class TestHonestyDefaults:
    def test_cleanup_proof_defaults_to_not_established(self) -> None:
        record = CaseRecord.model_validate(case_dict())
        assert record.lifecycle.cleanup_proof == "not established"

    @pytest.mark.parametrize("field", ["positive_validation", "negative_validation"])
    def test_proof_defaults_to_not_established(self, field: str) -> None:
        record = CaseRecord.model_validate(case_dict())
        assert getattr(record.proof, field) == "not established"

    def test_run_cost_is_unset_not_zero(self) -> None:
        run = RunRecord(run_id="run-1")
        assert run.model_cost is None
        assert run.model_tokens is None
        assert run.cost_known is False

    def test_evaluator_version_defaults_to_not_implemented(self) -> None:
        from evaluation.manifest import EvaluationRecord

        assert EvaluationRecord(case_id="c", run_id="r", outcome="unmatched").evaluator_version == (
            "not implemented"
        )


class TestOutcomeVocabulary:
    def test_abstention_is_distinct_from_true_negative(self) -> None:
        assert CaseOutcome.NEGATIVE_ABSTENTION != CaseOutcome.TRUE_NEGATIVE

    def test_negative_labels_are_recognised(self) -> None:
        assert not ExpectedLabel.VULNERABLE.is_negative
        assert ExpectedLabel.FIXED.is_negative
        assert ExpectedLabel.ABSENT.is_negative

    def test_no_outcome_is_named_for_a_missing_measurement(self) -> None:
        """Zero confirmations must be expressible without implying success."""
        assert CaseOutcome.NOT_MEASURABLE.value == "not_measurable"

    def test_unknown_outcome_is_refused(self) -> None:
        from evaluation.manifest import EvaluationRecord

        with pytest.raises(ValueError):
            EvaluationRecord(case_id="c", run_id="r", outcome="probably_true")


class TestSplitRules:
    def test_contamination_must_be_stated(self) -> None:
        with pytest.raises(ValueError, match="contaminated"):
            Split(
                partition=Partition.HOLDOUT,
                scenario_group="g",
                split_version="v1",
                contaminated=True,
            )

    def test_contaminated_case_records_which_run(self) -> None:
        split = Split(
            partition=Partition.HOLDOUT,
            scenario_group="g",
            split_version="v1",
            contaminated=True,
            exposure_history="inspected after run run-42",
        )
        assert split.contaminated

    def test_unknown_partition_is_refused(self) -> None:
        with pytest.raises(ValueError):
            Split(partition="staging", scenario_group="g", split_version="v1")


class TestSchemaStrictness:
    def test_extra_fields_are_refused(self) -> None:
        with pytest.raises(ValueError):
            FixtureCase(
                id="c",
                canonical_control="x",
                route_or_input="/",
                expected_label="vulnerable",
                claim_boundary="b",
                surprise="nope",
            )

    def test_claim_boundary_is_required(self) -> None:
        with pytest.raises(ValueError):
            FixtureCase(
                id="c",
                canonical_control="x",
                route_or_input="/",
                expected_label="vulnerable",
                claim_boundary="",
            )

    def test_records_are_frozen(self) -> None:
        record = CaseRecord.model_validate(case_dict())
        with pytest.raises(ValueError):
            record.case.id = "changed"  # type: ignore[misc]

    def test_lifecycle_requires_a_readiness_check(self) -> None:
        with pytest.raises(ValueError):
            Lifecycle(seed_method="s", reset_method="r", readiness_check="")

    def test_target_build_may_be_unpinned_but_must_say_so(self) -> None:
        build = TargetBuild(project="p", source_url="u")
        assert build.image_digest is None


class TestManifestAggregates:
    def test_duplicate_case_ids_are_detected(self) -> None:
        manifest = EvaluationManifest(
            split_version="v1",
            cases=(
                CaseRecord.model_validate(case_dict()),
                CaseRecord.model_validate(case_dict()),
            ),
        )
        assert manifest.duplicate_ids() == ["case-1"]

    def test_positive_and_negative_counts(self) -> None:
        manifest = EvaluationManifest(
            split_version="v1",
            cases=(
                CaseRecord.model_validate(case_dict()),
                CaseRecord.model_validate(
                    case_dict(case={"id": "case-2", "expected_label": "fixed"})
                ),
            ),
        )
        assert manifest.positive_count() == 1
        assert manifest.negative_count() == 1

    def test_status_defaults_to_schema_only(self) -> None:
        assert EvaluationManifest(split_version="v1").status == "schema_only"


class TestLoading:
    def test_loads_a_valid_file(self, tmp_path: Path) -> None:
        path = tmp_path / "m.yaml"
        path.write_text(
            yaml.safe_dump({"split_version": "v1", "cases": [case_dict()]}), encoding="utf-8"
        )
        assert load_manifest(path).case_ids() == ["case-1"]

    def test_duplicate_ids_are_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "m.yaml"
        path.write_text(
            yaml.safe_dump({"split_version": "v1", "cases": [case_dict(), case_dict()]}),
            encoding="utf-8",
        )
        with pytest.raises(EvaluationManifestError, match="duplicate case ids"):
            load_manifest(path)

    def test_non_mapping_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "m.yaml"
        path.write_text("- a\n", encoding="utf-8")
        with pytest.raises(EvaluationManifestError, match="mapping"):
            load_manifest(path)

    def test_invalid_case_names_the_file(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text(yaml.safe_dump({"split_version": "v1", "cases": [{}]}), encoding="utf-8")
        with pytest.raises(EvaluationManifestError, match=r"bad\.yaml"):
            load_manifest(path)


class TestShippedManifests:
    @pytest.mark.parametrize("name", ["development", "validation", "holdout"])
    def test_every_manifest_loads(self, name: str) -> None:
        assert load_manifest(MANIFESTS / f"{name}.yaml").split_version

    def test_manifests_distinguish_examples_from_reserved_holdouts(self) -> None:
        """Reserved cases require current health/measurement; examples remain examples."""
        for path in sorted(MANIFESTS.glob("*.yaml")):
            expected = (
                "reserved_requires_current_health_and_measurement"
                if path.stem == "holdout"
                else "schema_only"
            )
            assert load_manifest(path).status == expected, path.name

    def test_no_manifest_contains_results(self) -> None:
        for path in sorted(MANIFESTS.glob("*.yaml")):
            manifest = load_manifest(path)
            assert manifest.runs == (), path.name
            assert manifest.evaluations == (), path.name

    def test_holdout_is_reserved_and_separate_from_development(self) -> None:
        manifest = load_manifest(MANIFESTS / "holdout.yaml")
        assert manifest.cases
        assert {r.split.partition for r in manifest.cases} == {Partition.HOLDOUT}
        assert not any(r.split.contaminated for r in manifest.cases)
        assert set(manifest.case_ids()).isdisjoint(
            load_manifest(MANIFESTS / "development.yaml").case_ids()
        )
        assert all(
            r.build.commit or r.build.source_url.startswith("local:") for r in manifest.cases
        )

    def test_sibling_pair_shares_a_scenario_group(self) -> None:
        """Vulnerable/fixed pairs must not be split across partitions."""
        manifest = load_manifest(MANIFESTS / "development.yaml")
        groups = {record.split.scenario_group for record in manifest.cases}
        partitions = {record.split.partition for record in manifest.cases}
        assert len(groups) == 1
        assert partitions == {Partition.DEVELOPMENT}

    def test_development_cases_pair_vulnerable_with_fixed(self) -> None:
        manifest = load_manifest(MANIFESTS / "development.yaml")
        labels = {record.case.expected_label for record in manifest.cases}
        assert ExpectedLabel.VULNERABLE in labels
        assert ExpectedLabel.FIXED in labels

    def test_development_cases_have_observed_validation(self) -> None:
        """The two shipped cases were checked by labs/scripts/verify.sh, so they must
        not still say 'not established' — and nothing else may claim to be verified."""
        manifest = load_manifest(MANIFESTS / "development.yaml")
        for record in manifest.cases:
            assert record.lifecycle.cleanup_proof != "not established"
            assert "2026-09-24" in record.proof.positive_validation + (
                record.proof.negative_validation
            )
