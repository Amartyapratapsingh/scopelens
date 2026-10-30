from dataclasses import replace

import pytest
from tests.m2_helpers import context

from scopelens.checks.advisories import affected_version, load_bundle
from scopelens.checks.controls.components import evaluate_component_versions
from scopelens.domain.enums import ControlOutcome, EvidenceStatus


def test_matching_advisory_is_a_candidate_never_confirmation():
    ctx = context()
    tech = ctx.surface.tech[0].model_copy(update={"version": "1.0.0"})
    result = evaluate_component_versions(
        replace(ctx, surface=ctx.surface.model_copy(update={"tech": (tech,)}))
    )
    assert result.proof.status == EvidenceStatus.POTENTIAL
    assert not result.is_fully_assessed
    assert "sha256" in result.proof.reasons[-1]
    assert "x_FIXTURE-1" in result.summary


def test_fixed_version_passes_only_for_configured_corpus():
    assert evaluate_component_versions(context()).status == ControlOutcome.PASS
    assert (
        evaluate_component_versions(context(advisory_snapshot={})).status
        == ControlOutcome.INCONCLUSIVE
    )


@pytest.mark.parametrize(
    "version,expected", [("1.0.0", True), ("2.0.0", False), ("1.2.0-vendor", None)]
)
def test_range_boundaries(version, expected):
    affected = context().advisory_snapshot["bundle"]["records"][0]["affected"][0]
    assert affected_version(version, affected) is expected


def test_bundle_rejects_missing_provenance(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"version":"v1","source":"","packages":{},"records":[]}')
    with pytest.raises(ValueError):
        load_bundle(p)


def test_empty_package_corpus_does_not_establish_coverage():
    ctx = context()
    snapshot = {
        **ctx.advisory_snapshot,
        "bundle": {**ctx.advisory_snapshot["bundle"], "records": []},
    }
    result = evaluate_component_versions(replace(ctx, advisory_snapshot=snapshot))
    assert result.status == ControlOutcome.INCONCLUSIVE


def test_multiple_disjoint_ranges_preserve_earlier_match():
    affected = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "1.2.0"},
                    {"introduced": "2.0.0"},
                    {"last_affected": "2.1.0"},
                ],
            }
        ]
    }
    for version, expected in [("1.0.0", True), ("1.2.0", False), ("2.1.0", True), ("2.1.1", False)]:
        assert affected_version(version, affected) is expected


@pytest.mark.parametrize(
    "events",
    [
        [{"introduced": "0"}, {"fixed": "1.2.0-beta"}],
        [{"introduced": "0"}, {"future_kind": "1.2.0"}],
        [{"fixed": "1.2.0"}],
        [],
    ],
)
def test_unsupported_or_incomplete_range_cannot_match_or_pass(events):
    assert affected_version("1.3.0", {"ranges": [{"type": "SEMVER", "events": events}]}) is None
