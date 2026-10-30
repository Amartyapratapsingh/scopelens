"""Expanded component inputs remain pinned, passive and candidate-only."""

from dataclasses import replace
from pathlib import Path

import pytest
from tests.m2_helpers import context, response

from scopelens.checks.advisories import load_bundle
from scopelens.checks.controls.components import evaluate_component_versions
from scopelens.domain.enums import ControlOutcome, EvidenceStatus, ProfileName
from scopelens.domain.surface import TechFingerprint
from scopelens.expansion.components import (
    EXPANDED_ADVISORY_SHA256,
    advisory_snapshot_for_profile,
    expanded_component_surface,
)

REGISTRY = Path(__file__).resolve().parents[2] / "checks_registry"
PROFILE = ProfileName.EXTERNAL_DISCOVERY_V2


def observed(*responses, profile=PROFILE):
    surface = context().surface.model_copy(update={"tech": ()})
    return expanded_component_surface(profile, surface, responses)


@pytest.mark.parametrize("profile", [p for p in ProfileName if p.expanded])
def test_expanded_profiles_freeze_reviewed_snapshot_and_provenance(profile):
    snapshot = advisory_snapshot_for_profile(profile, registry_dir=REGISTRY, legacy_path=None)
    assert snapshot["sha256"] == EXPANDED_ADVISORY_SHA256
    assert len(snapshot["bundle"]["packages"]) == 18
    assert len(snapshot["bundle"]["records"]) == 651
    assert snapshot["bundle"]["provenance"]["parent_source_sha256"]
    assert snapshot["selection"]["profile"] == profile.value


def test_snapshot_change_cannot_silently_change_scan_corpus(tmp_path):
    path = tmp_path / "tooling" / "expansion" / "advisories.json"
    path.parent.mkdir(parents=True)
    original = REGISTRY / "tooling" / "expansion" / "advisories.json"
    path.write_bytes(original.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="content pin"):
        advisory_snapshot_for_profile(PROFILE, registry_dir=tmp_path, legacy_path=None)


def test_legacy_snapshot_and_fingerprints_do_not_change(tmp_path):
    legacy = REGISTRY / "tooling" / "expansion" / "advisories.json"
    actual = advisory_snapshot_for_profile(
        ProfileName.EXTERNAL_DAST, registry_dir=tmp_path, legacy_path=legacy
    )
    assert actual == load_bundle(legacy)
    surface = context().surface
    assert (
        expanded_component_surface(
            ProfileName.EXTERNAL_CONFIGURATION, surface, [response(body="lodash 4.17.20")]
        )
        is surface
    )


@pytest.mark.parametrize(
    "body,name,version",
    [
        ("/*! lodash 4.17.20 */", "lodash", "4.17.20"),
        ("/*! axios v0.21.0 */", "axios", "0.21.0"),
        ("/*! moment.js v2.24.0 */", "moment", "2.24.0"),
        ("/*! AngularJS v1.7.0 */", "angularjs", "1.7.0"),
        ('<div ng-version="17.2.1"></div>', "angular", "17.2.1"),
        ("/*! Next.js v14.2.25 */", "next.js", "14.2.25"),
        ("/*! Nuxt v3.1.0 */", "nuxt", "3.1.0"),
        ("/*! Vue.js v2.6.14 */", "vue.js", "2.6.14"),
        ("/*! React v18.1.0 */", "react", "18.1.0"),
        ("/*! Bootstrap v3.3.0 */", "bootstrap", "3.3.0"),
        ("/*! jQuery v3.4.1 */", "jquery", "3.4.1"),
        ("/*! Express v4.0.0 */", "express", "4.0.0"),
    ],
)
def test_named_version_observations_preserve_capture_provenance(body, name, version):
    surface = observed(response(body=body))
    fingerprint = next(t for t in surface.tech if t.name == name)
    assert fingerprint.version == version
    assert "captured excerpt sha256=" in fingerprint.evidence
    assert "exploitability unverified" in fingerprint.evidence


@pytest.mark.parametrize(
    "raw,expected", [("4.17.20-vendor", "4.17.20-vendor"), ("4.17.20.1", None), ("04.17.20", None)]
)
def test_suffix_or_invalid_version_never_becomes_stable_version(raw, expected):
    surface = observed(response(body=f"lodash {raw}"))
    assert surface.tech[0].version == expected
    snapshot = advisory_snapshot_for_profile(PROFILE, registry_dir=REGISTRY, legacy_path=None)
    result = evaluate_component_versions(
        replace(context(), surface=surface, advisory_snapshot=snapshot)
    )
    assert result.status == ControlOutcome.INCONCLUSIVE


def test_unadmitted_failed_responses_and_bare_mentions_do_not_supply_versions():
    surface = observed(
        response(body="lodash 4.17.20", via_proxy=False),
        response(body="axios 0.21.0", status=404),
        response(body="Site uses axios. Its release is 0.21.0. __NEXT_DATA__ buildId=1.2.3"),
    )
    assert surface.tech == ()


def test_asset_paths_are_inventory_and_angular_packages_stay_distinct():
    surface = observed(response("/vendor/angular/1.7.0/angular.js", ""))
    assert [(t.name, t.version, t.source) for t in surface.tech] == [("angularjs", "1.7.0", "path")]
    assert "identity unverified" in surface.tech[0].evidence


def test_old_parser_cannot_reintroduce_shortened_version_claim():
    surface = context().surface.model_copy(
        update={
            "tech": (
                TechFingerprint(
                    name="jquery", version="3.4.1", source="body", evidence="earlier parser"
                ),
            )
        }
    )
    result = expanded_component_surface(PROFILE, surface, [response(body="jQuery 3.4.1.9")])
    assert {t.version for t in result.tech} == {None}
    no_capture = expanded_component_surface(PROFILE, surface, [])
    assert no_capture.tech[0].version is None


def test_known_version_matches_remain_potential_with_trusted_evidence_references():
    surface = observed(response(body="/*! lodash 4.17.20 */"))
    snapshot = advisory_snapshot_for_profile(PROFILE, registry_dir=REGISTRY, legacy_path=None)
    result = evaluate_component_versions(
        replace(context(), surface=surface, advisory_snapshot=snapshot)
    )
    assert result.proof.status == EvidenceStatus.POTENTIAL
    assert not result.proof.satisfied
    assert result.proof.evidence_refs == ("capture-1", "advisory-1")
    assert "GHSA-" in result.summary
    assert EXPANDED_ADVISORY_SHA256 in result.proof.reasons[-1]
