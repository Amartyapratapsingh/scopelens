"""Check registry schema and loader (Build Plan §5.19).

The loader must fail loudly on an invalid entry. A control that is silently skipped
looks present in the file listing while counting as unsupported, which is a quiet form
of false reporting.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from scopelens.config import REPO_ROOT
from scopelens.domain.enums import Category, ProfileName, ReviewState
from scopelens.domain.registry import (
    CheckRegistry,
    CheckRegistryEntry,
    RegistryError,
    load_registry,
)


def entry_dict(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "SL-C01-TEST-01",
        "title": "A test control",
        "canonical_control": "test.control",
        "root_cause": "test-root-cause",
        "category": "C01",
        "availability": {
            "profiles": ["external-configuration"],
            "phase": "M2",
            "stance": "OBSERVE",
            "family": "F33",
        },
        "applicability": {
            "description": "Applies to the scope origin.",
            "evidence_required": "A captured response.",
        },
        "side_effects": {
            "expectation": "none",
            "stop_conditions": ["origin unreachable"],
        },
        "detection": {
            "signal": "header absent",
            "negative_controls": ["fixed fixture produces nothing"],
            "confirmation_criteria": "observed absent in a response we captured",
            "false_positive_considerations": ["cached responses"],
        },
        "fixtures": {"vulnerable": "labs-bad", "fixed": "labs-good"},
        "owner": "tester",
    }
    base.update(overrides)
    return base


def write_registry(tmp_path: Path, entries: list[dict[str, Any]]) -> Path:
    controls = tmp_path / "controls"
    controls.mkdir(parents=True, exist_ok=True)
    for index, entry in enumerate(entries):
        (controls / f"entry-{index}.yaml").write_text(yaml.safe_dump(entry), encoding="utf-8")
    return tmp_path


class TestEntryValidation:
    def test_minimal_valid_entry(self) -> None:
        parsed = CheckRegistryEntry.model_validate(entry_dict())
        assert parsed.id == "SL-C01-TEST-01"
        assert parsed.category is Category.C01_TRANSPORT
        assert parsed.profiles == (ProfileName.EXTERNAL_CONFIGURATION,)

    def test_id_format_is_enforced(self) -> None:
        with pytest.raises(ValueError, match="String should match pattern"):
            CheckRegistryEntry.model_validate(entry_dict(id="hsts-check"))

    def test_unknown_category_is_refused(self) -> None:
        with pytest.raises(ValueError):
            CheckRegistryEntry.model_validate(entry_dict(category="C99"))

    def test_unknown_stance_is_refused(self) -> None:
        bad = entry_dict()
        bad["availability"]["stance"] = "MAYBE"
        with pytest.raises(ValueError):
            CheckRegistryEntry.model_validate(bad)

    def test_extra_fields_are_refused(self) -> None:
        with pytest.raises(ValueError):
            CheckRegistryEntry.model_validate(entry_dict(surprise="value"))

    def test_at_least_one_profile_is_required(self) -> None:
        bad = entry_dict()
        bad["availability"]["profiles"] = []
        with pytest.raises(ValueError, match="at least one profile"):
            CheckRegistryEntry.model_validate(bad)

    def test_family_format_is_enforced(self) -> None:
        bad = entry_dict()
        bad["availability"]["family"] = "family33"
        with pytest.raises(ValueError, match="family must look like"):
            CheckRegistryEntry.model_validate(bad)

    def test_stop_conditions_cannot_be_empty(self) -> None:
        bad = entry_dict()
        bad["side_effects"]["stop_conditions"] = []
        with pytest.raises(ValueError):
            CheckRegistryEntry.model_validate(bad)


class TestSupportState:
    def test_experimental_is_not_supported(self) -> None:
        parsed = CheckRegistryEntry.model_validate(entry_dict())
        assert parsed.review_state is ReviewState.EXPERIMENTAL
        assert not parsed.is_supported

    def test_only_enabled_counts_as_supported(self) -> None:
        assert ReviewState.ENABLED.counts_as_supported
        for state in (ReviewState.EXPERIMENTAL, ReviewState.VALIDATED, ReviewState.RETIRED):
            assert not state.counts_as_supported


class TestPromotionGate:
    """A control cannot be promoted by editing one field."""

    def test_promotion_requires_verified_fixtures(self) -> None:
        with pytest.raises(ValueError, match=r"fixtures\.verified"):
            CheckRegistryEntry.model_validate(entry_dict(review_state="enabled"))

    def test_promotion_requires_a_reviewed_mapping(self) -> None:
        bad = entry_dict(review_state="validated")
        bad["fixtures"]["verified"] = True
        with pytest.raises(ValueError, match="reviewed standards mapping"):
            CheckRegistryEntry.model_validate(bad)

    def test_promotion_requires_last_reviewed(self) -> None:
        bad = entry_dict(review_state="validated")
        bad["fixtures"]["verified"] = True
        bad["standards"] = {"mapping_review": "reviewed"}
        with pytest.raises(ValueError, match="last_reviewed"):
            CheckRegistryEntry.model_validate(bad)

    def test_a_fully_prepared_entry_can_be_enabled(self) -> None:
        good = entry_dict(review_state="enabled", last_reviewed="2026-09-24")
        good["fixtures"]["verified"] = True
        good["standards"] = {"mapping_review": "reviewed"}
        parsed = CheckRegistryEntry.model_validate(good)
        assert parsed.is_supported


class TestLoading:
    def test_loads_a_directory_of_entries(self, tmp_path: Path) -> None:
        registry = load_registry(write_registry(tmp_path, [entry_dict()]))
        assert len(registry.entries) == 1

    def test_duplicate_ids_are_refused(self, tmp_path: Path) -> None:
        with pytest.raises(RegistryError, match="duplicate control ids"):
            load_registry(write_registry(tmp_path, [entry_dict(), entry_dict()]))

    def test_invalid_entry_names_the_file(self, tmp_path: Path) -> None:
        with pytest.raises(RegistryError, match=r"entry-0\.yaml"):
            load_registry(write_registry(tmp_path, [entry_dict(category="C99")]))

    def test_missing_controls_directory_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(RegistryError, match="no controls directory"):
            load_registry(tmp_path)

    def test_top_level_must_be_a_mapping(self, tmp_path: Path) -> None:
        controls = tmp_path / "controls"
        controls.mkdir()
        (controls / "bad.yaml").write_text("- a\n- b\n", encoding="utf-8")
        with pytest.raises(RegistryError):
            load_registry(tmp_path)


@pytest.fixture(scope="module")
def shipped_registry() -> CheckRegistry:
    """The repository's own registry, loaded once."""
    return load_registry(REPO_ROOT / "checks_registry")


class TestShippedRegistry:
    """Assertions about the repository's own registry."""

    def test_loads(self, shipped_registry: CheckRegistry) -> None:
        assert len(shipped_registry.for_profile(ProfileName.EXTERNAL_DAST)) == 22
        expansion = [e for e in shipped_registry.entries if e.availability.phase.startswith("B")]
        assert len(expansion) == 24
        assert len(shipped_registry.entries) == 46
        assert not shipped_registry.duplicate_ids()

    def test_every_control_in_the_configuration_profile_is_supported(
        self, shipped_registry: CheckRegistry
    ) -> None:
        """M2 implements and promotes every control the profile plans."""
        supported = shipped_registry.supported_for_profile(ProfileName.EXTERNAL_CONFIGURATION)
        assert len(supported) == 17
        assert all(entry.is_supported for entry in supported)

    def test_enabled_and_experimental_controls_remain_separate(
        self, shipped_registry: CheckRegistry
    ) -> None:
        """Promotion requires verified fixtures AND a reviewed standards mapping, and the
        loader enforces it — so `enabled` here means both were actually done."""
        assert sum(e.review_state is ReviewState.ENABLED for e in shipped_registry.entries) == 17
        assert (
            sum(e.review_state is ReviewState.EXPERIMENTAL for e in shipped_registry.entries) == 29
        )

    def test_supported_fixture_pairs_are_verified(self, shipped_registry: CheckRegistry) -> None:
        """`make labs-verify` demonstrates each pair; this asserts the claim matches."""
        assert all(e.fixtures.verified for e in shipped_registry.entries if e.is_supported)
        for entry in shipped_registry.entries:
            if not entry.fixtures.verified:
                assert entry.review_state is ReviewState.EXPERIMENTAL
                assert not entry.is_supported

    def test_every_entry_names_both_fixtures(self, shipped_registry: CheckRegistry) -> None:
        for entry in shipped_registry.entries:
            assert entry.fixtures.vulnerable
            assert entry.fixtures.fixed

    def test_m0_controls_request_no_target_traffic(self, shipped_registry: CheckRegistry) -> None:
        """§5.8 defines config checks as pure functions over already-collected data.

        Scoped to the three M0 controls rather than to every OBSERVE control: a future
        control may legitimately need its own fetch, and a blanket assertion would then
        fail for the wrong reason.
        """
        for check_id in ("SL-C01-HSTS-01", "SL-C02-COOKIE-01", "SL-C04-XCTO-01"):
            entry = shipped_registry.get(check_id)
            assert entry is not None, check_id
            assert entry.allowed_action.max_requests == 0, check_id

    def test_mappings_are_reviewed_where_populated(self, shipped_registry: CheckRegistry) -> None:
        """Promotion requires a reviewed mapping. WSTG and CWE identifiers were checked
        against their sources; ASVS and OWASP-2025 are deliberately left empty rather than
        guessed (docs/OPEN_QUESTIONS.md Q-4)."""
        for entry in shipped_registry.entries:
            if entry.is_supported:
                assert entry.standards.mapping_review == "reviewed", entry.id
                assert entry.standards.wstg_v42 or entry.standards.cwe, entry.id
            elif entry.standards.mapping_review != "reviewed":
                assert entry.review_state is ReviewState.EXPERIMENTAL

    def test_root_causes_are_distinct(self, shipped_registry: CheckRegistry) -> None:
        root_causes = [e.root_cause for e in shipped_registry.entries]
        assert len(root_causes) == len(set(root_causes))
