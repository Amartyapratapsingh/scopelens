"""Release manifest honesty (Build Plan §5.19, §0.3).

The manifest is where a release makes its version claims. These tests exist to stop it
reporting a plausible-looking value for something that was never measured.
"""

from __future__ import annotations

import pytest

from scopelens.config import REPO_ROOT, Settings
from scopelens.manifest import MANIFEST_VERSION, build_manifest, pinned_images


@pytest.fixture
def manifest() -> dict:
    return build_manifest(Settings(_env_file=None), None)


class TestUnknownsAreNotFabricated:
    def test_a_tools_status_and_version_agree(self, manifest: dict) -> None:
        """A tool claiming to be in use must name a version; an absent one must not.

        This is the invariant that makes the inventory trustworthy in either direction —
        a missing tool cannot borrow credibility from a version string, and a present one
        cannot hide behind `not_implemented`.
        """
        assert manifest["tools"], "the tool inventory must not be empty"
        for name, tool in manifest["tools"].items():
            assert tool["milestone"], name
            if tool["status"] == "not_implemented":
                assert tool["version"] is None, f"{name} claims a version it does not have"
            else:
                assert tool["version"], f"{name} is marked {tool['status']} without a version"

    def test_model_compatibility_is_empty_not_guessed(self, manifest: dict) -> None:
        assert manifest["model_compatibility"] == []

    def test_schema_revision_is_none_without_a_database(self, manifest: dict) -> None:
        assert manifest["database"]["schema_revision"] is None

    def test_git_revision_reports_unavailable_rather_than_faking(self) -> None:
        from scopelens.manifest import git_revision

        revision = git_revision()
        assert revision["status"] in {"ok", "unavailable"}
        if revision["status"] == "unavailable":
            assert revision["commit"] is None
        else:
            assert isinstance(revision["commit"], str)


class TestSupportClaims:
    def test_every_shipped_control_is_claimed_supported(self, manifest: dict) -> None:
        """M2 promoted all 17 controls: fixtures verified and mappings reviewed."""
        assert len(manifest["checks_registry"]["supported_control_ids"]) == 17

    def test_experimental_controls_are_not_claimed_supported(self, manifest: dict) -> None:
        """Implementation and development fixtures do not qualify new controls."""
        experimental = set(manifest["checks_registry"]["experimental_control_ids"])
        supported = set(manifest["checks_registry"]["supported_control_ids"])
        assert len(experimental) == 29
        assert not experimental & supported
        assert experimental | supported == {
            c["id"] for c in manifest["checks_registry"]["controls"]
        }

    def test_fixture_claims_match_registry_and_gate_support(self, manifest: dict) -> None:
        """`make labs-verify` must pass for this to be true; the gate is a command, not a claim."""
        from scopelens.domain.registry import load_registry

        registry = load_registry(REPO_ROOT / "checks_registry")
        for control in manifest["checks_registry"]["controls"]:
            entry = registry.get(control["id"])
            assert control["fixtures_verified"] is entry.fixtures.verified
            if control["id"] in manifest["checks_registry"]["supported_control_ids"]:
                assert control["fixtures_verified"] is True, control["id"]

    def test_release_qualification_does_not_follow_from_implementation(
        self, manifest: dict
    ) -> None:
        assert manifest["release_qualification"]["status"] == "not_qualified"
        assert "independent held-out benchmark" in manifest["release_qualification"]["required"]
        assert manifest["m4"]["graph"] == "baseline-observe-plan-admit-execute-verify"

    def test_m1_subsystems_are_no_longer_listed_as_unimplemented(self, manifest: dict) -> None:
        """The inverse claim, so the list cannot simply be left untouched."""
        unimplemented = set(manifest["unimplemented"])
        for delivered in (
            "scanner_adapters",
            "browser_exploration",
            "policy_broker",
            "task_ledger",
            "transactional_outbox",
            "celery_dispatch",
            "leases_and_fencing",
            "reconciler",
            "supervisor_and_isolated_workers",
            "trusted_evidence_intake",
            "cancellation_and_recovery",
        ):
            assert delivered not in unimplemented, delivered


class TestImages:
    def test_images_are_read_from_the_compose_files(self, manifest: dict) -> None:
        assert {"postgres", "labs-bad", "labs-good", "labs-edge"} <= set(manifest["images"])

    def test_every_image_is_digest_pinned(self, manifest: dict) -> None:
        """Build Plan §3: pin by digest; no floating tags in measured runs."""
        for name, image in manifest["images"].items():
            assert image["digest"], f"{name} is not pinned by digest"
            assert image["digest"].startswith("sha256:"), name

    def test_no_latest_tag(self, manifest: dict) -> None:
        for name, image in manifest["images"].items():
            assert not image["repository"].endswith(":latest"), name

    def test_missing_compose_file_is_tolerated(self, tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        monkeypatch.setattr("scopelens.manifest.REPO_ROOT", tmp_path)
        assert pinned_images() == {}


class TestManifestShape:
    def test_version_and_milestone_are_recorded(self, manifest: dict) -> None:
        assert manifest["manifest_version"] == MANIFEST_VERSION
        assert manifest["milestone"] == "M4/M5 backend candidate"

    def test_profiles_and_score_version_are_recorded(self, manifest: dict) -> None:
        assert manifest["profiles"]["default"] == "external-configuration"
        assert manifest["profiles"]["score_version"] == "score-v1.0"

    def test_write_manifest_produces_valid_json(self, tmp_path) -> None:
        import json

        from scopelens.manifest import write_manifest

        target = tmp_path / "release_manifest.json"
        settings = Settings(_env_file=None, release_manifest_path=target)

        path = write_manifest(settings, None)

        assert path == target
        assert (
            json.loads(target.read_text(encoding="utf-8"))["milestone"] == "M4/M5 backend candidate"
        )


def test_repository_manifest_is_committed() -> None:
    """The checked-in manifest must exist and be regenerable."""
    assert (REPO_ROOT / "release_manifest.json").exists()


def test_model_smoke_evidence_is_bound_to_adapter_and_role_config(tmp_path, monkeypatch):
    import hashlib
    import json

    from scopelens.config import ModelRoleSettings
    from scopelens.manifest import model_compatibility

    monkeypatch.setattr("scopelens.manifest.REPO_ROOT", tmp_path)
    adapter = tmp_path / "backend/scopelens/adapters/roles.py"
    adapter.parent.mkdir(parents=True)
    adapter.write_text("adapter version 1")
    evidence = tmp_path / "checks_registry/model_qualification.json"
    evidence.parent.mkdir()
    evidence.write_text(
        json.dumps(
            {
                "adapter_sha256": hashlib.sha256(adapter.read_bytes()).hexdigest(),
                "recorded_at": "2026-09-26T00:00:00+00:00",
                "limitations": ["Synthetic smoke only"],
                "results": [
                    {
                        "role": "planner",
                        "model": "tested-model",
                        "provider": "https://example.invalid/v1",
                        "smoke_passed": True,
                        "configuration": {"reasoning_effort": "low"},
                    }
                ],
            }
        )
    )
    settings = Settings(
        _env_file=None,
        planner_model=ModelRoleSettings(
            model="tested-model", base_url="https://example.invalid/v1", reasoning_effort="low"
        ),
    )
    assert len(model_compatibility(settings)) == 1
    settings.planner_model.reasoning_effort = "high"
    assert model_compatibility(settings) == []
    settings.planner_model.reasoning_effort = "low"
    adapter.write_text("changed adapter")
    assert model_compatibility(settings) == []
    evidence.write_text("truncated")
    assert model_compatibility(settings) == []
