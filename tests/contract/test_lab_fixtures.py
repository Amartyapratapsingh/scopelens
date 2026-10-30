"""Lab fixture integrity (Build Plan §7).

These tests exist because of a real defect found during the M0 exit-gate run: the
`labs-bad` fixture served a file literally named `.env`, which is matched by common
gitignore rules — including global ones a project cannot override. The file was present
in the working tree and absent from a fresh clone, so the fixture silently lost its
point while every check still passed.

The rules below make that class of failure impossible to reintroduce quietly.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from scopelens.config import REPO_ROOT

LABS = REPO_ROOT / "labs"
BAD_NGINX = LABS / "fixtures" / "bad" / "nginx.conf"
GOOD_NGINX = LABS / "fixtures" / "good" / "nginx.conf"
EDGE_NGINX = LABS / "fixtures" / "edge" / "nginx.conf"
SEED = LABS / "scripts" / "seed.sh"

# Extensions and names that automated tooling treats as secrets or build output.
# A fixture that depends on one of these can vanish from a fresh checkout.
UNTRACKABLE_NAMES = re.compile(r"^\.env(\.|$)")

DEDICATED_FIXTURES = {
    "labs-browser-workflows",
    "labs-callbacks",
    "labs-discovery-a",
    "labs-discovery-b",
    "labs-academic-a",
    "labs-academic-b",
    "labs-session-expiry-a",
    "labs-session-expiry-b",
    "labs-academic-faults",
}


def fixture_compose() -> dict:
    from scopelens.domain.lab import load_lab_services

    base = yaml.safe_load((LABS / "docker-compose.yml").read_text(encoding="utf-8"))
    allowlist = load_lab_services(REPO_ROOT / "deploy" / "lab_services.yaml")
    fixture_ids = {service.id for service in allowlist.services}
    services = dict(base["services"])
    for path in sorted(LABS.glob("*.compose.yml")):
        extra = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not fixture_ids.intersection(extra["services"]):
            continue
        duplicates = services.keys() & extra["services"].keys()
        assert not duplicates, f"duplicate fixture services in {path.name}: {sorted(duplicates)}"
        services.update(extra["services"])
    return {**base, "services": services}


class TestComposeFixtureInventory:
    def test_every_allowlisted_fixture_is_loaded(self) -> None:
        from scopelens.domain.lab import load_lab_services

        allowlist = load_lab_services(REPO_ROOT / "deploy" / "lab_services.yaml")
        assert {service.id for service in allowlist.services} <= fixture_compose()[
            "services"
        ].keys()

    def test_duplicate_service_across_compose_files_is_rejected(
        self, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setitem(fixture_compose.__globals__, "LABS", tmp_path)
        fixture = "services:\n  labs-good:\n    image: synthetic-fixture\n"
        (tmp_path / "docker-compose.yml").write_text(fixture)
        (tmp_path / "duplicate.compose.yml").write_text(fixture)
        with pytest.raises(AssertionError, match="duplicate fixture services"):
            fixture_compose()


def all_fixture_files() -> list[Path]:
    """Committed fixture assets, excluding the generated certificate directory.

    ``fixtures/certs/`` is produced by ``labs/scripts/seed.sh`` and gitignored, so it is
    legitimately absent on a fresh clone. Everything else must be present, because a
    fixture that depends on a generated asset would silently degrade.
    """
    certs = LABS / "fixtures" / "certs"
    return sorted(
        p for p in (LABS / "fixtures").rglob("*") if p.is_file() and certs not in p.parents
    )


class TestNoUntrackableFixtureFiles:
    def test_no_fixture_file_is_named_like_a_secret(self) -> None:
        offenders = [
            str(p.relative_to(LABS)) for p in all_fixture_files() if UNTRACKABLE_NAMES.match(p.name)
        ]
        assert not offenders, (
            "these fixture files would be hidden by common gitignore rules, including "
            f"global ones: {offenders}. Rename them and serve the realistic path via an "
            "nginx alias instead."
        )

    def test_no_fixture_depends_on_a_generated_certificate(self) -> None:
        for path in all_fixture_files():
            assert path.suffix not in {".crt", ".key", ".pem"}, path

    def test_expected_fixture_files_are_present(self) -> None:
        relative = {str(p.relative_to(LABS)) for p in all_fixture_files()}
        for required in (
            "fixtures/bad/html/index.html",
            "fixtures/bad/html/files/notes.txt",
            "fixtures/bad/html/fixture-files/synthetic-dotenv.txt",
            "fixtures/bad/html/fixture-files/synthetic-backup.sql",
            "fixtures/good/html/index.html",
            "fixtures/good/html/files/notes.txt",
        ):
            assert required in relative, required


class TestSeedScriptMatchesReality:
    def test_every_required_file_in_seed_sh_exists(self) -> None:
        """seed.sh fails the whole reset if a required file is missing.

        Keeping the list and the filesystem in agreement here means a missing fixture is
        caught by `make test` rather than by a broken lab reset.
        """
        script = SEED.read_text(encoding="utf-8")
        block = re.search(r"for required in(.*?)\ndo\b", script, re.DOTALL)
        assert block, "seed.sh no longer has a `for required in` block"

        # The paths are written as "$labs_dir/fixtures/...".
        required = re.findall(r"\$labs_dir/(fixtures/[^\s\"]+)", block.group(1))
        assert required, "seed.sh declares no required fixture files"

        for relative in required:
            assert (LABS / relative).is_file(), f"seed.sh requires a missing file: {relative}"

    def test_seed_script_requires_the_sensitive_file_fixtures(self) -> None:
        script = SEED.read_text(encoding="utf-8")
        assert "synthetic-dotenv.txt" in script
        assert "synthetic-backup.sql" in script


class TestFixtureContentIsSynthetic:
    @pytest.mark.parametrize(
        "path",
        [
            LABS / "fixtures" / "bad" / "html" / "fixture-files" / "synthetic-dotenv.txt",
            LABS / "fixtures" / "bad" / "html" / "fixture-files" / "synthetic-backup.sql",
        ],
    )
    def test_exposed_file_fixtures_are_marked_synthetic(self, path: Path) -> None:
        """Build Plan §7: synthetic data only. A reader must never mistake these for real."""
        assert "SYNTHETIC" in path.read_text(encoding="utf-8")

    def test_no_fixture_leaks_private_key_material(self) -> None:
        """Fixture files are committed, so none may contain embedded key material."""
        for path in all_fixture_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert "-----BEGIN" not in text, path


class TestNginxServesTheRealisticPaths:
    def test_bad_fixture_aliases_the_env_path(self) -> None:
        config = BAD_NGINX.read_text(encoding="utf-8")
        assert "location = /.env" in config
        assert "synthetic-dotenv.txt" in config

    def test_bad_fixture_aliases_the_backup_path(self) -> None:
        config = BAD_NGINX.read_text(encoding="utf-8")
        assert "location = /backup.sql" in config
        assert "synthetic-backup.sql" in config

    def test_good_fixture_returns_404_for_both_paths(self) -> None:
        config = GOOD_NGINX.read_text(encoding="utf-8")
        assert "location = /.env" in config
        assert "location = /backup.sql" in config
        assert config.count("return 404") >= 2

    def test_good_fixture_disables_directory_listing(self) -> None:
        assert "autoindex off" in GOOD_NGINX.read_text(encoding="utf-8")


class TestLabNetworkIsolation:
    def test_fixture_network_is_internal(self) -> None:
        compose = fixture_compose()
        assert compose["networks"]["labs_net"]["internal"] is True

    def test_no_fixture_publishes_a_port(self) -> None:
        """Fixtures sit on an internal network, so they cannot publish ports at all."""
        compose = fixture_compose()
        for name in (
            "labs-bad",
            "labs-good",
            "juice-shop",
            *sorted(DEDICATED_FIXTURES),
        ):
            assert "ports" not in compose["services"][name], name

    def test_only_the_edge_forwarder_publishes_ports(self) -> None:
        compose = fixture_compose()
        published = compose["services"]["labs-edge"]["ports"]
        assert published
        for mapping in published:
            assert mapping.startswith("127.0.0.1:"), mapping

    def test_only_the_edge_joins_the_non_internal_network(self) -> None:
        """If a fixture joined labs_edge it would gain a route out."""
        compose = fixture_compose()
        for name, service in compose["services"].items():
            networks = service.get("networks") or {}
            if name == "labs-edge":
                assert "labs_edge" in networks
            else:
                assert "labs_edge" not in networks, name

    def test_edge_forwards_only_to_fixtures(self) -> None:
        """The forwarder must be a fixed-destination mapping, never an open proxy."""
        config = EDGE_NGINX.read_text(encoding="utf-8")
        targets = re.findall(r"proxy_pass\s+([^;]+);", config)
        assert targets, "edge config declares no upstreams"
        for target in targets:
            assert target in {
                "labs-bad:80",
                "labs-bad:8443",
                "labs-good:80",
                "labs-good:8443",
                "labs-validation:8080",
            }, target

    def test_edge_upstreams_match_the_allowlist_ports(self) -> None:
        from scopelens.domain.lab import load_lab_services

        allowlist = load_lab_services(REPO_ROOT / "deploy" / "lab_services.yaml")
        config = EDGE_NGINX.read_text(encoding="utf-8")

        for service in allowlist.services:
            if service.id.startswith("labs-holdout-"):
                import yaml

                compose = yaml.safe_load((REPO_ROOT / "labs/holdout.compose.yml").read_text())
                fixture = compose["services"][service.id]
                assert fixture["profiles"] == ["holdout"]
                assert set(fixture["networks"]) == {"labs", "private"}
                assert all(p.startswith("127.0.0.1:") for p in fixture["ports"])
                assert fixture["networks"]["labs"]["ipv4_address"] in service.addresses
                assert f"proxy_pass {service.id}:" not in config
                continue
            if service.id in DEDICATED_FIXTURES:
                # Dedicated development fixtures are reachable only through the broker.
                compose = fixture_compose()
                fixture = compose["services"][service.id]
                assert set(fixture["networks"]) == {"labs_net"}
                assert not fixture.get("ports")
                assert fixture["networks"]["labs_net"]["ipv4_address"] in service.addresses
                assert f"proxy_pass {service.id}:" not in config
                continue
            if service.id == "juice-shop":
                # This optional fixture is assessed from the isolated worker/evaluator
                # network; it deliberately has no host-facing edge listener.
                compose = fixture_compose()
                assert compose["services"][service.id]["profiles"] == ["juice-shop"]
                assert not compose["services"][service.id].get("ports")
                continue
            for port in service.ports:
                assert f"proxy_pass {service.id}:{port};" in config, f"{service.id}:{port}"
