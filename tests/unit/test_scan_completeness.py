"""Budget continuations, native TLS inventory and stable ecosystem ranges."""

import hashlib
from types import SimpleNamespace

import httpx
import pytest
from tests.unit.test_m2_crawler import crawler

from scopelens.adapters.scanners import omitted_active_controls, parse_output, scanner_profile_view
from scopelens.broker.tls_tool import measure_negotiation
from scopelens.checks.advisories import affected_version, load_bundle
from scopelens.checks.conditional import approvals
from scopelens.config import Settings
from scopelens.domain.enums import ProfileName


def test_crawl_continues_frontier_only_inside_hard_allowance(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("scopelens.checks.crawl.time.monotonic", lambda: clock[0])
    worker = crawler(lambda _: None, max_duration_seconds=10, hard_duration_seconds=35)
    clock[0] = 11
    assert worker._remaining_time() == 24
    assert worker._extensions == 1
    clock[0] = 36
    assert worker._remaining_time() < 0
    assert worker._duration == 35


def test_repeated_transport_errors_do_not_extend_crawl(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("scopelens.checks.crawl.time.monotonic", lambda: clock[0])
    worker = crawler(lambda _: None, max_duration_seconds=10, hard_duration_seconds=35)
    worker._stats = worker._stats.model_copy(update={"errors": 3})
    clock[0] = 11
    assert worker._remaining_time() < 0
    assert worker._extensions == 0


def test_continued_crawl_reaches_remaining_links_without_repeating_requests(monkeypatch):
    clock = [0.0]
    seen = []
    monkeypatch.setattr("scopelens.checks.crawl.time.monotonic", lambda: clock[0])

    def reply(request):
        seen.append(request.url.path)
        clock[0] += 2
        body = '<a href="/remaining">Next</a>' if request.url.path == "/" else "fixture"
        return httpx.Response(
            200 if request.url.path in {"/", "/remaining"} else 404,
            text=body,
            headers={"content-type": "text/html"},
        )

    result = crawler(reply, max_duration_seconds=8, hard_duration_seconds=50).run()
    assert "/remaining" in seen
    assert len(seen) == len(set(seen))
    assert result.surface.stats.budget_extensions > 0
    assert result.surface.stats.stopped_by is None


def test_cors_default_uses_only_authorized_seed_and_active_profile():
    scope = SimpleNamespace(
        allowed_check_profile=ProfileName.EXTERNAL_DAST,
        lab_binding=None,
        origin="https://approved.test",
        allowed_methods=("GET",),
        allowed_path_prefixes=("/app",),
        excluded_paths=(),
    )
    assert approvals(Settings(), scope) == [
        {"kind": "cors", "path": "/app", "review": "cors-approved-seed-v1"}
    ]
    scope.allowed_check_profile = ProfileName.EXTERNAL_CONFIGURATION
    assert approvals(Settings(), scope) == []
    scope.allowed_check_profile = ProfileName.EXTERNAL_DAST
    scope.excluded_paths = ("/app",)
    assert approvals(Settings(), scope) == []
    scope.excluded_paths = ()
    scope.allowed_methods = ("HEAD",)
    assert approvals(Settings(), scope) == []


@pytest.mark.parametrize("ecosystem", ["PyPI", "Maven"])
def test_numeric_ecosystem_ranges_have_exact_fixed_boundaries(ecosystem):
    affected = {
        "package": {"ecosystem": ecosystem},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.1.3"}]}],
    }
    assert affected_version("2.1.2", affected) is True
    assert affected_version("2.1.3", affected) is False
    assert affected_version("2.1.3-vendor", affected) is None
    assert affected_version("2.1", affected) is None
    affected["package"]["ecosystem"] = "Debian:12"
    assert affected_version("2.1.3", affected) is None


def test_advisory_pin_rejects_changed_bytes(tmp_path):
    path = tmp_path / "snapshot.json"
    raw = b'{"version":"test","source":"synthetic","packages":{},"records":[]}'
    path.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    assert load_bundle(path, expected_sha256=digest)["sha256"] == digest
    path.write_bytes(raw + b"\n")
    with pytest.raises(ValueError, match="content pin"):
        load_bundle(path, expected_sha256=digest)


def test_warning_rule_ids_never_count_as_assessed():
    result = parse_output(
        "testssl", "test", '[{"id":"ALPN","severity":"WARN","finding":"unsupported"}]'
    )
    assert result.state == "error"
    assert not result.assessed_rule_ids


@pytest.mark.parametrize(
    "profile,changes",
    [
        ("external-dast", {}),
        ("external-configuration", {"state": "error"}),
        ("external-configuration", {"errors": ["actual missing binary"]}),
        ("external-configuration", {"assessed_rule_ids": ["cors"]}),
    ],
)
def test_profile_exclusion_never_hides_active_approval_or_real_failure(profile, changes):
    original = {
        "tool": "conditional-config",
        "state": "not_tested",
        "observations": [],
        "assessed_rule_ids": [],
        "errors": ["No reviewed endpoints enabled for this profile and origin"],
        **changes,
    }
    assert scanner_profile_view([original], profile) == [original]


def test_profile_exclusions_match_the_reviewed_registry():
    from scopelens.domain.registry import load_registry

    registry = load_registry(Settings().checks_registry_dir)
    enabled = {row.id for row in registry.for_profile(ProfileName.EXTERNAL_CONFIGURATION)}
    active = {row.id for row in registry.for_profile(ProfileName.EXTERNAL_DAST)}
    omitted = omitted_active_controls("external-configuration")
    assert len(omitted) == 5
    assert all(row["check_id"] in active - enabled for row in omitted)
    assert all(
        row["state"] == "not_in_profile" and row["reason"] == "Not in profile" for row in omitted
    )


def test_worker_cannot_claim_an_active_control_is_outside_the_trusted_profile():
    original = {
        "tool": "conditional-config",
        "state": "not_tested",
        "errors": ["No reviewed endpoints enabled for this profile and origin"],
        "not_in_profile_controls": omitted_active_controls("external-configuration"),
    }
    public = scanner_profile_view([original], "external-dast")[0]
    assert public["errors"] == original["errors"]
    assert "not_in_profile_controls" not in public
    assert original["not_in_profile_controls"]


def test_native_negotiation_uses_admitted_proxy_and_requires_handshake(monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout=b"New, TLSv1.2, Cipher is TLS_TEST\nNo ALPN negotiated\n",
            stderr=b"",
        )

    monkeypatch.setattr("scopelens.broker.tls_tool.subprocess.run", run)
    gate = SimpleNamespace(proxy="127.0.0.1:1234", live=lambda: True)
    observations, errors, assessed = measure_negotiation("approved.test", 443, gate, timeout=3)
    assert assessed == ["ALPN", "NPN"] and not errors
    assert all(command[command.index("-proxy") + 1] == gate.proxy for command in commands)
    assert all(o.reported_severity == "informational" for o in observations)
    monkeypatch.setattr(
        "scopelens.broker.tls_tool.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
    )
    assert measure_negotiation("approved.test", 443, gate, timeout=3)[1]
