"""Offline, database-free checks for trusted runtime inventory and report gating."""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from scopelens.domain.capabilities import canonical_sha256, runtime_control_decisions
from scopelens.domain.registry import load_registry
from scopelens.execution.capability_probe import (
    PROBE_SHA256,
    PROBE_SOURCE,
    ProbeFailure,
    _run_image_probe,
    build_capability_snapshot,
    collect_runtime_measurement,
)
from scopelens.writer.report import _capabilities

PROFILE = "external-active-v2"
IMAGE = "sha256:" + "1" * 64


def _execute_probe(monkeypatch, tmp_path, capsys):
    import pathlib
    import sys

    original_path = pathlib.Path
    monkeypatch.setattr(
        pathlib, "Path", lambda value: tmp_path if value == "/app/backend" else original_path(value)
    )
    monkeypatch.setattr(sys, "argv", ["sealed-probe", "tool"])
    namespace = {}
    exec(compile(PROBE_SOURCE, "<sealed-probe>", "exec"), namespace)
    import json

    payload = json.loads(capsys.readouterr().out)
    return namespace, payload


def test_executed_probe_matches_coordinator_source_digest(monkeypatch, tmp_path, capsys):
    from scopelens.execution.capability_producer import source_digest

    (tmp_path / "main.py").write_text("x = 1\n")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "worker.py").write_text("y = 2\n")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "ignored.py").write_text("ignored = True\n")
    _, payload = _execute_probe(monkeypatch, tmp_path, capsys)
    assert payload == {
        "version": "runtime-probe-v2",
        "role": "tool",
        "tools": [],
        "source_sha256": source_digest(tmp_path),
    }


@pytest.mark.parametrize(
    ("tool", "stdout", "stderr", "version"),
    [
        ("zap", b"2.16.1\n", b"", "2.16.1"),
        (
            "nuclei",
            b"",
            b"\x1b[34m[INF] Current nuclei version: v3.11.1\x1b[0m\n",
            "[INF] Current nuclei version: v3.11.1",
        ),
        ("testssl", b"Copyright 2026\n testssl.sh 3.2.2\n", b"", "testssl.sh 3.2.2"),
        ("chromium", b"Chromium 153.0.8010.12\n", b"", "Chromium 153.0.8010.12"),
        (
            "chromium",
            b"Google Chrome for Testing 153.0.8010.12 \n",
            b"",
            "Google Chrome for Testing 153.0.8010.12",
        ),
    ],
)
def test_executed_probe_parses_version_banners(
    monkeypatch, tmp_path, capsys, tool, stdout, stderr, version
):
    import os
    import subprocess

    namespace, _ = _execute_probe(monkeypatch, tmp_path, capsys)
    monkeypatch.setattr(os.path, "isfile", lambda path: True)
    monkeypatch.setattr(os, "access", lambda path, mode: True)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr),
    )
    namespace["digest"] = lambda path: "b" * 64
    assert namespace["binary"](tool, "/sealed/tool", ["-version"]) == {
        "name": tool,
        "state": "present",
        "version": version,
        "sha256": "b" * 64,
    }


@pytest.mark.parametrize(
    "tool,stdout,code",
    [
        ("testssl", b"Google Chrome for Testing 153.0.8010.12\n", 0),
        ("chromium", b"Google Chrome for Testing 153.0.8010.12 unexpected\n", 0),
        ("chromium", b"Google Chrome for Testing 153.0.8010.12\n", 1),
    ],
)
def test_branded_chromium_banner_does_not_credit_other_tools_or_failures(
    monkeypatch, tmp_path, capsys, tool, stdout, code
):
    import os
    import subprocess

    namespace, _ = _execute_probe(monkeypatch, tmp_path, capsys)
    monkeypatch.setattr(os.path, "isfile", lambda path: True)
    monkeypatch.setattr(os, "access", lambda path, mode: True)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=code, stdout=stdout, stderr=b""),
    )
    namespace["digest"] = lambda path: "b" * 64
    assert namespace["binary"](tool, "/sealed/tool", ["--version"]) == {
        "name": tool,
        "state": "failed",
    }


def plan():
    return {
        "registry": load_registry(Path("checks_registry")).model_dump(mode="json"),
        "capability_candidate_fingerprint": "a" * 64,
        "capability_execution_plan": {"frozen_revision": "v1"},
        "capability_expected_images": [
            {
                "role": "kali",
                "image_id": IMAGE,
                "architecture": "arm64",
                "probe_sha256": PROBE_SHA256,
            }
        ],
    }


def measurement():
    return {
        "image_bindings": plan()["capability_expected_images"],
        "installation_complete": True,
        "installed_tools": [
            {
                "name": "nuclei",
                "measured_version": "3.11.1",
                "verification_ref": "probe:ref",
                "image_id": IMAGE,
                "binary_sha256": "b" * 64,
            }
        ],
    }


def controls(p):
    from scopelens.domain.enums import ProfileName
    from scopelens.domain.registry import CheckRegistry

    registry = CheckRegistry.model_validate(p["registry"])
    return [
        {
            "control_id": entry.id,
            "runtime_supported": index == 0,
            "prerequisites_satisfied": True,
            "authority_admitted": True,
            "verification_ref": "trusted:decision",
        }
        for index, entry in enumerate(registry.supported_for_profile(ProfileName(PROFILE)))
    ]


def bound():
    p = plan()
    p["capability_snapshot"] = build_capability_snapshot(
        p,
        scan_id="scan-1",
        scope_version_id="scope-1",
        profile=PROFILE,
        measurement=measurement(),
        runtime_controls=controls(p),
    )
    return p


def report(p):
    return _capabilities(p, PROFILE, scan_id="scan-1", scope_version_id="scope-1")


def test_exact_binding_and_enabled_control_decisions():
    p = bound()
    result = report(p)
    assert result["installed_tools"]["names"] == ["nuclei"]
    assert result["executable_checks"]["names"] == [controls(p)[0]["control_id"]]
    assert result["independently_qualified_families"]["count"] is None


def test_control_decisions_use_registered_implementation_and_frozen_admission():
    p = plan()
    first = controls(p)[0]["control_id"]
    no_admission = runtime_control_decisions(p, profile=PROFILE)
    assert any(row["control_id"] == first and row["runtime_supported"] for row in no_admission)
    assert all(not row["authority_admitted"] for row in no_admission)
    p["capability_execution_plan"].update(
        admitted_control_ids=[first], prerequisites_satisfied_ids=[first]
    )
    decisions = runtime_control_decisions(p, profile=PROFILE)
    admitted = [row for row in decisions if row["authority_admitted"]]
    assert len(admitted) == 1
    assert admitted[0]["control_id"] == first
    assert admitted[0]["prerequisites_satisfied"] is True


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["capability_snapshot"].update(scan_id="wrong"),
        lambda p: p["capability_snapshot"].update(scope_version_id="wrong"),
        lambda p: p["capability_snapshot"]["image_bindings"][0].update(
            image_id="sha256:" + "2" * 64
        ),
        lambda p: p["capability_execution_plan"].update(frozen_revision="stale"),
        lambda p: p["registry"]["entries"].pop(),
        lambda p: p.update(capability_candidate_fingerprint="c" * 64),
    ],
)
def test_mismatched_or_stale_snapshot_is_unknown(change):
    p = bound()
    change(p)
    result = report(p)
    assert result["installed_tools"]["count"] is None
    assert result["executable_checks"]["count"] is None


def test_partial_probe_and_incomplete_control_inventory_are_unknown():
    p = bound()
    p["capability_snapshot"]["installation_complete"] = False
    p["capability_snapshot"]["runtime_controls"].pop()
    result = report(p)
    assert result["installed_tools"]["count"] is None
    assert result["executable_checks"]["count"] is None


def test_string_boolean_cannot_claim_complete_inventory():
    p = bound()
    p["capability_snapshot"]["installation_complete"] = "true"
    assert report(p)["installed_tools"]["count"] is None


def test_qualification_requires_independent_matching_record():
    p = bound()
    snap = p["capability_snapshot"]
    snap["qualification"] = {
        "version": "qualification-v2",
        "partition": "holdout",
        "verification_ref": "holdout",
        "curator_ref": "independent-curator",
        "candidate_fingerprint": "a" * 64,
        "manifest_sha256": "d" * 64,
        "registry_sha256": snap["registry_sha256"],
        "image_binding_sha256": canonical_sha256(snap["image_bindings"]),
        "frozen_before_run": True,
        "contaminated": False,
        "families": {"F01": {"qualified": True}},
    }
    assert report(p)["independently_qualified_families"]["count"] is None
    p["capability_qualification_manifest_sha256"] = "d" * 64
    p["capability_qualification_verification_ref"] = "holdout"
    p["capability_qualification_curator_ref"] = "independent-curator"
    assert report(p)["independently_qualified_families"]["names"] == ["F01"]
    stale = deepcopy(p)
    stale["capability_snapshot"]["qualification"]["candidate_fingerprint"] = "b" * 64
    assert report(stale)["independently_qualified_families"]["count"] is None
    p["capability_snapshot"]["qualification"]["partition"] = "development"
    assert report(p)["independently_qualified_families"]["count"] is None


def test_probe_uses_resolved_image_no_network_mount_or_scan_credentials():
    container = Mock()
    container.image.id = IMAGE
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = [
        b'{"version":"runtime-probe-v2","role":"tool","tools":[],"source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    ]
    client = Mock()
    client.images.get.return_value = SimpleNamespace(id=IMAGE, attrs={"Architecture": "arm64"})
    client.containers.run.return_value = container
    binding, tools, source = _run_image_probe(client, "tool", "configured:tag")
    assert tools == [] and binding.image_id == IMAGE
    assert source == "a" * 64
    kwargs = client.containers.run.call_args.kwargs
    assert kwargs["image"] == IMAGE
    assert kwargs["network_mode"] == "none"
    assert kwargs["read_only"] is True
    assert "volumes" not in kwargs and "mounts" not in kwargs
    assert "SCOPELENS_TARGET_URL" not in kwargs["environment"]
    container.remove.assert_called_once()


def test_failed_probe_never_means_measured_absence():
    client = Mock()
    client.images.get.return_value = SimpleNamespace(id=IMAGE, attrs={"Architecture": "arm64"})
    client.containers.run.return_value.wait.side_effect = TimeoutError()
    with pytest.raises(ProbeFailure):
        _run_image_probe(client, "tool", "configured:tag")
    result = collect_runtime_measurement(client, image_refs={"tool": "configured:tag"})
    assert result["installation_complete"] is False
    assert result["installed_tools"] == []


@pytest.mark.parametrize(
    "output",
    [
        [b"not json"],
        [
            b'{"version":"runtime-probe-v2","role":"browser","tools":[],"source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
        ],
        [
            b'{"version":"runtime-probe-v2","role":"tool","tools":[],"source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
            b"fake",
        ],
        [b"x" * 12_001],
    ],
)
def test_malformed_or_spoofed_probe_output_fails_closed(output):
    client = Mock()
    client.images.get.return_value = SimpleNamespace(id=IMAGE, attrs={"Architecture": "arm64"})
    container = client.containers.run.return_value
    container.image.id = IMAGE
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = output
    with pytest.raises(ProbeFailure):
        _run_image_probe(client, "tool", "configured:tag")


def test_ordinary_worker_stdout_is_not_a_capability_source():
    p = plan()
    p["scanner_results"] = [
        {
            "tool": "nuclei",
            "version": "3",
            "output_hash": "x",
            "state": "completed",
            "capability_snapshot": "spoof",
        }
    ]
    result = report(p)
    assert result["observed_tools"]["count"] == 1
    assert result["installed_tools"]["count"] is None
