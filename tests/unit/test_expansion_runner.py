"""Pinned tool adapter process/manifest/parser contracts; no external requests."""

import hashlib
import json
import os
import shutil
import sys
import time
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from scopelens.adapters import expansion_runner as runner
from scopelens.adapters.scanners import parse_output
from scopelens.checks.packs.tooling import reviewed_templates

BUNDLE = Path("checks_registry/tooling/expansion")


def output_line(pin, url):
    return json.dumps(
        {
            "template-id": pin.id,
            "info": {"name": "Fixture observation", "severity": "high"},
            "matched-at": url,
            "response": "private-fixture-response",
        }
    )


def test_reviewed_engine_binary_pins_derive_from_verified_archives():
    manifest = json.loads(Path("checks_registry/tooling/releases.json").read_text())
    actual = set()
    for arch in ("arm64", "amd64"):
        entry = manifest["nuclei-" + arch]
        archive = Path("workers/vendor") / entry["file"]
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == entry["sha256"]
        with zipfile.ZipFile(archive) as source:
            actual.add(hashlib.sha256(source.read("nuclei")).hexdigest())
    assert actual == runner.ENGINE_SHA256


def test_engine_tamper_rejected(tmp_path):
    binary = tmp_path / "nuclei"
    binary.write_bytes(b"unreviewed-executable")
    with pytest.raises(ValueError, match="integrity"):
        runner.verify_engine(binary)


def configure(monkeypatch):
    monkeypatch.setattr(runner, "verify_engine", lambda _: next(iter(runner.ENGINE_SHA256)))
    monkeypatch.setenv("HTTP_PROXY", "http://reviewed-broker:8098")
    monkeypatch.setenv("SCOPELENS_EGRESS_TOKEN", "fixture-token")

    def bridge(proxy, token):
        assert proxy == "http://reviewed-broker:8098" and token == "fixture-token"
        return nullcontext("http://127.0.0.1:8765")

    monkeypatch.setattr(runner, "Bridge", bridge)


def test_all_five_templates_are_fixed_bounded_and_candidate_only(monkeypatch):
    configure(monkeypatch)
    calls = []
    pins = reviewed_templates(BUNDLE, ("php", "apache", "spring"))
    by_file = {pin.file: pin for pin in pins}

    def invoke(command, output, environment, *, timeout, cancelled):
        calls.append(command)
        path = Path(command[command.index("-t") + 1])
        pin = by_file[path.name]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == pin.sha256
        assert command[command.index("-proxy") + 1] == "http://127.0.0.1:8765"
        assert command[command.index("-H") + 1] == "x-scopelens-egress: fixture-token"
        for flag in (
            "-no-interactsh",
            "-disable-redirects",
            "-disable-clustering",
            "-omit-raw",
            "-disable-update-check",
            "-no-httpx",
            "-no-stdin",
        ):
            assert flag in command
        assert command[command.index("-retries") + 1] == "0"
        assert command[command.index("-response-size-read") + 1] == "65536"
        assert 0 < timeout <= 25
        assert "SCOPELENS_EXPANSION_CAPABILITY" not in environment
        assert "SCOPELENS_EGRESS_TOKEN" not in environment
        return parse_output("nuclei", "3.11.1", output_line(pin, "https://fixture.test" + pin.path))

    monkeypatch.setattr(runner, "_invoke", invoke)
    results = list(
        runner.run_expansion_tools(
            SimpleNamespace(origin="https://fixture.test"),
            technologies=("php", "apache", "spring"),
            bundle=BUNDLE,
        )
    )
    assert len(calls) == len(results) == 5
    for result, pin in zip(results, pins, strict=True):
        assert result.state == "completed"
        assert result.observations[0].status == "potential"
        assert result.observations[0].mapped_control == pin.control_id
        assert "private-fixture-response" not in result.model_dump_json()
        assert result.assessed_rule_ids == []
        assert result.template_hash


def test_manifest_tampering_and_missing_proxy_do_not_launch(monkeypatch, tmp_path):
    configure(monkeypatch)
    monkeypatch.setattr(runner, "_invoke", lambda *args, **kwargs: pytest.fail("must not launch"))
    shutil.copytree(BUNDLE, tmp_path / "bundle")
    manifest = tmp_path / "bundle/manifest.json"
    manifest.write_text(manifest.read_text() + "\n")
    assert (
        next(
            runner.run_expansion_tools(
                SimpleNamespace(origin="https://fixture.test"), bundle=manifest.parent
            )
        ).state
        == "not_tested"
    )
    monkeypatch.delenv("HTTP_PROXY")
    assert (
        next(
            runner.run_expansion_tools(
                SimpleNamespace(origin="https://fixture.test"), bundle=BUNDLE
            )
        ).state
        == "not_tested"
    )


def test_output_wrong_rule_or_destination_cannot_acquire_mapping():
    pin = reviewed_templates(BUNDLE)[0]
    result = parse_output("nuclei", "3.11.1", output_line(pin, "https://other.test" + pin.path))
    result = runner._bind_observations(result, pin, "https://fixture.test")
    assert result.state == "error" and not result.observations
    result = parse_output(
        "nuclei",
        "3.11.1",
        output_line(pin, "https://fixture.test" + pin.path).replace(pin.id, "unreviewed-rule"),
    )
    assert runner._bind_observations(result, pin, "https://fixture.test").state == "error"


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("valid", "completed"),
        ("empty", "completed"),
        ("malformed", "partial"),
        ("nonzero", "partial"),
        ("timeout", "timeout"),
        ("cancel", "cancelled"),
        ("truncated", "partial"),
    ],
)
def test_real_process_partial_output_and_stop_contract(tmp_path, mode, expected):
    output = tmp_path / "out.jsonl"
    pin = reviewed_templates(BUNDLE)[0]
    line = output_line(pin, "https://fixture.test" + pin.path) + "\n"
    script = "import pathlib,time,sys\np=pathlib.Path(sys.argv[1])\n"
    script += "p.write_text(" + repr("" if mode == "empty" else line) + ")\n"
    if mode == "malformed":
        script += "with p.open('a') as f: f.write('{bad-json')\n"
    elif mode == "truncated":
        script += "with p.open('a') as f: f.write('x' * 1100000)\n"
    elif mode in {"timeout", "cancel"}:
        script += "time.sleep(20)\n"
    elif mode == "nonzero":
        script += "sys.exit(2)\n"
    started = time.monotonic()
    result = runner._invoke(
        [sys.executable, "-c", script, str(output)],
        output,
        dict(os.environ),
        timeout=0.4 if mode == "timeout" else 3,
        cancelled=lambda: mode == "cancel" and time.monotonic() - started > 0.2,
    )
    assert result.state == expected, result
    assert time.monotonic() - started < 4
    if mode != "empty":
        assert len(result.observations) == 1
    assert result.output_hash


def test_pre_cancel_does_not_start_process(tmp_path, monkeypatch):
    monkeypatch.setattr(
        runner.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("cancelled process launched"),
    )
    assert (
        runner._invoke(["nuclei"], tmp_path / "out", {}, timeout=1, cancelled=lambda: True).state
        == "cancelled"
    )
