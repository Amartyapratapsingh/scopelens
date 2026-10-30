"""Coordinator inventory must match image source and retain denied decisions."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from tests.unit.test_runtime_capability_measurement import measurement, plan

from scopelens.config import Settings
from scopelens.domain.enums import ProfileName
from scopelens.execution.capability_producer import bind_measurement, source_digest


def scope(**changes):
    return SimpleNamespace(
        **{
            "id": "scope-1",
            "origin": "https://fixture.test",
            "scheme": "https",
            "allowed_path_prefixes": ("/",),
            "excluded_paths": (),
            "allowed_methods": ("GET", "HEAD"),
            "authorization_expires_at": datetime.now(UTC) + timedelta(hours=1),
            "transport_http_port": 80,
            "allowed_check_profile": ProfileName.EXTERNAL_ACTIVE_V2,
            **changes,
        }
    )


def measured():
    result = measurement()
    result["source_sha256"] = source_digest()
    return result


def bind(p=None, target=None, evidence=None):
    return bind_measurement(
        p or plan(),
        scan_id="scan-1",
        scope=target or scope(),
        settings=Settings(_env_file=None),
        measurement=evidence or measured(),
    )


def test_coordinator_source_and_image_binding_produce_complete_inventory():
    result = bind()
    snap = result["capability_snapshot"]
    assert snap["runtime_inventory_complete"]
    assert snap["candidate_fingerprint"] == source_digest()
    assert snap["qualification"] == {}
    decisions = {row["control_id"]: row for row in snap["runtime_controls"]}
    assert decisions["SL-C04-CSP-01"]["authority_admitted"]
    assert not decisions["SL-C06-COMPONENT-01"]["prerequisites_satisfied"]
    assert not any("XSS" in control for control in decisions)


@pytest.mark.parametrize("fault", ["source", "missing_source", "missing_images"])
def test_unmatched_image_measurement_removes_stale_snapshot(fault):
    original = bind()
    evidence = measured()
    if fault == "source":
        evidence["source_sha256"] = "b" * 64
    elif fault == "missing_source":
        evidence.pop("source_sha256")
    else:
        evidence["image_bindings"] = []
    assert "capability_snapshot" not in bind(original, evidence=evidence)


@pytest.mark.parametrize(
    "target",
    [
        scope(allowed_methods=("HEAD",)),
        scope(authorization_expires_at=datetime.now(UTC) - timedelta(hours=1)),
        scope(excluded_paths=("/",)),
    ],
)
def test_missing_scope_prerequisites_never_admit_controls(target):
    result = bind(target=target)
    assert not any(
        row["authority_admitted"] for row in result["capability_snapshot"]["runtime_controls"]
    )


def test_new_plan_is_rebound_without_promoting_measurement_or_qualification():
    original = bind()
    changed = deepcopy(original)
    changed["request_catalogue"] = {"revision": "second"}
    result = bind(changed)
    assert (
        result["capability_snapshot"]["plan_sha256"]
        != original["capability_snapshot"]["plan_sha256"]
    )
    assert result["capability_snapshot"]["qualification"] == {}


def test_source_digest_ignores_bytecode_and_changes_on_source(tmp_path):
    (tmp_path / "a.py").write_text("x=1")
    before = source_digest(tmp_path)
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "a.py").write_text("ignored")
    assert source_digest(tmp_path) == before
    (tmp_path / "a.py").write_text("x=2")
    assert source_digest(tmp_path) != before
