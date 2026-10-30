import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from scopelens.checks.packs.tooling import (
    ActiveRuleBinding,
    reviewed_templates,
    zap_active_admission,
)

ROOT = Path("checks_registry/tooling/expansion")


def test_reviewed_bundle_hashes_technology_selection_and_mapping():
    assert len(reviewed_templates(ROOT)) == 2
    rows = reviewed_templates(ROOT, ["php", "apache", "spring"])
    assert len(rows) == 5
    assert all(
        r.control_id.startswith("SL-C05-") and r.review_state == "experimental" for r in rows
    )


def test_tampered_bundle_fails_closed(tmp_path):
    import shutil

    shutil.copytree(ROOT, tmp_path / "bundle")
    path = tmp_path / "bundle" / "scopelens-private-key-candidate.yaml"
    path.write_text(path.read_text() + "\n# changed\n")
    with pytest.raises(ValueError, match="integrity"):
        reviewed_templates(path.parent)


def test_active_rule_exact_parameter_binding():
    binding = ActiveRuleBinding(
        url="https://site.test/search?q=normal&tenant=synthetic", parameter="q"
    )
    assert binding.accepts("GET", "https://site.test/search?q=marker&tenant=synthetic")
    for method, url, body in [
        ("POST", binding.url, b""),
        ("GET", "https://site.test/search?q=a&tenant=other", b""),
        ("GET", "https://site.test/search?q=a&q=b&tenant=synthetic", b""),
        ("GET", "https://site.test/elsewhere?q=a&tenant=synthetic", b""),
        ("GET", "https://foreign.test/search?q=a&tenant=synthetic", b""),
        ("GET", binding.url, b"body"),
    ]:
        assert not binding.accepts(method, url, body)
    assert zap_active_admission(binding, transport_capability=None)["state"] == "blocked"


def test_unreviewed_active_rule_is_rejected():
    with pytest.raises(ValidationError):
        ActiveRuleBinding(rule_id=40018, url="https://site.test/?q=a", parameter="q")
    with pytest.raises(ValidationError):
        ActiveRuleBinding(url="https://site.test/?other=a", parameter="q")


def test_manifest_pins_and_maps_every_template():
    manifest = json.loads((ROOT / "manifest.json").read_text())
    for record in manifest["templates"]:
        assert hashlib.sha256((ROOT / record["file"]).read_bytes()).hexdigest() == record["sha256"]
        assert (ROOT / (record["control_id"] + ".yaml")).is_file()
