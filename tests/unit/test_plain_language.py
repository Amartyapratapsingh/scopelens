"""Public explanations must not turn candidates or missing guards into exploit proof."""

from pathlib import Path

import yaml

from scopelens.writer.plain_language import COPY, explain


def test_every_shipped_control_has_a_plain_explanation():
    ids = {
        yaml.safe_load(path.read_text())["id"]
        for path in Path("checks_registry").rglob("SL-*.yaml")
    }
    assert ids <= COPY.keys()
    for entry in COPY.values():
        assert all(entry[key] for key in ("title", "what", "why", "fix", "limit"))


def test_cookie_guard_does_not_claim_login_bypass():
    result = explain("SL-C02-COOKIE-01", "confirmed", ["/auerp/Login.do"])
    assert "/auerp/Login.do" in result["what"]
    assert "did not demonstrate" in result["why"]
    assert "bypassing the login" in result["why"]


def test_sql_candidate_is_not_a_demonstrated_exploit():
    result = explain("SL-C03-SQL-01", "potential", ["/search"])
    assert result["title"].startswith("Possible issue:")
    assert "still needs verification" in result["what"]
    assert "Repeated controlled" not in result["what"]
    assert "did not extract a database" in result["why"]


def test_scope_uses_recorded_locations_only_and_unknown_control_has_no_invented_copy():
    result = explain("SL-C04-CSP-01", "confirmed", ["/", "/", "/page", "/other", "/fourth"])
    assert "1 more recorded locations" in result["what"]
    assert "login" not in result["what"]
    assert explain("unmapped-new-check", "confirmed", ["/"]) is None
