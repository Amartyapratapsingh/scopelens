"""A lock token is checked; evaluators never acquire or delete locks themselves."""

import pytest
from evaluation import holdout_lab


def test_without_helper_token_cannot_enter_or_delete_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(holdout_lab, "STACK_LOCK", tmp_path)
    monkeypatch.delenv(holdout_lab.LOCK_TOKEN_ENV, raising=False)
    owner = tmp_path / "owner"
    owner.write_text("another-lane pid=123")
    with pytest.raises(RuntimeError, match="require the shared"), holdout_lab.stack_lock():
        pytest.fail("unlocked operation executed")
    assert owner.read_text() == "another-lane pid=123"


def test_changed_helper_owner_invalidates_without_removing_replacement(tmp_path, monkeypatch):
    monkeypatch.setattr(holdout_lab, "STACK_LOCK", tmp_path)
    token = "holdout-benchmark pid=456"
    monkeypatch.setenv(holdout_lab.LOCK_TOKEN_ENV, token)
    owner = tmp_path / "owner"
    owner.write_text(token)
    with pytest.raises(RuntimeError, match="ownership changed"), holdout_lab.stack_lock():
        owner.write_text("replacement-lane pid=789")
    assert owner.read_text() == "replacement-lane pid=789"
