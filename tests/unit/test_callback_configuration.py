"""Callback configuration is explicit, secret-bearing and immutable."""

import uuid

import pytest
from pydantic import ValidationError

from scopelens.config import Settings
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.client import AssessmentControlClient


def test_callback_defaults_disabled_and_both_settings_required():
    assert not Settings(_env_file=None).callbacks_enabled
    assert not Settings(
        _env_file=None, callback_collector_origins=("https://collector.test",)
    ).callbacks_enabled
    assert not Settings(_env_file=None, callback_signing_key="x" * 32).callbacks_enabled
    configured = Settings(
        _env_file=None,
        callback_collector_origins=("https://collector.test",),
        callback_signing_key="x" * 32,
    )
    assert configured.callbacks_enabled
    assert "x" * 32 not in repr(configured)


@pytest.mark.parametrize(
    "origin",
    [
        "ftp://collector.test",
        "https://user:pass@collector.test",
        "https://collector.test/collect",
        "https://collector.test?key=secret",
        "https://collector.test#fragment",
        "https://collector.test:invalid",
    ],
)
def test_collector_origin_is_exact(origin):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, callback_collector_origins=(origin,))


def test_key_too_short():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, callback_signing_key="short")


def test_named_recipes_frozen_and_no_worker_authority_fields():
    config = AssessmentConfiguration(scope_version_id=uuid.uuid4())
    with pytest.raises(ValidationError):
        config.callback_recipes = ()
    for payload in (
        {"operation": "issue", "owner_id": "other"},
        {"operation": "capture"},
        {"operation": "issue", "expected_target_peers": ["192.0.2.1"]},
    ):
        # Validation must reject before a client/socket is needed.
        with pytest.raises(ValueError):
            AssessmentControlClient.callback_rpc(None, payload)
