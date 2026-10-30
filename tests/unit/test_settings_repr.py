"""Settings diagnostics omit credential-bearing endpoints without changing values."""

from typing import get_args

import pytest
from pydantic import SecretStr

from scopelens.config import ModelRoleSettings, Settings


def configured(**values):
    return Settings(
        _env_file=None,
        environment="test",
        zap_active_lab_enabled=False,
        callback_collector_origins=(),
        **values,
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("database_url", "postgresql+psycopg://diagnostic-user:diagnostic-password@db.test/db"),
        ("redis_url", "redis://diagnostic-user:diagnostic-password@redis.test/0"),
        ("docker_host", "tcp://diagnostic-user:diagnostic-password@docker.test:2376"),
        ("model_gateway_url", "https://diagnostic-user:diagnostic-password@models.test"),
        ("sandbox_gateway_url", "https://diagnostic-user:diagnostic-password@sandbox.test"),
        ("policy_service_url", "https://diagnostic-user:diagnostic-password@policy.test"),
        ("tls_lane_url", "https://diagnostic-user:diagnostic-password@tls.test"),
        ("proxy_host", "diagnostic-user:diagnostic-password@proxy.test"),
    ],
)
def test_credential_endpoints_absent_from_repr_and_str_but_usable(field, value):
    settings = configured(**{field: value})
    for diagnostic in (repr(settings), str(settings)):
        assert "diagnostic-user" not in diagnostic
        assert "diagnostic-password" not in diagnostic
        assert field + "=" not in diagnostic
    assert type(getattr(settings, field)) is str
    assert getattr(settings, field) == value
    assert settings.model_dump()[field] == value


def test_database_and_redis_credentials_hidden_together():
    settings = configured(
        database_url="postgresql+psycopg://db-user:unique-db-password@db.test/db",
        redis_url="redis://redis-user:unique-redis-password@redis.test/0",
    )
    for diagnostic in (repr(settings), str(settings)):
        assert "unique-db-password" not in diagnostic
        assert "unique-redis-password" not in diagnostic


@pytest.mark.parametrize(
    "role", ["planner_model", "browser_model", "verification_model", "report_writer_model"]
)
def test_nested_model_and_fallback_credentials_are_hidden(role):
    endpoint = "https://model-user:model-password@models.test/v1"
    fallback = "https://fallback-user:fallback-password@fallback.test/v1"
    model = ModelRoleSettings(
        base_url=endpoint,
        api_key="private-model-key",
        model="fixture-model",
        fallbacks=[ModelRoleSettings(base_url=fallback, model="fixture-fallback")],
    )
    settings = configured(**{role: model}, approved_model_base_urls=[endpoint, fallback])
    for value in (settings, model, model.fallbacks[0]):
        for diagnostic in (repr(value), str(value)):
            for secret in ("model-password", "fallback-password", "private-model-key"):
                assert secret not in diagnostic
    assert model.configured
    assert model.base_url == endpoint
    assert model.fallbacks[0].base_url == fallback
    assert settings.approved_model_base_urls == [endpoint, fallback]
    assert settings.model_dump()[role]["base_url"] == endpoint


def test_dedicated_secret_fields_remain_secretstr():
    # Prevent adding a password/key setting as a diagnostic-visible plain string.
    for model in (Settings, ModelRoleSettings):
        for name, field in model.model_fields.items():
            if any(
                word in name
                for word in ("password", "secret", "api_key", "signing_key", "encryption_key")
            ):
                assert field.annotation is SecretStr or SecretStr in get_args(field.annotation)
