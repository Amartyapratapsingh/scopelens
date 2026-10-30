"""Receiver isolation, key distribution and nonrotating setup contracts."""

import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml
from fastapi.testclient import TestClient
from scripts import bootstrap_env, initialize_callback_key
from tests.unit.test_callback_runtime import call
from tests.unit.test_identity_key_deployment import compose

from scopelens.callback_app import create_callback_app
from scopelens.config import Settings
from scopelens.execution.supervisor import DockerWorkerSupervisor

pytest_plugins = ["tests.unit.test_callback_runtime"]
ROOT = Path(__file__).resolve().parents[2]
KEY = "SCOPELENS_CALLBACK_SIGNING_KEY"


def test_receiver_only_health_and_receipts_and_ignores_forwarded_peer(fixture):
    runtime, task, _ = fixture
    nonce = call(runtime, task, "issue", purpose="negative")["nonce"]
    app = create_callback_app(runtime=runtime)
    with TestClient(app, client=("192.0.2.20", 40000)) as client:
        assert client.get("/healthz").status_code == 200
        for path in (
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/scans",
            "/internal/broker/assessment",
        ):
            assert client.get(path).status_code == 404
        assert client.get("/callback/not-issued").status_code == 404
        response = client.get(
            urlsplit(nonce["url"]).path, headers={"X-Forwarded-For": "192.0.2.10"}
        )
        assert response.status_code == 204
        assert response.headers["cache-control"] == "no-store"
    receipts = runtime.service.receipts(
        nonce["id"], owner_id=task.owner_id, scan_id=task.scan_id, task_id=task.task_id
    )
    assert len(receipts) == 1 and receipts[0].source == "scanner"
    assert receipts[0].peer == "192.0.2.20"


def test_receiver_disabled_without_configuration():
    with pytest.raises(RuntimeError):
        create_callback_app(
            Settings(_env_file=None, callback_collector_origins=(), callback_signing_key=None)
        )


def test_callback_compose_profile_routes_and_secret_distribution():
    dev = compose("docker-compose.dev.yml")
    services = dev["services"]
    receiver = services["callback-receiver"]
    assert receiver["profiles"] == ["callbacks"]
    assert receiver["networks"] == {"control": {}, "labs": {"ipv4_address": "172.28.0.17"}}
    assert not receiver.get("ports") and not receiver.get("env_file")
    assert set(receiver["environment"]) == {
        "SCOPELENS_ENVIRONMENT",
        "SCOPELENS_DATABASE_URL",
        "SCOPELENS_CALLBACK_SIGNING_KEY",
        "SCOPELENS_CALLBACK_COLLECTOR_ORIGINS",
    }
    assert "--no-proxy-headers" in receiver["command"]
    assert "--no-access-log" in receiver["command"] and "--factory" in receiver["command"]
    permitted = {"api", "policy", "supervisor", "callback-receiver"}
    for name, service in services.items():
        if name in permitted:
            assert service["environment"][KEY] == "${SCOPELENS_CALLBACK_SIGNING_KEY:-}"
        elif service.get("env_file"):
            assert service["environment"][KEY] == ""
        else:
            assert service.get("environment", {}).get(KEY, "") == ""
    assert KEY not in DockerWorkerSupervisor.ALLOWED_ENV_KEYS
    release = compose("docker-compose.release.yml")["services"]["callback-receiver"]
    assert release["volumes"] == []
    assert "SCOPELENS_RELEASE_API_IMAGE" in release["image"]
    labs = yaml.safe_load((ROOT / "labs/docker-compose.yml").read_text())
    fixture = labs["services"]["labs-callbacks"]
    assert fixture["profiles"] == ["callbacks"]
    assert fixture["networks"] == {"labs_net": {"ipv4_address": "172.28.0.18"}}
    assert labs["networks"]["labs_net"]["internal"] is True
    assert not fixture.get("ports") and not fixture.get("env_file")
    addresses = [
        config["ipv4_address"]
        for service in labs["services"].values()
        for config in service.get("networks", {}).values()
        if config and "ipv4_address" in config
    ]
    assert len(addresses) == len(set(addresses)) and "172.28.0.17" not in addresses
    bindings = yaml.safe_load((ROOT / "deploy/lab_services.yaml").read_text())["services"]
    binding = next(item for item in bindings if item["id"] == "labs-callbacks")
    assert binding["addresses"] == ["172.28.0.18"] and binding["ports"] == [8080]


def test_initializer_is_private_nonrotating_and_silent(tmp_path, capsys):
    path = tmp_path / ".env"
    path.write_text("OTHER=value\n" + KEY + "=\n")
    assert initialize_callback_key.main(["--env-file", str(path)]) == 0
    content = path.read_text()
    key = next(line.split("=", 1)[1] for line in content.splitlines() if line.startswith(KEY + "="))
    assert len(key) >= 32
    assert key not in capsys.readouterr().out
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert initialize_callback_key.main(["--env-file", str(path)]) == 0
    assert path.read_text() == content
    assert key not in capsys.readouterr().out


def test_new_install_key_separate_and_callbacks_still_disabled(tmp_path, monkeypatch, capsys):
    path = tmp_path / ".env"
    monkeypatch.setattr(bootstrap_env, "ENV_FILE", path)
    monkeypatch.setattr(bootstrap_env, "ENV_EXAMPLE", ROOT / ".env.example")
    assert bootstrap_env.main() == 0
    assignments = dict(
        line.split("=", 1)
        for line in path.read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    key = assignments[KEY]
    assert len(key) >= 32 and key != assignments["SCOPELENS_IDENTITY_ENCRYPTION_KEY"]
    assert assignments["SCOPELENS_CALLBACK_COLLECTOR_ORIGINS"] == "[]"
    assert key not in capsys.readouterr().out
