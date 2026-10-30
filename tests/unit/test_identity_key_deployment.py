"""Credential persistence and nonrotating key initialization contracts."""

import base64
import os
from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet
from scripts import bootstrap_env, initialize_identity_key

from scopelens.execution.supervisor import DockerWorkerSupervisor

ROOT = Path(__file__).resolve().parents[2]
KEY = "SCOPELENS_IDENTITY_ENCRYPTION_KEY"
STORE_PATH = "/var/lib/scopelens/identity-secrets"


class ComposeLoader(yaml.SafeLoader):
    pass


ComposeLoader.add_constructor("!override", lambda loader, node: loader.construct_sequence(node))


def compose(name):
    return yaml.load((ROOT / "deploy" / name).read_text(), Loader=ComposeLoader)


def test_dev_and_release_keep_shared_persistent_credentials_and_readonly_policy():
    dev = compose("docker-compose.dev.yml")
    release = compose("docker-compose.release.yml")
    assert "identity_credentials" in dev["volumes"]
    for document in (dev, release):
        services = document["services"]
        assert f"identity_credentials:{STORE_PATH}" in services["api"]["volumes"]
        assert f"identity_credentials:{STORE_PATH}:ro" in services["policy"]["volumes"]
        assert "evidence:/app/runs/evidence" in services["api"]["volumes"]
        for name, service in services.items():
            if name not in {"api", "policy"}:
                assert not any("identity_credentials:" in v for v in service.get("volumes", []))
    for name in ("api", "policy"):
        env = dev["services"][name]["environment"]
        assert env["SCOPELENS_IDENTITY_STORE_PATH"] == STORE_PATH
        assert env[KEY] == "${SCOPELENS_IDENTITY_ENCRYPTION_KEY:-}"


def test_proxy_and_untrusted_workers_never_receive_credential_volume_or_key():
    dev = compose("docker-compose.dev.yml")
    proxy = dev["services"]["proxy"]
    assert "env_file" not in proxy
    assert KEY not in proxy.get("environment", {})
    assert KEY not in DockerWorkerSupervisor.ALLOWED_ENV_KEYS
    assert "SCOPELENS_IDENTITY_STORE_PATH" not in DockerWorkerSupervisor.ALLOWED_ENV_KEYS
    for name in ("supervisor", "dispatcher", "tls-lane", "model-gateway"):
        assert dev["services"][name]["environment"][KEY] == ""
    # The dedicated VM override still owns the supervisor mounts. This change must
    # not restore host Docker access or add credential storage to that service.
    vm = compose("docker-compose.worker-vm.yml")["services"]["supervisor"]
    assert "../runs/worker-vm/client:/worker-docker-certs:ro" in vm["volumes"]
    assert not any(
        "docker.sock" in value or "identity_credentials" in value for value in vm["volumes"]
    )


def value_from(path, key=KEY):
    return next(
        line.split("=", 1)[1]
        for line in path.read_text().splitlines()
        if line.startswith(key + "=")
    )


def test_existing_env_initializer_is_idempotent_private_and_silent_about_values(tmp_path, capsys):
    path = tmp_path / ".env"
    path.write_text("OTHER_SECRET=retain-me\n", encoding="utf-8")
    path.chmod(0o644)
    assert initialize_identity_key.main(["--env-file", str(path)]) == 0
    first = path.read_bytes()
    key = value_from(path)
    assert len(base64.urlsafe_b64decode(key)) == 32
    cipher = Fernet(key.encode())
    assert cipher.decrypt(cipher.encrypt(b"fixture")) == b"fixture"
    assert path.stat().st_mode & 0o777 == 0o600
    assert initialize_identity_key.main(["--env-file", str(path)]) == 0
    assert path.read_bytes() == first
    assert "OTHER_SECRET=retain-me" in path.read_text()
    output = capsys.readouterr()
    assert key not in output.out + output.err
    assert "retain-me" not in output.out + output.err


@pytest.mark.parametrize(
    "assignment",
    [
        f"{KEY}=keep-this-nonempty-value\n",
        f"export {KEY} = 'keep-this-nonempty-value' # comment\n",
        f'{KEY}="keep-this-nonempty-value"\n',
    ],
)
def test_any_existing_nonempty_key_is_never_overwritten(tmp_path, capsys, assignment):
    path = tmp_path / ".env"
    path.write_text(assignment)
    path.chmod(0o644)
    assert initialize_identity_key.main(["--env-file", str(path)]) == 0
    assert path.read_text() == assignment
    assert path.stat().st_mode & 0o777 == 0o600
    assert "keep-this-nonempty-value" not in capsys.readouterr().out


@pytest.mark.parametrize("empty", ["", "''", '""', " # optional"])
def test_empty_assignments_are_initialized_without_duplicate_override(tmp_path, empty):
    path = tmp_path / ".env"
    path.write_text(f"{KEY}={empty}\n{KEY}=\nUNCHANGED=1\n")
    assert initialize_identity_key.initialize_identity_key(path)
    active = [line for line in path.read_text().splitlines() if line.startswith(KEY + "=")]
    assert len(active) == 1
    assert len(base64.urlsafe_b64decode(value_from(path))) == 32
    assert "UNCHANGED=1" in path.read_text()


def test_invalid_quoting_does_not_echo_secret_or_replace_file(tmp_path, capsys):
    path = tmp_path / ".env"
    content = f"{KEY}='private-test-marker\n"
    path.write_text(content)
    assert initialize_identity_key.main(["--env-file", str(path)]) == 1
    assert path.read_text() == content
    assert path.stat().st_mode & 0o777 == 0o600
    output = capsys.readouterr()
    assert "private-test-marker" not in output.out + output.err


def test_initializer_refuses_missing_files_and_symlinks(tmp_path):
    path = tmp_path / ".env"
    with pytest.raises(FileNotFoundError):
        initialize_identity_key.initialize_identity_key(path)
    target = tmp_path / "target"
    target.write_text("UNCHANGED=1\n")
    path.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        initialize_identity_key.initialize_identity_key(path)
    assert target.read_text() == "UNCHANGED=1\n"


def test_bootstrap_creates_distinct_identity_key_and_preserves_existing_env(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / ".env"
    monkeypatch.setattr(bootstrap_env, "ENV_FILE", path)
    monkeypatch.setattr(bootstrap_env, "ENV_EXAMPLE", ROOT / ".env.example")
    previous = os.umask(0)
    try:
        assert bootstrap_env.main() == 0
    finally:
        os.umask(previous)
    key = value_from(path)
    evidence_key = value_from(path, "SCOPELENS_EVIDENCE_ENCRYPTION_KEY")
    assert key != evidence_key
    assert len(base64.urlsafe_b64decode(key)) == 32
    assert path.stat().st_mode & 0o777 == 0o600
    original = path.read_bytes()
    assert bootstrap_env.main() == 0
    assert path.read_bytes() == original
    output = capsys.readouterr()
    assert key not in output.out + output.err
    assert evidence_key not in output.out + output.err
