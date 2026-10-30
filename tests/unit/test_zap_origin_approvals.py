"""Origin approval and HTTPS IPC contracts; these are not native lab acceptance."""

import json
import ssl
from types import SimpleNamespace

import pytest

from scopelens.adapters.zap_active import (
    ActiveRulePin,
    ActiveRuleTask,
    ApprovedOrigin,
    OriginScopedRulePin,
    reviewed_rule,
)
from scopelens.adapters.zap_active_worker import CONFIG_SHA256, logical_url, native_url
from scopelens.domain.enums import AuthorityDomain, ProfileName
from scopelens.execution.zap_active import container_kwargs, dispatch, transport_kwargs


@pytest.fixture
def approved(settings, tmp_path, monkeypatch):
    monkeypatch.setattr("scopelens.adapters.zap_active.REVIEWED_RULES", {})
    pin = OriginScopedRulePin(
        rule_id="40012",
        control_id="SL-C03-XSS-01",
        engine_version="2.17.0",
        engine_sha256="2" * 64,
        rule_config_sha256=CONFIG_SHA256,
        addon_filename="ascanrules-release-78.zap",
        addon_sha256="3" * 64,
        allowed_values=("scopelens", "marker"),
        max_requests=2,
        deadline_seconds=5,
        approved_origins=[{"scheme": "https", "host": "owned.example", "port": 443}],
        approval={
            "operator": "Fixture operator",
            "date": "2026-10-11",
            "decision": "Synthetic test only, not an operational approval.",
        },
    )
    path = tmp_path / "approved.json"
    path.write_text(
        json.dumps(
            {"version": "zap-active-allowlist-v2", "approved_rules": [pin.model_dump(mode="json")]}
        )
    )
    config = settings.model_copy(
        update={"zap_active_allowlist_file": path, "zap_active_lab_enabled": True}
    )
    return config, pin, path


def target(origin="https://owned.example", *, lab=False):
    return SimpleNamespace(
        authority_domain=AuthorityDomain.LAB if lab else AuthorityDomain.PRODUCTION,
        allowed_check_profile=ProfileName.EXTERNAL_ACTIVE_V2 if lab else ProfileName.EXTERNAL_DAST,
        origin=origin,
        scheme=origin.split(":")[0],
        lab_binding=SimpleNamespace(service="labs-bad") if lab else None,
    )


def task():
    return ActiveRuleTask(
        scan_id="scan",
        task_id="task",
        input_id="input",
        rule_id="40012",
        url="https://owned.example/active/xss?q=scopelens",
        input_name="q",
        rule_config_sha256=CONFIG_SHA256,
        max_requests=2,
        deadline_seconds=5,
    )


@pytest.mark.parametrize(
    "origin",
    [
        "https://other.example",
        "http://owned.example",
        "https://owned.example:444",
        "https://sub.owned.example",
    ],
)
def test_v2_dispatch_denies_other_exact_origin(approved, monkeypatch, origin):
    config, _, _ = approved
    monkeypatch.setattr(
        "scopelens.execution.zap_active.run_task",
        lambda *args: pytest.fail("unapproved origin dispatched"),
    )
    assert (
        dispatch(
            config,
            object(),
            scan_id="scan",
            scope=target(origin),
            probes=[{"kind": "xss", "path": "/active/xss", "parameter": "q"}],
            token="token",
        )
        == []
    )


def test_https_dispatch_uses_approved_pin_and_logical_https_task(approved, monkeypatch):
    config, pin, _ = approved
    calls = []

    def launch(settings, supervisor, offered, selected, token):
        calls.append(offered)
        assert selected == pin and token == "token"
        return "candidate"

    monkeypatch.setattr("scopelens.execution.zap_active.run_task", launch)
    assert dispatch(
        config,
        object(),
        scan_id="scan",
        scope=target(),
        probes=[{"kind": "xss", "path": "/active/xss", "parameter": "q"}],
        token="token",
    ) == ["candidate"]
    assert calls[0].url == task().url
    config = container_kwargs("sha256:" + "a" * 64, calls[0], pin)
    worker_pin = json.loads(config["command"][-1])["pin"]
    assert "approved_origins" not in worker_pin and "approval" not in worker_pin
    ActiveRulePin.model_validate(worker_pin)


@pytest.mark.parametrize("version", ["zap-active-allowlist-v1", "zap-active-allowlist-v2"])
def test_empty_v1_v2_dispatches_zero_requests_on_eligible_lab_and_production(approved, version):
    config, _, path = approved
    path.write_text(json.dumps({"version": version, "approved_rules": []}))

    class Unreachable:
        @property
        def client(self):
            pytest.fail("empty allowlist accessed Docker")

    for scope in (target(), target("http://172.28.0.11", lab=True)):
        assert (
            dispatch(
                config,
                Unreachable(),
                scan_id="scan",
                scope=scope,
                probes=[{"kind": "xss", "path": "/active/xss", "parameter": "q"}],
                token="token",
            )
            == []
        )


def test_v1_lab_path_works_but_confers_no_production_authority(approved, monkeypatch):
    config, pin, path = approved
    legacy = pin.model_dump(mode="json", include=set(ActiveRulePin.model_fields))
    path.write_text(json.dumps({"version": "zap-active-allowlist-v1", "approved_rules": [legacy]}))
    assert type(reviewed_rule("40012", config)) is ActiveRulePin
    monkeypatch.setattr("scopelens.execution.zap_active.run_task", lambda *args: "candidate")
    probes = [{"kind": "xss", "path": "/active/xss", "parameter": "q"}]
    assert dispatch(
        config,
        object(),
        scan_id="scan",
        scope=target("http://172.28.0.11", lab=True),
        probes=probes,
        token="token",
    ) == ["candidate"]
    assert (
        dispatch(config, object(), scan_id="scan", scope=target(), probes=probes, token="token")
        == []
    )


@pytest.mark.parametrize(
    "host",
    [
        "*.owned.example",
        "OWNED.example",
        "owned.example.",
        "owned.example/",
        " user.example",
        "user@owned.example",
        "",
    ],
)
def test_origin_host_is_exact_canonical_not_pattern(host):
    with pytest.raises(ValueError):
        ApprovedOrigin(scheme="https", host=host, port=443)


@pytest.mark.parametrize(
    "fault",
    [
        "missing_record",
        "blank_operator",
        "blank_decision",
        "empty_origins",
        "duplicate_origin",
        "other_rule",
        "v1_pin",
    ],
)
def test_invalid_v2_approval_fails_closed(approved, fault):
    config, pin, path = approved
    row = pin.model_dump(mode="json")
    if fault == "missing_record":
        del row["approval"]
    elif fault == "blank_operator":
        row["approval"]["operator"] = " "
    elif fault == "blank_decision":
        row["approval"]["decision"] = " "
    elif fault == "empty_origins":
        row["approved_origins"] = []
    elif fault == "duplicate_origin":
        row["approved_origins"] *= 2
    elif fault == "other_rule":
        row["rule_id"] = "40018"
    else:
        row = pin.model_dump(mode="json", include=set(ActiveRulePin.model_fields))
    path.write_text(json.dumps({"version": "zap-active-allowlist-v2", "approved_rules": [row]}))
    assert reviewed_rule("40012", config) is None


def test_https_projection_maps_only_bound_origin_path_port_and_payload(approved):
    _, pin, _ = approved
    logical = task()
    assert native_url(logical) == "http://owned.example:443/active/xss?q=scopelens"
    assert logical_url(logical, pin, native_url(logical).replace("scopelens", "marker")) == (
        "https://owned.example/active/xss?q=marker"
    )
    for offered in (
        "http://owned.example/active/xss?q=marker",
        "http://other.example:443/active/xss?q=marker",
        "http://owned.example:443/admin?q=marker",
        "http://owned.example:443/active/xss?q=unreviewed",
    ):
        assert logical_url(logical, pin, offered) is None


def test_https_transport_uses_broker_connect_credential_and_verified_ca(approved, monkeypatch):
    config, _, _ = approved
    context = ssl.create_default_context()
    seen = []

    def load(*, cafile):
        seen.append(cafile)
        return context

    monkeypatch.setattr("scopelens.execution.zap_active.ssl.create_default_context", load)
    options = transport_kwargs(config, task(), "scan-token")
    assert seen == [str(config.proxy_ca_path)]
    assert options["verify"] is context and context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert str(options["proxy"].url) == f"http://{config.proxy_host}:{config.proxy_http_port}"
    assert dict(options["proxy"].headers) == {"x-scopelens-egress": "scan-token"}
    assert not options["follow_redirects"] and not options["trust_env"]


def test_missing_broker_ca_denies_https_transport_before_network(approved, tmp_path):
    config, _, _ = approved
    with pytest.raises(FileNotFoundError):
        transport_kwargs(
            config.model_copy(update={"proxy_ca_path": tmp_path / "missing"}), task(), "token"
        )


def test_real_https_forward_sends_token_only_connect_then_signed_inner_get(approved, tmp_path):
    """Local TLS-intercepting proxy, with no DNS or upstream connection."""
    import base64
    import socket
    import threading
    from datetime import UTC, datetime, timedelta

    import httpx
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from pydantic import SecretStr

    from scopelens.broker.zap_task import SignedTaskRequest
    from scopelens.execution.zap_active import _forward

    config, _, _ = approved
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned.example")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("owned.example")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    ca, pem_key = tmp_path / "proxy-ca.pem", tmp_path / "proxy-key.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pem_key.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(ca, pem_key)
    captured, errors = [], []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(5)
    config = config.model_copy(
        update={
            "proxy_host": "127.0.0.1",
            "proxy_http_port": listener.getsockname()[1],
            "proxy_ca_path": ca,
            "zap_active_signing_key": SecretStr("k" * 32),
        }
    )
    offered = task().model_copy(update={"scan_id": "00000000-0000-0000-0000-000000000001"})
    grant = {
        "grant_id": "grant",
        "scope_version_id": "00000000-0000-0000-0000-000000000002",
        "task": offered.model_dump(),
        "token": "task-token",
    }

    def headers(conn):
        data = bytearray()
        while b"\r\n\r\n" not in data:
            block = conn.recv(1024)
            if not block or len(data) + len(block) > 16384:
                raise ValueError("incomplete or unbounded fixture headers")
            data.extend(block)
        return data.decode("ascii")

    def serve():
        try:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(5)
                captured.append(headers(conn))
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                with tls.wrap_socket(conn, server_side=True) as secure:
                    captured.append(headers(secure))
                    secure.sendall(
                        b"HTTP/1.1 200 OK\r\nx-scopelens-zap-decision: allow\r\nContent-Length: 7\r\nConnection: close\r\n\r\nfixture"
                    )
        except (OSError, ValueError) as error:
            errors.append(type(error).__name__)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        with httpx.Client(**transport_kwargs(config, offered, "scan-token")) as client:
            result, allowed = _forward(
                client,
                config,
                grant,
                offered,
                "a" * 64,
                {"method": "GET", "url": offered.url},
                "scan-token",
            )
        assert allowed and base64.b64decode(result["body"]) == b"fixture"
    finally:
        listener.close()
        thread.join(timeout=6)
    assert not errors and not thread.is_alive()
    outer, inner = captured
    assert outer.startswith("CONNECT owned.example:443 HTTP/1.1\r\n")
    assert "x-scopelens-egress: scan-token" in outer.lower()
    assert "x-scopelens-zap-task" not in outer.lower() and "task-token" not in outer
    assert inner.startswith("GET /active/xss?q=scopelens HTTP/1.1\r\n")
    value = next(
        row.split(": ", 1)[1]
        for row in inner.split("\r\n")
        if row.lower().startswith("x-scopelens-zap-task:")
    )
    signed = SignedTaskRequest.model_validate_json(base64.b64decode(value))
    assert signed.url == offered.url and signed.worker_id == "a" * 64
