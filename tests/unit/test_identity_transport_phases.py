"""HTTPX/httpcore phases exercised with in-memory sockets and no network."""

import json

import httpcore
import httpx
import pytest
from pydantic import SecretStr
from tests.unit.test_identity_readiness import configuration

from scopelens.identities.readiness import collect_identity_readiness, evaluate_identity_readiness
from scopelens.identities.sessions import transport_phase


class FixtureStream(httpcore.NetworkStream):
    def __init__(self, failure):
        self.failure = failure
        self.reads = 0

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        if self.failure == "tls":
            raise httpcore.ConnectError("private TLS diagnostic")
        return self

    def write(self, buffer, timeout=None):
        if self.failure == "request_send":
            raise httpcore.WriteTimeout("private send diagnostic")

    def read(self, max_bytes, timeout=None):
        self.reads += 1
        if self.failure == "response_headers":
            raise httpcore.ReadTimeout("private header diagnostic")
        if self.reads == 1:
            encoding = (
                b"Content-Encoding: gzip\r\n" if self.failure == "response_body_decode" else b""
            )
            return b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n" + encoding + b"\r\n"
        if self.failure == "response_body":
            raise httpcore.ReadError("private body diagnostic")
        return b"invalid gzip"

    def close(self):
        pass

    def get_extra_info(self, info):
        return None


class FixtureBackend(httpcore.NetworkBackend):
    def __init__(self, failure):
        self.failure = failure
        self.connections = 0

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.connections += 1
        if self.failure == "connect":
            raise httpcore.ConnectTimeout("private connect diagnostic")
        return FixtureStream(self.failure)


@pytest.mark.parametrize(
    "phase,category,status",
    [
        ("connect", "timeout", None),
        ("tls", "connect", None),
        ("request_send", "timeout", None),
        ("response_headers", "timeout", None),
        ("response_body", "http_transport", 200),
        ("response_body_decode", "decoding", 200),
    ],
)
def test_real_httpcore_failure_phase_retains_only_safe_diagnostics(phase, category, status):
    record = failure_record(phase)
    assert record["transport_phase"] == phase
    assert record["transport_error"] == category
    assert record["response_status"] == status


def failure_record(phase, *, proxy=False):
    backend = FixtureBackend(phase)

    def client_factory(_):
        transport = httpx.HTTPTransport(trust_env=False)
        transport._pool.close()
        # Preserve the real HTTPX -> httpcore -> h11 stack, replacing only sockets.
        transport._pool = (
            httpcore.HTTPProxy(proxy_url="http://broker.invalid:8080", network_backend=backend)
            if proxy
            else httpcore.ConnectionPool(network_backend=backend)
        )
        return httpx.Client(transport=transport, trust_env=False)

    config = configuration()
    records = []
    collect_identity_readiness(
        config,
        lambda _: SecretStr("synthetic-cookie"),
        client_factory,
        lambda _, record: records.append(record),
        cancelled=lambda: False,
    )
    assert backend.connections == len(records) == 1
    record = records[0]
    assert record["status"] is None and record["observed_digest"] is None
    assert record["state"] == "blocked"
    assert "private" not in json.dumps(record)
    assert not evaluate_identity_readiness(
        config.identities[0], record, configuration_binding=record["configuration_binding"]
    )
    return record


def test_proxy_connect_status_is_not_recorded_as_target_status_on_tls_failure():
    record = failure_record("tls", proxy=True)
    assert record["transport_phase"] == "tls"
    assert record["response_status"] is None


def test_unwrapped_decoding_failure_is_body_decode_even_without_retained_status():
    assert transport_phase(httpx.DecodingError("private diagnostic")) == "response_body_decode"


@pytest.mark.parametrize(
    "error", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError]
)
def test_no_trace_ambiguous_failure_does_not_claim_an_unobserved_phase(error):
    assert transport_phase(error("private diagnostic")) == "unknown"


def test_no_trace_pool_failure_has_its_own_phase():
    assert transport_phase(httpx.PoolTimeout("private diagnostic")) == "connection_pool"
