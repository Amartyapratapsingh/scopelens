import json
from urllib.parse import parse_qs

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scopelens.callbacks.probes import CallbackProbeRecipe, run_callback_probe
from scopelens.callbacks.service import CallbackBase, CallbackService, callback_router


@pytest.fixture
def service():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    CallbackBase.metadata.create_all(engine)
    service = CallbackService(
        sessionmaker(engine), b"x" * 32, {"https://callback.test"}, now=lambda: 100.0
    )
    yield service
    engine.dispose()


def issue(service, **changes):
    data = dict(
        owner_id="owner",
        scan_id="scan",
        task_id="task",
        family="ssrf",
        purpose="positive",
        callback_origin="https://callback.test",
        expected_target_peers={"192.0.2.10"},
        scanner_peers={"192.0.2.20"},
    )
    return service.issue(**(data | changes))


def test_nonce_signature_scope_expiry_and_revocation(service):
    nonce = issue(service)
    token = nonce.url.rsplit("/", 1)[1]
    receipt = service.capture(token, peer="192.0.2.10", method="GET")
    assert receipt.source == "target" and service.verify(receipt)
    assert not service.verify(receipt.model_copy(update={"peer": "203.0.113.5"}))
    with pytest.raises(PermissionError):
        service.receipts(nonce.id, owner_id="other", scan_id="scan", task_id="task")
    service.revoke_scan(owner_id="owner", scan_id="scan")
    assert service.capture(token, peer="192.0.2.10", method="GET") is None
    another = issue(service)
    service.now = lambda: 160.0
    assert service.capture(another.url.rsplit("/", 1)[1], peer="192.0.2.10", method="GET") is None


def test_ambiguous_nat_and_unregistered_callback_blocked(service):
    with pytest.raises(ValueError, match="distinct"):
        issue(service, scanner_peers={"192.0.2.10"})
    with pytest.raises(ValueError, match="unregistered"):
        issue(service, callback_origin="https://unapproved.test")


def test_router_uses_peer_not_forwarded_headers(service):
    app = FastAPI()
    app.include_router(callback_router(service))
    nonce = issue(service)
    path = "/callback/" + nonce.url.rsplit("/", 1)[1]
    with TestClient(app, client=("192.0.2.20", 40000)) as client:
        response = client.get(path, headers={"X-Forwarded-For": "192.0.2.10"})
    assert response.status_code == 204
    rows = service.receipts(nonce.id, owner_id="owner", scan_id="scan", task_id="task")
    assert rows[0].source == "scanner"


def test_receipt_cap_and_unknown_peer(service):
    nonce = issue(service)
    token = nonce.url.rsplit("/", 1)[1]
    for _ in range(4):
        receipt = service.capture(token, peer="203.0.113.55", method="GET")
        assert receipt.source == "unknown"
    assert service.capture(token, peer="192.0.2.10", method="GET") is None


def recipe(family):
    return CallbackProbeRecipe(
        family=family,
        target_url="https://target.test/fetch?url=normal"
        if family == "ssrf"
        else "https://target.test/xml",
        method="GET" if family == "ssrf" else "POST",
        parameter="url" if family == "ssrf" else None,
        callback_origin="https://callback.test",
        expected_target_peers=frozenset({"192.0.2.10"}),
        scanner_peers=frozenset({"192.0.2.20"}),
        approved_staging=True,
        unexpected_external_fetch=True,
        max_wait_seconds=0,
    )


@pytest.mark.parametrize("family", ["ssrf", "xxe"])
@pytest.mark.parametrize("variant", ["vulnerable", "fixed", "scanner", "dns", "negative-also"])
def test_paired_canary_proof_and_negative_variants(service, family, variant):
    def transport(request):
        if family == "ssrf":
            value = parse_qs(request.url.query.decode())["url"][0]
            positive = value.startswith("https:")
            token = value.rsplit("/", 1)[1]
        else:
            body = request.content.decode()
            positive = "<!DOCTYPE" in body
            import re

            token = re.search(r"/callback/([A-Za-z0-9_-]+)", body).group(1)
        if variant != "fixed" and (positive or variant == "negative-also"):
            service.capture(
                token,
                peer="192.0.2.20" if variant == "scanner" else "192.0.2.10",
                method="GET",
                protocol="dns" if variant == "dns" else "http",
            )
        return httpx.Response(200, text="processed synthetic input")

    with httpx.Client(transport=httpx.MockTransport(transport)) as client:
        outcome = run_callback_probe(
            client, service, recipe(family), owner_id="owner", scan_id="scan", task_id="task"
        )
    assert outcome.requests == 3
    assert outcome.state == ("confirmed" if variant == "vulnerable" else "inconclusive")
    assert len(set(outcome.nonce_ids)) == 3
    assert "callback/" not in json.dumps(outcome.model_dump())


def test_cancellation_issues_no_requests(service):
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: pytest.fail("request after cancel"))
    ) as client:
        outcome = run_callback_probe(
            client,
            service,
            recipe("ssrf"),
            owner_id="owner",
            scan_id="scan",
            task_id="task",
            cancelled=lambda: True,
        )
    assert outcome.state == "cancelled" and outcome.requests == 0


def test_collector_restart_preserves_signed_receipts(service):
    nonce = issue(service)
    receipt = service.capture(nonce.url.rsplit("/", 1)[1], peer="192.0.2.10", method="GET")
    restarted = CallbackService(service.sessions, b"x" * 32, {"https://callback.test"})
    rows = restarted.receipts(nonce.id, owner_id="owner", scan_id="scan", task_id="task")
    assert rows == [receipt] and restarted.verify(rows[0])
