"""Fixed collector session fingerprints survive trusted intake without cookie values."""

import hashlib
import json
from http.cookies import SimpleCookie
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select
from tests.unit.test_session_fingerprints import session_policy, session_record

from scopelens.academic.evidence import load_captures
from scopelens.domain.evidence import EvidenceOrigin
from scopelens.evidence.intake import record_json_evidence, verify_integrity
from scopelens.identities.lifecycle import check_session_policy, evaluate_session_proof
from scopelens.identities.sessions import IdentitySessions
from scopelens.persistence.models import EvidenceRow, ScanRow, TaskRow
from scopelens.security.redaction import REDACTED, redact

pytestmark = pytest.mark.db
FINGERPRINTS = ("old_cookie_hash", "new_cookie_hash", "replayed_cookie_hash")
PRODUCER_HASH = hashlib.sha256(
    (Path(__file__).parents[2] / "backend/scopelens/expansion/worker.py").read_bytes()
).hexdigest()


def artifact(data):
    return {
        "source": "expansion",
        "kind": "identity_observation",
        "run_id": "session-run",
        "data": data,
    }


@pytest.mark.parametrize("vulnerable", [False, True])
def test_fixed_collector_intake_and_reloaded_proof_agree(
    db_session, settings, evidence_store, queued_scan, vulnerable
):
    scan, task = queued_scan
    policy, profile = session_policy()
    cookie_values = ("synthetic-first-session", "synthetic-replacement-session")
    active = set()
    logins = 0
    records = []

    def respond(request):
        nonlocal logins
        if request.url.path == "/login":
            value = cookie_values[0] if logins == 0 or vulnerable else cookie_values[1]
            logins += 1
            if not vulnerable:
                active.clear()
            active.add(value)
            return httpx.Response(200, json={}, headers={"Set-Cookie": f"sid={value}; Path=/"})
        if request.url.path == "/logout":
            if not vulnerable:
                active.clear()
            return httpx.Response(200, json={})
        cookie = SimpleCookie(request.headers.get("cookie", ""))
        value = cookie["sid"].value if "sid" in cookie else None
        return (
            httpx.Response(200, json={"identity": profile.id})
            if value in active
            else httpx.Response(401, json={"error": "unauthenticated"})
        )

    def capture(data):
        data = {
            **data,
            "proof_type": "session",
            "proof_id": profile.id,
            "headers": {
                "Cookie": "sid=" + cookie_values[0],
                "Set-Cookie": "sid=" + cookie_values[1],
            },
            "password": "synthetic-private-password",
            "nested": {"old_cookie_hash": "c" * 64},
        }
        record = record_json_evidence(
            db_session,
            settings=settings,
            store=evidence_store,
            scan=scan,
            origin=EvidenceOrigin.SUPERVISOR,
            producer="reviewed_expansion_capture",
            producer_hash=PRODUCER_HASH,
            task_id=task.id,
            run_id="session-run",
            payload=artifact(data),
        )
        records.append(record)
        return record.id

    with IdentitySessions(
        (profile,),
        lambda _: SecretStr("synthetic-private-password"),
        lambda _: httpx.Client(transport=httpx.MockTransport(respond)),
    ) as sessions:
        results = check_session_policy(policy, sessions, capture)

    expected = "confirmed" if vulnerable else "pass"
    assert [result.state for result in results] == [expected] * 3
    rows = list(db_session.scalars(select(EvidenceRow).where(EvidenceRow.scan_id == scan.id)))
    loaded = load_captures(db_session, scan, rows, evidence_store, 30)
    assert len(loaded) == 3
    assert {item["data"]["check"] for item in loaded} == {"rotation", "old_session", "logout"}
    assert [evaluate_session_proof(policy, profile, item["data"])[0] for item in loaded] == [
        expected
    ] * 3
    for record in records:
        assert verify_integrity(evidence_store, record)
        stored = evidence_store.get(record.content_ref)
        assert all(value.encode() not in stored for value in cookie_values)
        assert b"synthetic-private-password" not in stored
        data = json.loads(stored)["data"]
        assert data["headers"] == {"Cookie": REDACTED, "Set-Cookie": REDACTED}
        assert data["password"] == REDACTED
        assert data["nested"]["old_cookie_hash"] == REDACTED
        assert data["old_cookie_hash"] == hashlib.sha256(cookie_values[0].encode()).hexdigest()
        assert (
            data["new_cookie_hash"]
            == hashlib.sha256(cookie_values[0 if vulnerable else 1].encode()).hexdigest()
        )


@pytest.mark.parametrize(
    "invalid_binding",
    [
        "origin",
        "producer",
        "producer_hash",
        "no_task",
        "wrong_task_scan",
        "no_run",
        "wrong_run",
        "source",
        "artifact_kind",
        "data_kind",
        "proof_type",
        "proof_id",
    ],
)
def test_fingerprint_exception_requires_fixed_collector_provenance(
    db_session, settings, evidence_store, queued_scan, invalid_binding
):
    scan, task = queued_scan
    payload = artifact(session_record("logout"))
    kwargs = dict(
        origin=EvidenceOrigin.SUPERVISOR,
        producer="reviewed_expansion_capture",
        producer_hash=PRODUCER_HASH,
        task_id=task.id,
        run_id="session-run",
    )
    if invalid_binding == "origin":
        kwargs["origin"] = EvidenceOrigin.UNTRUSTED_OBSERVATION
    elif invalid_binding == "producer":
        kwargs["producer"] = "reviewed_expansion_browser_capture"
    elif invalid_binding == "producer_hash":
        kwargs["producer_hash"] = "not-a-collector-hash"
    elif invalid_binding == "no_task":
        kwargs["task_id"] = None
    elif invalid_binding == "wrong_task_scan":
        other_scan = ScanRow(
            operator_id=scan.operator_id,
            scope_version_id=scan.scope_version_id,
            target_origin=scan.target_origin,
            profile=scan.profile,
            score_version=scan.score_version,
            status="queued",
        )
        db_session.add(other_scan)
        db_session.flush()
        other_task = TaskRow(
            scan_id=other_scan.id,
            logical_id="other",
            attempt_id="a1",
            task_type=task.task_type,
            state=task.state,
        )
        db_session.add(other_task)
        db_session.flush()
        kwargs["task_id"] = other_task.id
    elif invalid_binding == "no_run":
        kwargs["run_id"] = None
    elif invalid_binding == "wrong_run":
        payload["run_id"] = "other-run"
    elif invalid_binding == "source":
        payload["source"] = "expansion_browser"
    elif invalid_binding == "artifact_kind":
        payload["kind"] = "session_observation"
    elif invalid_binding == "data_kind":
        payload["data"]["kind"] = "worker_claim"
    elif invalid_binding == "proof_type":
        payload["data"]["proof_type"] = "access"
    else:
        payload["data"]["proof_id"] = "other-identity"
    record = record_json_evidence(
        db_session, settings=settings, store=evidence_store, scan=scan, payload=payload, **kwargs
    )
    stored = json.loads(evidence_store.get(record.content_ref))
    assert all(stored["data"][field] == REDACTED for field in FINGERPRINTS)
    assert evaluate_session_proof(*session_policy(), stored["data"])[0] == "inconclusive"


@pytest.mark.parametrize("invalid", ["[redacted]", "raw-session-value", "a" * 63, "g" * 64])
def test_trusted_intake_does_not_preserve_malformed_hashes(
    db_session, settings, evidence_store, queued_scan, invalid
):
    scan, task = queued_scan
    data = session_record("logout")
    data.update({field: invalid for field in FINGERPRINTS})
    record = record_json_evidence(
        db_session,
        settings=settings,
        store=evidence_store,
        scan=scan,
        origin=EvidenceOrigin.SUPERVISOR,
        producer="reviewed_expansion_capture",
        producer_hash=PRODUCER_HASH,
        task_id=task.id,
        run_id="session-run",
        payload=artifact(data),
    )
    stored = json.loads(evidence_store.get(record.content_ref))["data"]
    assert all(stored[field] == REDACTED for field in FINGERPRINTS)
    assert evaluate_session_proof(*session_policy(), stored)[0] == "inconclusive"
    # The global redactor has no fingerprint exemption.
    assert redact(session_record("logout"))["old_cookie_hash"] == REDACTED
