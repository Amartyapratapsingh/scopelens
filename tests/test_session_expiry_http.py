"""Fixed collector and report evaluator against an actual loopback expiry server."""

import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from uuid import uuid4

import httpx
import pytest
from labs.session_expiry.app import PASSWORD, handler
from pydantic import SecretStr
from tests.unit.test_expansion_proof_aggregation import evaluate
from tests.unit.test_session_expiry import contract

from scopelens.domain.enums import ControlOutcome as State
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.identities.lifecycle import check_session_policy
from scopelens.identities.sessions import IdentitySessions


@contextmanager
def lab(**kwargs):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(**kwargs))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("vulnerable", [False, True])
@pytest.mark.parametrize("browser_max_age", [None, 2])
def test_real_server_expiry_has_repeat_bound_proof(vulnerable, browser_max_age):
    records = []
    with lab(vulnerable=vulnerable, browser_max_age=browser_max_age) as origin:
        policy, profile = contract(origin)
        if browser_max_age is not None:
            policy = policy.model_copy(update={"expiry_after_seconds": browser_max_age})
        with IdentitySessions(
            (profile,),
            lambda _: SecretStr(PASSWORD),
            lambda _: httpx.Client(timeout=2, trust_env=False),
        ) as sessions:
            results = check_session_policy(
                policy, sessions, lambda data: records.append(data) or "local-capture"
            )
        from scripts.verify_session_expiry_lab import assert_fixture_proof

        with httpx.Client(timeout=2, trust_env=False) as client:
            assert_fixture_proof(records[0], client.get(origin + "/fixture-proof").json())
    assert len(results) == 1
    assert results[0].rule_id == "session:student:expiry"
    assert results[0].state == ("confirmed" if vulnerable else "pass")
    assert records[0]["expiry_waited_seconds"] >= policy.expiry_after_seconds
    assert len(records[0]["expiry_replays"]) == 2
    assert all(
        r["elapsed_seconds"] >= policy.expiry_after_seconds for r in records[0]["expiry_replays"]
    )
    assert records[0]["replayed_cookie_hash"] == records[0]["new_cookie_hash"]
    assert PASSWORD not in str(records)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"denial_status": 403},
        {"denial_value": "waf"},
        {"fail_replay": True},
    ],
)
def test_server_failure_or_undeclared_response_cannot_pass(kwargs):
    records = []
    with lab(**kwargs) as origin:
        policy, profile = contract(origin)
        with IdentitySessions(
            (profile,),
            lambda _: SecretStr(PASSWORD),
            lambda _: httpx.Client(timeout=2, trust_env=False),
        ) as sessions:
            results = check_session_policy(
                policy, sessions, lambda data: records.append(data) or "local-capture"
            )
    assert results[0].state in {"blocked", "inconclusive"}
    assert all(result.state not in {"pass", "confirmed"} for result in results)


@pytest.mark.parametrize("vulnerable", [False, True])
def test_fixed_collector_expiry_is_required_in_report(tmp_path, vulnerable):
    # Use the production collector helper, overriding only the synthetic password resolver.
    from scopelens.expansion.identity_collector import collect_identity_assessments

    artifacts = []
    with lab(vulnerable=vulnerable) as origin:
        policy, profile = contract(origin)
        config = AssessmentConfiguration(
            scope_version_id=uuid4(), identities=(profile,), session_policies=(policy,)
        )

        class Control:
            secret = staticmethod(lambda _: SecretStr(PASSWORD))

        def emit(kind, data):
            artifacts.append(
                {
                    "kind": kind,
                    "data": data,
                    "source": "expansion",
                    "run_id": "local-expiry-run",
                    "evidence_ref": f"stored-{len(artifacts)}",
                }
            )

        collect_identity_assessments(
            config,
            Control(),
            lambda _: httpx.Client(timeout=2, trust_env=False),
            emit,
            cancelled=lambda: False,
        )
    outcome = evaluate(config, artifacts)["SL-C08-SESSION-01"]
    assert outcome.status is (State.CONFIRMED_ISSUE if vulnerable else State.PASS)
    assert outcome.required_instances == outcome.completed_instances == ("session:student:expiry",)
    assert outcome.is_fully_assessed
    assert (
        evaluate(config, [], trusted_refs=set())["SL-C08-SESSION-01"].status is State.INCONCLUSIVE
    )
    assert not evaluate(config, artifacts, trusted_refs=set())[
        "SL-C08-SESSION-01"
    ].is_fully_assessed
    stripped = [a for a in artifacts if a["kind"] != "identity_observation"]
    assert not evaluate(config, stripped)["SL-C08-SESSION-01"].is_fully_assessed
