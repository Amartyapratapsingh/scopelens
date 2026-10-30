"""Standalone supplied identities get read-only evidence without any control pass."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr
from tests.unit.test_html_identity_probe import BODY, DIGEST, TEXT, profile

from scopelens.academic.readiness import project_readiness
from scopelens.domain.capabilities import canonical_sha256
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import IdentityProfile, IdentityRequest, LoginRecipe, SessionPolicy
from scopelens.domain.registry import load_registry
from scopelens.evidence.intake import _redact_json_or_text
from scopelens.expansion.analysis import expansion_controls
from scopelens.expansion.identity_collector import collect_identity_assessments
from scopelens.identities.probe import probe_binding
from scopelens.identities.readiness import evaluate_identity_readiness, identity_digest

COOKIE = "JSESSIONID=synthetic-test-cookie"


@pytest.mark.parametrize(
    "error,category",
    [
        (httpx.ReadTimeout, "timeout"),
        (httpx.ProxyError, "proxy"),
        (httpx.ConnectError, "connect"),
        (httpx.RemoteProtocolError, "protocol"),
    ],
)
def test_transport_diagnostics_never_include_exception_secrets(error, category):
    config = configuration()

    def failed(request):
        raise error("Cookie=private-fixture-secret", request=request)

    artifacts, requests, _, _ = collect(config, handler=failed)
    record = artifacts[0]["data"]
    assert record["reason"] == "identity_probe_transport_unavailable"
    assert record["transport_error"] == category
    assert len(requests) == 1
    assert "private-fixture-secret" not in json.dumps(record)
    assert not evaluate_identity_readiness(
        config.identities[0],
        record,
        configuration_binding=canonical_sha256(config.model_dump(mode="json")),
    )


def test_identity_reads_negotiate_uncompressed_response():
    def handler(request):
        assert request.headers["accept-encoding"] == "identity"
        return httpx.Response(200, content=BODY, headers={"content-type": "text/html"})

    artifacts, requests, _, _ = collect(configuration(), handler=handler)
    assert len(requests) == 1
    assert artifacts[0]["data"]["state"] == "verified"


@pytest.mark.parametrize("header", ["accept-encoding", "Accept-Encoding", "ACCEPT-ENCODING"])
def test_compression_negotiation_has_one_case_insensitive_header(header):
    config = configuration()
    config = config.model_copy(
        update={
            "identities": (
                config.identities[0].model_copy(
                    update={
                        "supplied_headers": {
                            "Cookie": "fixture-cookie-reference",
                            header: "fixture-compression-reference",
                        }
                    }
                ),
            )
        }
    )

    def handler(request):
        assert request.headers.get_list("accept-encoding") == ["identity"]
        return httpx.Response(200, content=BODY, headers={"content-type": "text/html"})

    artifacts, requests, _, _ = collect(config, handler=handler)
    assert len(requests) == 1 and artifacts[0]["data"]["state"] == "verified"


@pytest.mark.parametrize("status", [200, 401, 302])
def test_failed_body_retains_header_status_without_identity_proof(status):
    def broken(request):
        return httpx.Response(
            status,
            headers={"content-encoding": "gzip", "content-type": "text/html"},
            stream=httpx.ByteStream(b"invalid gzip private-response-secret"),
        )

    config = configuration()
    artifacts, requests, _, _ = collect(config, handler=broken)
    record = artifacts[0]["data"]
    assert len(requests) == 1
    assert record["status"] is None and record["response_status"] == status
    assert record["transport_phase"] == "response_body_decode"
    assert record["transport_error"] == "decoding"
    assert record["reason"] == "identity_probe_transport_unavailable"
    assert record["observed_digest"] is None
    assert not evaluate_identity_readiness(
        config.identities[0],
        record,
        configuration_binding=canonical_sha256(config.model_dump(mode="json")),
    )
    assert "private-response-secret" not in json.dumps(record)


def configuration(*, json_probe=False, login=False, expires_at=None, anonymous=False):
    p = profile().model_copy(
        update={
            "supplied_headers": {"Cookie": "fixture-cookie-reference"},
            "expires_at": expires_at,
        }
    )
    if json_probe:
        p = p.model_copy(
            update={
                "probe": p.probe.model_copy(
                    update={
                        "response_format": "json",
                        "html_selector": None,
                        "expected_identity": TEXT,
                    }
                )
            }
        )
    if login:
        p = p.model_copy(
            update={
                "login": LoginRecipe(
                    request=IdentityRequest(method="POST", url="https://lab.invalid/login")
                )
            }
        )
    identities = (
        (p, IdentityProfile(id="anonymous", role="anonymous", anonymous=True))
        if anonymous
        else (p,)
    )
    return AssessmentConfiguration(scope_version_id=uuid4(), identities=identities)


def collect(
    config, *, handler=None, resolver=None, cancelled=lambda: False, configuration_binding=None
):
    requests, roles, artifacts, clients, references = [], [], [], [], []

    def respond(request):
        requests.append(request)
        if handler:
            return handler(request)
        assert request.headers["Cookie"] == COOKIE
        if config.identities[0].probe.response_format == "json":
            return httpx.Response(200, json={"identity": TEXT, "password": "response-secret"})
        return httpx.Response(200, content=BODY, headers={"Content-Type": "text/html"})

    def factory(role):
        roles.append(role)
        client = httpx.Client(transport=httpx.MockTransport(respond))
        clients.append(client)
        return client

    def secret(reference):
        references.append(reference)
        return resolver(reference) if resolver else SecretStr(COOKIE)

    def emit(kind, data):
        artifacts.append(
            {
                "kind": kind,
                "data": data,
                "source": "expansion",
                "run_id": "fixture",
                "evidence_ref": str(uuid4()),
            }
        )

    collect_identity_assessments(
        config,
        SimpleNamespace(secret=secret),
        factory,
        emit,
        cancelled=cancelled,
        configuration_binding=configuration_binding,
    )
    assert all(client.is_closed for client in clients)
    return artifacts, requests, roles, references


def projection(config, artifacts):
    digest = canonical_sha256(config.model_dump(mode="json"))
    identifier = uuid4()
    return project_readiness(
        configuration_id=identifier,
        configuration_hash=digest,
        config=config,
        profile="authenticated-api-v1",
        scan_id=uuid4(),
        frozen={
            "configuration_id": str(identifier),
            "configuration_hash": digest,
            "expansion_config": config.model_dump(mode="json"),
        },
        artifacts=artifacts,
    )


@pytest.mark.parametrize("json_probe", [False, True])
def test_standalone_supplied_identity_is_observed_without_login_or_control_pass(json_probe):
    config = configuration(json_probe=json_probe)
    artifacts, requests, roles, references = collect(config)
    assert len(requests) == len(artifacts) == 1
    assert requests[0].method == "GET"
    assert requests[0].url.path == "/home"
    assert roles == ["student"]
    assert references == ["fixture-cookie-reference"]
    record = artifacts[0]["data"]
    assert record["state"] == "verified"
    assert record["reason"] == "identity_probe_verified"
    assert record["probe_binding"] == probe_binding(config.identities[0].probe)
    assert record["observed_digest"] == identity_digest(
        config.identities[0].probe.expected_identity
    )
    assert evaluate_identity_readiness(
        config.identities[0],
        record,
        configuration_binding=canonical_sha256(config.model_dump(mode="json")),
    )
    serialized = json.dumps(artifacts)
    for private in (TEXT, COOKIE, "response-secret", "fixture-cookie-reference", "<html>"):
        assert private not in serialized
    stored = json.loads(_redact_json_or_text(serialized))[0]
    assert stored["data"]["observed_digest"] == record["observed_digest"]
    result = projection(config, [stored])
    assert result.actors[0].identity_evidence == "verified_probe"
    assert result.coverage.executed == result.coverage.proven == result.coverage.fully_assessed == 0
    assert result.cases == ()
    assert (
        expansion_controls(
            artifacts,
            {"expansion_config": config.model_dump(mode="json")},
            load_registry(Path("checks_registry")),
            trusted_refs={a["evidence_ref"] for a in artifacts},
        )
        == ()
    )


def test_declared_login_recipe_is_never_used_for_readiness():
    config = configuration(login=True)
    artifacts, requests, _, _ = collect(config)
    assert artifacts[0]["data"]["state"] == "verified"
    assert [request.method for request in requests] == ["GET"]
    assert all(request.url.path != "/login" for request in requests)


def test_anonymous_profiles_are_skipped_and_never_used_as_fallback():
    config = configuration(anonymous=True)
    artifacts, requests, roles, _ = collect(config, handler=lambda _: httpx.Response(401))
    assert len(requests) == len(artifacts) == 1
    assert roles == ["student"]
    assert artifacts[0]["data"]["state"] == "blocked"


@pytest.mark.parametrize(
    "failure",
    [
        "missing",
        "revoked",
        "empty",
        "expired_profile",
        "cancelled",
        "cancel_during_resolve",
        "expires_during_resolve",
        "no_references",
        "post_probe",
        "probe_body",
    ],
)
def test_unavailable_credentials_and_unsafe_probes_block_before_target_io(failure):
    config = configuration()
    state = {"cancelled": False}
    resolver = None
    if failure == "expired_profile":
        config = configuration(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    elif failure in {"missing", "revoked"}:

        def resolver(_):
            raise PermissionError("sensitive-secret-that-must-not-be-emitted")
    elif failure == "empty":

        def resolver(_):
            return SecretStr("")
    elif failure == "cancelled":
        state["cancelled"] = True
    elif failure == "cancel_during_resolve":

        def resolver(_):
            state["cancelled"] = True
            return SecretStr(COOKIE)
    elif failure == "expires_during_resolve":
        expires = datetime.now(UTC) + timedelta(minutes=1)
        config = configuration(expires_at=expires)

        def resolver(_):
            config.identities[0].__dict__["expires_at"] = datetime.now(UTC) - timedelta(seconds=1)
            return SecretStr(COOKIE)
    elif failure == "no_references":
        config = config.model_copy(
            update={
                "identities": (config.identities[0].model_copy(update={"supplied_headers": {}}),)
            }
        )
    else:
        p = config.identities[0]
        request = p.probe.request.model_copy(
            update={"method": "POST"} if failure == "post_probe" else {"json_body": {"q": "input"}}
        )
        config = config.model_copy(
            update={
                "identities": (
                    p.model_copy(update={"probe": p.probe.model_copy(update={"request": request})}),
                )
            }
        )
    artifacts, requests, roles, _ = collect(
        config, resolver=resolver, cancelled=lambda: state["cancelled"]
    )
    assert requests == roles == []
    record = artifacts[0]["data"]
    assert record["state"] == "blocked"
    assert record["observed_digest"] is None
    assert record["reason"] != "identity_probe_not_observed"
    assert "sensitive-secret" not in json.dumps(artifacts)
    assert not evaluate_identity_readiness(
        config.identities[0], record, configuration_binding=record["configuration_binding"]
    )


@pytest.mark.parametrize(
    "status,body,content_type,reason",
    [
        (401, b"", "text/html", "identity_probe_unauthenticated"),
        (403, b"", "text/html", "identity_probe_unauthenticated"),
        (302, BODY, "text/html", "identity_probe_redirect_not_followed"),
        (
            200,
            b"<html>anonymous login page</html>",
            "text/html",
            "identity_probe_invalid_or_mismatched",
        ),
        (200, BODY + BODY, "text/html", "identity_probe_invalid_or_mismatched"),
        (
            200,
            BODY.replace(TEXT.encode(), b"another identity"),
            "text/html",
            "identity_probe_invalid_or_mismatched",
        ),
        (
            200,
            json.dumps({"identity": DIGEST}).encode(),
            "application/json",
            "identity_probe_invalid_or_mismatched",
        ),
        (200, b"x" * 1048577, "text/html", "identity_probe_transport_or_response_unavailable"),
    ],
)
def test_failed_probe_records_redacted_reason_and_never_verifies(
    status, body, content_type, reason
):
    config = configuration()
    artifacts, requests, roles, _ = collect(
        config,
        handler=lambda _: httpx.Response(
            status,
            content=body,
            headers={"Content-Type": content_type, "Location": "https://unapproved.invalid/login"},
        ),
    )
    assert len(requests) == 1
    assert roles == ["student"]
    record = artifacts[0]["data"]
    assert record["state"] == "blocked"
    assert record["reason"] == reason
    assert record["observed_digest"] is None
    assert projection(config, artifacts).actors[0].identity_evidence == "failed_probe"


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", "other"),
        ("proof_type", "access"),
        ("proof_id", "anonymous"),
        ("configuration_binding", "0" * 64),
        ("probe_binding", "sha256:" + "0" * 64),
        ("method", "POST"),
        ("url", "https://lab.invalid/other"),
        ("status", 401),
        ("observed_digest", None),
        ("observed_at", "2026-10-05T00:00:00"),
    ],
)
def test_readiness_replays_require_exact_frozen_configuration_and_probe(field, value):
    config = configuration()
    artifacts, *_ = collect(config)
    record = deepcopy(artifacts[0]["data"])
    record[field] = value
    record["state"] = "verified"
    record["reason"] = "identity_probe_verified"
    assert not evaluate_identity_readiness(
        config.identities[0],
        record,
        configuration_binding=canonical_sha256(config.model_dump(mode="json")),
        now=datetime.now(UTC),
    )


def test_original_configuration_binding_survives_filtered_execution_configuration():
    config = configuration()
    original = config.model_copy(
        update={
            "session_policies": (SessionPolicy(identity_id="student", cookie_name="JSESSIONID"),)
        }
    )
    binding = canonical_sha256(original.model_dump(mode="json"))
    assert binding != canonical_sha256(config.model_dump(mode="json"))
    artifacts, *_ = collect(config, configuration_binding=binding)
    assert projection(original, artifacts).actors[0].identity_evidence == "verified_probe"
    without_original_binding, *_ = collect(config)
    assert (
        projection(original, without_original_binding).actors[0].identity_evidence == "not_observed"
    )


def test_untrusted_source_cannot_establish_readiness():
    config = configuration()
    artifacts, *_ = collect(config)
    artifacts[0]["source"] = "adaptive"
    assert projection(config, artifacts).actors[0].identity_evidence == "not_observed"
    artifacts[0].update(source="expansion", evidence_ref="")
    assert projection(config, artifacts).actors[0].identity_evidence == "not_observed"


def test_worker_passes_original_frozen_binding_to_standalone_collection(monkeypatch):
    from tests.unit.test_html_identity_probe import configured_input

    from scopelens.expansion import worker

    config = configuration()
    original = config.model_copy(
        update={
            "session_policies": (SessionPolicy(identity_id="student", cookie_name="JSESSIONID"),)
        }
    )
    binding = canonical_sha256(original.model_dump(mode="json"))
    catalogue, plan, _ = configured_input()
    plan = plan.model_copy(update={"tasks": (), "denominator": 0})
    payload = {
        "configuration": config.model_dump(mode="json"),
        "configuration_binding": binding,
        "catalogue": catalogue.model_dump(mode="json"),
        "plan": plan.model_dump(mode="json"),
    }
    artifacts, requests = [], []

    def respond(request):
        requests.append(request)
        assert request.headers["Cookie"] == COOKIE
        return httpx.Response(200, content=BODY, headers={"Content-Type": "text/html"})

    class Crawler:
        def __init__(self, _):
            pass

        def _http(self):
            return httpx.Client(transport=httpx.MockTransport(respond))

    class Control:
        def __init__(self, _):
            pass

        def secret(self, _):
            return SecretStr(COOKIE)

    monkeypatch.setenv("SCOPELENS_EXPANSION_INPUT", json.dumps(payload))
    monkeypatch.setenv("SCOPELENS_SCANNER_TOOLS_ENABLED", "false")
    monkeypatch.setattr(worker, "Crawler", Crawler)
    monkeypatch.setattr(worker, "config_from_env", lambda: None)
    monkeypatch.setattr(worker, "AssessmentControlClient", Control)
    monkeypatch.setattr(
        worker,
        "collect_exposure_pack",
        lambda *args, **kwargs: SimpleNamespace(observations=(), model_dump=lambda **kwargs: {}),
    )
    monkeypatch.setattr(
        worker, "emit", lambda kind, data: artifacts.append({"kind": kind, "data": data})
    )
    monkeypatch.setattr(worker, "_cancelled", False)
    worker.main()
    readiness = [a["data"] for a in artifacts if a["kind"] == "identity_observation"]
    assert len(readiness) == len(requests) == 1
    assert readiness[0]["configuration_binding"] == binding
    assert readiness[0]["state"] == "verified"
