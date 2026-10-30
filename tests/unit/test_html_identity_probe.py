"""HTML session probes use exact bounded text and never persist account values."""

import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from scopelens.domain.identity import (
    IdentityProfile,
    IdentityRequest,
    PermissionMatrix,
    SessionProbe,
)
from scopelens.expansion.authenticated_inputs import IDENTITY_PROOF_VERSION, evaluate_input_identity
from scopelens.identities.browser import BrowserIdentitySessions
from scopelens.identities.probe import (
    parse_probe_document,
    probe_binding,
    probe_binding_matches,
    response_probe_value,
)
from scopelens.identities.proof import select_identity_response
from scopelens.identities.sessions import IdentitySessions

TEXT = "Dedicated synthetic student"
SELECTOR = ".user-menu .dropdown-toggle span.hidden-xs"
BODY = f'<html><body><div class="user-menu"><a class="dropdown-toggle"><span class="hidden-xs"> {TEXT} </span></a></div></body></html>'.encode()
DIGEST = "sha256:" + hashlib.sha256(TEXT.encode()).hexdigest()


def profile(**probe_changes):
    return IdentityProfile(
        id="student",
        role="student",
        probe=SessionProbe(
            request=IdentityRequest(url="https://lab.invalid/home"),
            response_format="html",
            html_selector=SELECTOR,
            expected_identity=DIGEST,
            **probe_changes,
        ),
    )


def test_json_contract_serialization_is_unchanged():
    data = {
        "request": IdentityRequest(url="https://lab.invalid/me").model_dump(mode="json"),
        "identity_pointer": "/identity",
        "expected_identity": "student",
        "unauthenticated_pointer": None,
        "unauthenticated_value": None,
        "unauthenticated_statuses": [401],
    }
    assert SessionProbe.model_validate(data).model_dump(mode="json") == data
    assert probe_binding_matches(SessionProbe.model_validate(data), None)
    assert not probe_binding_matches(profile().probe, None)


@pytest.mark.parametrize(
    "changes",
    [
        {"html_selector": None},
        {"html_selector": "script"},
        {"html_selector": ".menu input"},
        {"html_selector": "span[value=student]"},
        {"html_selector": "span:first-child"},
        {"html_selector": "span,div"},
        {"html_selector": ".a" * 129},
        {"expected_identity": TEXT},
        {"expected_identity": "sha256:" + "A" * 64},
        {"identity_pointer": "/account"},
        {"unauthenticated_pointer": "/error"},
    ],
)
def test_invalid_html_contract_is_rejected(changes):
    data = profile().probe.model_dump(mode="json")
    data.update(changes)
    with pytest.raises(ValidationError):
        SessionProbe.model_validate(data)


def test_json_cannot_declare_html_selector():
    with pytest.raises(ValidationError):
        SessionProbe(
            request=IdentityRequest(url="https://lab.invalid/me"),
            expected_identity="student",
            html_selector=SELECTOR,
        )


def test_html_digest_is_exact_and_browser_adapter_keeps_provenance():
    p = profile()
    document = parse_probe_document(p.probe, BODY)
    assert document == {"identity": DIGEST}
    assert (
        parse_probe_document(p.probe, BODY.replace(TEXT.encode(), TEXT.upper().encode()))
        != document
    )
    matrix = PermissionMatrix(version="test", objects=(), rules=())
    adapter = SimpleNamespace(status_code=200, json=lambda: document)
    selected = select_identity_response(
        p.id, p.probe.request, adapter, (p,), matrix, evidence_ref="trusted"
    )
    assert selected.document == {"identity": DIGEST}
    assert selected.probe_binding == probe_binding(p.probe)
    adapter.json = lambda: {"identity": DIGEST}
    assert (
        select_identity_response(
            p.id, p.probe.request, adapter, (p,), matrix, evidence_ref="trusted"
        ).document
        == {}
    )
    for observation in (document, selected.model_dump(mode="json")):
        encoded = json.dumps(observation)
        assert TEXT not in encoded
        assert "<html>" not in encoded


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"<span>missing selector</span>",
        BODY + BODY,
        BODY.replace(TEXT.encode(), b" "),
        BODY.replace(TEXT.encode(), b"x" * 257),
        BODY.replace(TEXT.encode(), b"bad\x01text"),
        BODY.replace(TEXT.encode(), b"bad\xfftext"),
        BODY.replace(TEXT.encode(), b"\x1c" + TEXT.encode()),
        b"<![malformed]>" + BODY,
        BODY.replace(TEXT.encode(), b"&#xD800;"),
        BODY.replace(TEXT.encode(), b"bad&#0;text"),
        BODY.replace(TEXT.encode(), b"<script>name</script>"),
        BODY.replace(TEXT.encode(), b'<input value="name">'),
        b"<form>" + BODY + b"</form>",
        BODY + b'<form><input type="password"></form>',
        BODY + f'<input value="{TEXT}">'.encode(),
        BODY + b" " * 1048576,
        json.dumps({"identity": DIGEST}).encode(),
    ],
)
def test_html_extraction_fails_closed(body):
    assert parse_probe_document(profile().probe, body) is None


@pytest.mark.parametrize(
    "status,body,content_type,expected",
    [
        (200, BODY, "text/html; charset=utf-8", True),
        (200, BODY, "application/xhtml+xml", True),
        (200, BODY, "application/json", False),
        (302, BODY, "text/html", False),
        (200, BODY.replace(TEXT.encode(), b"Another synthetic student"), "text/html", False),
        (200, json.dumps({"identity": DIGEST}).encode(), "application/json", False),
        (200, b"<html>login</html>", "text/html", False),
    ],
)
def test_http_and_browser_use_same_probe(status, body, content_type, expected):
    p = profile()
    observed = []

    def handler(request):
        return httpx.Response(status, content=body, headers={"Content-Type": content_type})

    with IdentitySessions(
        (p,),
        lambda _: SecretStr("unused"),
        lambda _: httpx.Client(transport=httpx.MockTransport(handler)),
        response_observer=lambda i, r, response: observed.append(
            response_probe_value(response, p.probe)
        ),
    ) as sessions:
        assert sessions.verify(p.id) is expected

    class Response:
        def __init__(self):
            self.status, self.headers, self.disposed = status, {"content-type": content_type}, False

        def body(self):
            return body

        def json(self):
            return json.loads(body)

        def dispose(self):
            self.disposed = True

    response = Response()
    context = SimpleNamespace(
        cookies=lambda: [],
        request=SimpleNamespace(fetch=lambda *args, **kwargs: response),
        clear_cookies=lambda: None,
        close=lambda: None,
    )
    browser_observed = []
    sessions = BrowserIdentitySessions(
        (p,),
        lambda _: SecretStr("unused"),
        lambda _: context,
        response_observer=lambda i, r, s, d: browser_observed.append(d),
    )
    try:
        assert sessions.verify(p.id, action_owner="test") is expected
        assert response.disposed
        assert TEXT not in json.dumps(browser_observed)
    finally:
        sessions.close()


@pytest.mark.parametrize("binding", [None, "sha256:" + "0" * 64, "json", "other-selector"])
def test_legacy_or_wrong_binding_cannot_qualify_html_input_proof(binding):
    p = profile()
    task = SimpleNamespace(id="task", template_id="template")
    template = SimpleNamespace(id="template", role_id=p.id, origin="https://lab.invalid")
    proof = {
        "version": IDENTITY_PROOF_VERSION,
        "plan_id": "plan",
        "task_id": task.id,
        "template_id": template.id,
        "role_id": p.id,
        "probes": [],
    }
    for phase in ("before", "after"):
        proof["probes"].append(
            {
                "phase": phase,
                "identity_id": p.id,
                "method": "GET",
                "url": p.probe.request.url,
                "pointer": "/identity",
                "status": 200,
                "observed_identity": DIGEST,
                "observed_at": datetime.now(UTC).isoformat(),
                "probe_binding": binding,
            }
        )
    assert not evaluate_input_identity(p, task, template, "plan", proof)[0]
    for item in proof["probes"]:
        item["probe_binding"] = probe_binding(p.probe)
    assert evaluate_input_identity(p, task, template, "plan", proof)[0]
    changed = p.model_copy(
        update={"probe": p.probe.model_copy(update={"html_selector": "span.hidden-xs"})}
    )
    assert not evaluate_input_identity(changed, task, template, "plan", proof)[0]


def test_http_capture_retains_only_matched_digest_and_binding():
    p = profile()
    matrix = PermissionMatrix(version="test", objects=(), rules=())
    response = httpx.Response(200, content=BODY, headers={"Content-Type": "text/html"})
    record = select_identity_response(
        p.id, p.probe.request, response, (p,), matrix, evidence_ref="trusted"
    )
    assert record.document == {"identity": DIGEST}
    assert record.probe_binding == probe_binding(p.probe)
    assert TEXT not in record.model_dump_json()
    assert "html" not in record.model_dump_json()
    response = httpx.Response(200, json={"identity": DIGEST})
    assert (
        select_identity_response(
            p.id, p.probe.request, response, (p,), matrix, evidence_ref="trusted"
        ).document
        == {}
    )


def configured_input():
    from tests.integration.test_authenticated_inputs import configured

    catalogue, plan, p = configured("https://lab.invalid", role="student")
    return catalogue, plan, p.model_copy(update={"probe": profile().probe})


def test_generic_http_capture_emits_html_digest_and_exact_binding():
    from urllib.parse import parse_qs

    from scopelens.expansion.authenticated_inputs import run_authenticated_inputs

    catalogue, plan, p = configured_input()
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/home":
            return httpx.Response(200, content=BODY, headers={"Content-Type": "text/html"})
        value = parse_qs(request.url.query.decode()).get("next", ["/safe"])[0]
        return httpx.Response(302, headers={"Location": value})

    with httpx.Client(transport=httpx.MockTransport(handler)) as anonymous:
        result = run_authenticated_inputs(
            catalogue,
            plan,
            anonymous,
            (p,),
            lambda _: httpx.Client(transport=httpx.MockTransport(handler)),
            lambda _: SecretStr("synthetic-token"),
        )
    data = result[0]["data"]
    assert data["state"] == "confirmed", data
    proof = data["identity_proof"]
    assert [item["phase"] for item in proof["probes"]] == ["before", "after"]
    assert all(
        item["observed_identity"] == DIGEST and item["probe_binding"] == probe_binding(p.probe)
        for item in proof["probes"]
    )
    assert evaluate_input_identity(p, plan.tasks[0], catalogue.templates[0], plan.id, proof)[0]
    assert TEXT not in json.dumps(result)
    assert all(request.method == "GET" for request in requests)


def test_generic_browser_capture_and_replay_bind_html_contract():
    from scopelens.expansion.authenticated_browser import (
        AuthenticatedBrowserLifecycle,
        evaluate_browser_input_identity,
    )

    catalogue, plan, p = configured_input()
    contexts = []

    class Response:
        status = 200

        def __init__(self):
            self.headers = {"content-type": "text/html"}

        def body(self):
            return BODY

        def dispose(self):
            pass

    def factory(_):
        context = SimpleNamespace(
            cookies=lambda: [],
            request=SimpleNamespace(fetch=lambda *args, **kwargs: Response()),
            clear_cookies=lambda: None,
            close=lambda: None,
        )
        contexts.append(context)
        return context

    lifecycle = AuthenticatedBrowserLifecycle(
        catalogue, plan, (p,), factory, lambda _: SecretStr("synthetic-token")
    )
    proofs, captures = [], []
    template, task = catalogue.templates[0], plan.tasks[0]
    for name in ("baseline", "probe1", "probe2"):
        probe = lifecycle.open(
            task,
            template,
            plan.id,
            name,
            {"url": "https://lab.invalid/bad/redirect", "headers": {}},
        )
        probe.before()
        probe.finish()
        proofs.append(probe.proof)
        captures.append({"name": name, "context_id": probe.context_id})
    assert len(contexts) == 3
    assert evaluate_browser_input_identity(p, task, template, plan.id, proofs, captures)[0]
    assert TEXT not in json.dumps(proofs)
    proofs[0]["identity_proof"]["probes"][0].pop("probe_binding")
    assert not evaluate_browser_input_identity(p, task, template, plan.id, proofs, captures)[0]


def test_access_replay_rejects_legacy_html_proofs_and_changed_selectors():
    from scopelens.domain.identity import OwnedTestObject, PermissionRule
    from scopelens.identities.proof import CapturedIdentityResponse, evaluate_access_proof

    p = profile()
    target = OwnedTestObject(
        id="seed",
        owner_identity=p.id,
        request=IdentityRequest(url="https://lab.invalid/object"),
        marker_pointer="/marker",
        marker="synthetic-owned-marker",
    )
    matrix = PermissionMatrix(
        version="test",
        objects=(target,),
        rules=(
            PermissionRule(
                id="rule", object_id=target.id, identity_id=p.id, family="object", allowed=True
            ),
        ),
    )
    records = []
    for is_probe in (True, False, True, True, False, True, True, False, True):
        request = p.probe.request if is_probe else target.request
        records.append(
            CapturedIdentityResponse(
                identity_id=p.id,
                method="GET",
                url=request.url,
                status=200,
                document={"identity": DIGEST} if is_probe else {"marker": target.marker},
                evidence_ref=f"trusted-{len(records)}",
                probe_binding=probe_binding(p.probe) if is_probe else None,
            )
        )
    assert evaluate_access_proof(matrix, (p,), "rule", tuple(records)).state == "pass"
    legacy = tuple(record.model_copy(update={"probe_binding": None}) for record in records)
    assert evaluate_access_proof(matrix, (p,), "rule", legacy).state == "inconclusive"
    changed = p.model_copy(
        update={"probe": p.probe.model_copy(update={"html_selector": "span.hidden-xs"})}
    )
    assert evaluate_access_proof(matrix, (changed,), "rule", tuple(records)).state == "inconclusive"


def test_lifecycle_replay_requires_html_probe_binding():
    from tests.unit.test_session_fingerprints import session_policy, session_record

    from scopelens.identities.lifecycle import evaluate_session_proof

    policy, original = session_policy()
    p = original.model_copy(update={"probe": profile().probe})
    record = session_record()
    record.update(initial_identity=DIGEST, new_identity=DIGEST)
    assert evaluate_session_proof(policy, p, record)[0] == "inconclusive"
    record["probe_binding"] = probe_binding(p.probe)
    assert evaluate_session_proof(policy, p, record)[0] == "pass"
