"""Native Chromium CORS proof on synthetic loopback origins; no external requests."""

import copy
import json
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace

import pytest
from labs.expansion_browser.app import FIXTURE_PASSWORD, handler
from playwright.sync_api import sync_playwright
from pydantic import SecretStr

from scopelens.domain.assessment import DiscoveryCatalogue
from scopelens.domain.enums import ProfileName
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.browser_worker import (
    GuardedContext,
    RequestGuard,
    collect_browser_assessments,
)
from scopelens.expansion.integration import freeze_revision
from scopelens.identities.cors import (
    collect_cors_proof,
    cors_configuration_binding,
    evaluate_cors_proof,
)

MARKER = "scopelens-owned-cors-marker-84721"


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        item = p.chromium.launch(headless=True)
        yield item
        item.close()


@contextmanager
def sites(mode=None):
    events = []
    base = handler({"bad": "", "fixed": ""})

    class App(base):
        def respond(self):
            events.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "origin": self.headers.get("Origin"),
                    "cookie": bool(self.headers.get("Cookie")),
                    "authorization": bool(self.headers.get("Authorization")),
                }
            )
            if mode == "public" and self.path.endswith("cors-record"):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"private": MARKER}).encode())
                return
            if (
                mode == "revoked"
                and self.path.endswith("identity")
                and any(e["origin"] for e in events)
            ):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"{}")
                return
            if (
                mode == "redirect"
                and self.path.endswith("cors-record")
                and self.headers.get("Origin")
            ):
                self.send_response(302)
                self.send_header("Location", "/never-follow")
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.end_headers()
                return
            return super().respond()

        do_GET = respond
        do_POST = respond

    servers = [ThreadingHTTPServer(("127.0.0.1", 0), App) for _ in range(2)]
    threads = [Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    try:
        yield *(f"http://127.0.0.1:{s.server_port}" for s in servers), events
    finally:
        for s, t in zip(servers, threads, strict=True):
            s.shutdown()
            s.server_close()
            t.join(timeout=2)


def configuration(origin, foreign, variant="bad"):
    scope_id, foreign_id = uuid.uuid4(), uuid.uuid4()
    return AssessmentConfiguration.model_validate(
        {
            "scope_version_id": str(scope_id),
            "related_origins": [
                {
                    "origin": foreign,
                    "purpose": "scan",
                    "scope_version_id": str(foreign_id),
                    "grant_id": "controlled-page",
                }
            ],
            "identities": [
                {
                    "id": "A",
                    "role": "owner",
                    "login": {
                        "request": {
                            "method": "POST",
                            "url": origin + f"/{variant}/credential-login",
                            "json_body": {"role": "A"},
                            "secret_fields": {"password": "fixture-reference"},
                        }
                    },
                    "probe": {
                        "request": {"url": origin + f"/{variant}/identity"},
                        "expected_identity": "A",
                    },
                },
                {"id": "anonymous", "role": "anonymous", "anonymous": True},
            ],
            "cors_recipes": [
                {
                    "id": "cors-owned-record",
                    "foreign_url": foreign + "/foreign",
                    "foreign_scope_version_id": str(foreign_id),
                    "foreign_grant_id": "controlled-page",
                    "target": {
                        "id": "owned-seed",
                        "owner_identity": "A",
                        "request": {"url": origin + f"/{variant}/cors-record"},
                        "marker_pointer": "/private",
                        "marker": MARKER,
                    },
                }
            ],
        }
    )


def setup(config, origin, browser, cancelled=lambda: False):
    cat = DiscoveryCatalogue(origin=origin)
    _, plan, _, _ = freeze_revision(
        {},
        cat,
        config,
        scope=SimpleNamespace(
            id=config.scope_version_id, allowed_check_profile=ProfileName.AUTHENTICATED_API_V1
        ),
        run_id="test",
    )
    crawl = SimpleNamespace(origin=origin, allowed_path_prefixes=("/",), excluded_paths=())
    guard = RequestGuard(config, cat, plan, crawl, cancelled=cancelled, limit=50)

    def factory(_):
        return GuardedContext(
            browser.new_context(service_workers="block"), guard, "synthetic-egress"
        )

    return cat, plan, crawl, guard, factory


def collect(config, origin, browser, cancelled=lambda: False, grant=True):
    *_, guard, factory = setup(config, origin, browser, cancelled)
    return collect_cors_proof(
        config.cors_recipes[0],
        config.identities,
        factory,
        lambda _: SecretStr(FIXTURE_PASSWORD),
        action_owner="fixture-controller",
        configuration_binding=cors_configuration_binding(config),
        allowed_foreign_origins=frozenset(guard.origins if grant else ()),
        cancelled=cancelled,
    )


@pytest.mark.parametrize("variant,expected", [("bad", "confirmed"), ("fixed", "inconclusive")])
def test_native_runtime_ambient_cookies_and_reports_fact_sequence(browser, variant, expected):
    with sites() as (origin, foreign, events):
        config = configuration(origin, foreign, variant)
        proof = collect(config, origin, browser)
        assert (
            evaluate_cors_proof(
                config.cors_recipes[0],
                config.identities,
                proof,
                configuration_binding=cors_configuration_binding(config),
            )[0]
            == expected
        ), proof
        assert [f["phase"] for f in proof["facts"]] == [
            "before",
            "owner_baseline",
            "anonymous_baseline",
            "foreign_page",
            "read_1",
            "read_2",
            "after",
        ]
        native = [e for e in events if e["origin"] == foreign]
        assert len(native) == 2 and all(e["cookie"] and not e["authorization"] for e in native)
        assert all(e["method"] == "GET" or e["path"].endswith("credential-login") for e in events)
        assert FIXTURE_PASSWORD not in json.dumps(proof) and "sid=A" not in json.dumps(proof)


@pytest.mark.parametrize("mode", ["public", "revoked", "redirect", "cancel", "missing_grant"])
def test_missing_authority_identity_or_actual_browser_read_never_confirms(browser, mode):
    with sites(mode) as (origin, foreign, events):
        config = configuration(origin, foreign)

        def cancelled():
            return mode == "cancel" and any(e["origin"] for e in events)

        proof = collect(config, origin, browser, cancelled, grant=mode != "missing_grant")
        assert (
            evaluate_cors_proof(
                config.cors_recipes[0],
                config.identities,
                proof,
                configuration_binding=cors_configuration_binding(config),
            )[0]
            == "inconclusive"
        )
        assert not any(e["path"] == "/never-follow" for e in events)
        if mode == "missing_grant":
            assert events == []
        if mode in {"revoked", "cancel"}:
            assert proof["facts"] and proof["error"]
            assert sum(e["path"].endswith("credential-login") for e in events) == 1


@pytest.fixture(scope="module")
def valid_proof(browser):
    with sites() as (origin, foreign, _):
        config = configuration(origin, foreign)
        return config, collect(config, origin, browser)


@pytest.mark.parametrize(
    "change",
    [
        "binding",
        "recipe",
        "context",
        "before",
        "after",
        "public",
        "requests",
        "origin",
        "header",
        "marker",
        "timestamp",
        "expired",
        "booleans",
    ],
)
def test_proof_tampering_or_incomplete_records_cannot_confirm(valid_proof, change):
    config, raw = valid_proof
    proof = copy.deepcopy(raw)
    if change == "binding":
        proof["configuration_binding"] = "invented"
    elif change == "recipe":
        proof["recipe_id"] = "other"
    elif change == "context":
        proof["context_ids"]["anonymous"] = proof["context_ids"]["A"]
    elif change == "before":
        proof["facts"][0]["observed_identity"] = "other"
    elif change == "after":
        proof["facts"].pop()
    elif change == "public":
        proof["facts"][2]["status"] = 200
    elif change == "requests":
        proof["facts"][4]["requests"] = []
    elif change == "origin":
        proof["facts"][4]["requests"][0]["origin"] = "https://unapproved.invalid"
    elif change == "header":
        proof["facts"][4]["requests"][0]["authorization_present"] = True
    elif change == "marker":
        proof["facts"][4]["selected_value"] = None
    elif change == "timestamp":
        proof["facts"][0]["captured_at"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    elif change == "expired":
        config = config.model_copy(
            update={
                "identities": (
                    config.identities[0].model_copy(
                        update={"expires_at": datetime.now(UTC) - timedelta(days=1)}
                    ),
                    config.identities[1],
                )
            }
        )
    else:
        proof = {"confirmed": True, "readable": True, "marker_seen": True}
    assert (
        evaluate_cors_proof(
            config.cors_recipes[0],
            config.identities,
            proof,
            configuration_binding=cors_configuration_binding(config),
        )[0]
        == "inconclusive"
    )


def test_fixed_browser_collector_dispatches_cors_and_revision_cannot_replay(browser):
    with sites() as (origin, foreign, _):
        config = configuration(origin, foreign)
        cat, plan, crawl, _, _ = setup(config, origin, browser)
        artifacts = []
        result = collect_browser_assessments(
            config,
            cat,
            plan,
            browser,
            SimpleNamespace(secret=lambda _: SecretStr(FIXTURE_PASSWORD)),
            crawl,
            lambda kind, data: artifacts.append({"kind": kind, "data": data}),
            owner="controlled-worker",
            token="synthetic-egress",
            cancelled=lambda: False,
        )
        assert result["complete"], artifacts
        row = next(a for a in artifacts if a["data"].get("proof_type") == "credentialed_cors")
        assert row["kind"] == "identity_observation"
        target = SimpleNamespace(
            id=config.scope_version_id, allowed_check_profile=ProfileName.AUTHENTICATED_API_V1
        )
        frozen, _, _, first = freeze_revision({}, cat, config, scope=target, run_id="first")
        _, _, _, second = freeze_revision(frozen, cat, config, scope=target, run_id="second")
        assert first.cors_recipes and not second.cors_recipes


@pytest.mark.parametrize(
    "fault", ["untrusted", "wrong_source", "duplicate", "wrong_run", "missing_after", None]
)
def test_only_unique_admitted_browser_facts_reach_report(valid_proof, fault):
    from pathlib import Path

    from scopelens.domain.registry import load_registry
    from scopelens.expansion.analysis import expansion_controls

    config, proof = valid_proof
    artifact = {
        "kind": "identity_observation",
        "source": "expansion_browser",
        "run_id": "reviewed-browser-run",
        "evidence_ref": "trusted-cors",
        "data": {
            "proof_type": "credentialed_cors",
            "proof_id": config.cors_recipes[0].id,
            "kind": "credentialed_cors_proof",
            **copy.deepcopy(proof),
        },
    }
    refs = {"trusted-cors"}
    rows = [artifact]
    if fault == "untrusted":
        refs = set()
    elif fault == "wrong_source":
        artifact["source"] = "expansion"
    elif fault == "duplicate":
        rows.append(copy.deepcopy(artifact))
    elif fault == "wrong_run":
        duplicate = copy.deepcopy(artifact)
        duplicate.update(run_id="another-attempt", evidence_ref="trusted-second")
        refs.add("trusted-second")
        rows.append(duplicate)
    elif fault == "missing_after":
        artifact["data"]["facts"].pop()
    controls = expansion_controls(
        rows,
        {"expansion_config": config.model_dump(mode="json")},
        load_registry(Path("checks_registry")),
        trusted_refs=refs,
    )
    outcome = next(c.evaluate(None) for c in controls if c.check_id == "SL-C04-CORSDATA-01")
    assert outcome.status.value == ("confirmed_issue" if fault is None else "inconclusive")
    assert bool(outcome.completed_instances) == (fault is None)
    assert outcome.required_instances == (config.cors_recipes[0].id,)


@pytest.mark.parametrize(
    "change",
    [
        "write",
        "header",
        "probe_write",
        "probe_body",
        "same_origin",
        "missing_grant",
        "resource_only",
        "anonymous_owner",
        "same_identity",
    ],
)
def test_invalid_cors_authority_cannot_be_frozen(change):
    from pydantic import ValidationError

    payload = configuration("http://127.0.0.1:8080", "http://127.0.0.1:8081").model_dump(
        mode="json"
    )
    recipe = payload["cors_recipes"][0]
    if change == "write":
        recipe["target"]["request"]["method"] = "POST"
    elif change == "header":
        payload["identities"][0]["supplied_headers"] = {"Authorization": "ref"}
    elif change == "probe_write":
        payload["identities"][0]["probe"]["request"]["method"] = "POST"
    elif change == "probe_body":
        payload["identities"][0]["probe"]["request"]["json_body"] = {"q": "value"}
    elif change == "same_origin":
        recipe["foreign_url"] = "http://127.0.0.1:8080/foreign"
    elif change == "missing_grant":
        payload["related_origins"] = []
    elif change == "resource_only":
        payload["related_origins"][0]["purpose"] = "resource_only"
    elif change == "anonymous_owner":
        recipe["target"]["owner_identity"] = "anonymous"
    elif change == "same_identity":
        recipe["anonymous_identity_id"] = "A"
    with pytest.raises(ValidationError):
        AssessmentConfiguration.model_validate(payload)


def test_expired_profile_and_cancellation_during_secret_resolution_send_no_login(browser):
    with sites() as (origin, foreign, events):
        config = configuration(origin, foreign)
        expired = config.model_copy(
            update={
                "identities": (
                    config.identities[0].model_copy(
                        update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
                    ),
                    config.identities[1],
                )
            }
        )
        proof = collect(expired, origin, browser)
        assert proof["error"] and events == []
        *_, guard, factory = setup(config, origin, browser)
        state = {"cancelled": False}

        def resolve(_):
            state["cancelled"] = True
            return SecretStr(FIXTURE_PASSWORD)

        captured = []
        proof = collect_cors_proof(
            config.cors_recipes[0],
            config.identities,
            factory,
            resolve,
            action_owner="fixture-controller",
            configuration_binding=cors_configuration_binding(config),
            allowed_foreign_origins=frozenset(guard.origins),
            cancelled=lambda: state["cancelled"],
            capture=lambda value: captured.append(copy.deepcopy(value)),
        )
        assert proof["error"] and events == [] and captured == [proof]


def test_expiry_is_checked_against_fact_capture_times(valid_proof):
    config, raw = valid_proof
    proof = copy.deepcopy(raw)
    expiry = datetime.fromisoformat(proof["facts"][4]["captured_at"])
    config = config.model_copy(
        update={
            "identities": (
                config.identities[0].model_copy(update={"expires_at": expiry}),
                config.identities[1],
            )
        }
    )
    binding = cors_configuration_binding(config)
    proof["configuration_binding"] = binding
    assert (
        evaluate_cors_proof(
            config.cors_recipes[0], config.identities, proof, configuration_binding=binding
        )[0]
        == "inconclusive"
    )
