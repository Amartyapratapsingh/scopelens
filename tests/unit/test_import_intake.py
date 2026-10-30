"""Offline imports stay metadata until an operator freezes a reviewed baseline/policy."""

import json
import uuid
from types import SimpleNamespace

import pytest

from scopelens.discovery.intake import ImportEnvelope, decode_envelope, normalize_import
from scopelens.domain.assessment import ActionPolicy, DiscoveryCatalogue, RelatedOriginGrant
from scopelens.domain.enums import ProfileName
from scopelens.domain.expansion import AssessmentConfiguration, CatalogueImport
from scopelens.expansion.integration import (
    freeze_revision,
    prepare_catalogue,
    prior_capture_plan_id,
)

ORIGIN = "https://owned.invalid"
SCOPE = uuid.uuid4()


def imported(kind="har", origin=ORIGIN):
    if kind == "har":
        document = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": origin + "/unlisted?query=private-query",
                            "method": "POST",
                            "role_id": "attacker-selected",
                            "headers": [{"name": "Authorization", "value": "Bearer private-auth"}],
                            "cookies": [{"name": "sid", "value": "private-cookie"}],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps(
                                    {"query": "private-body", "token": "private-token"}
                                ),
                            },
                        },
                        "response": {"content": {"text": "private-response"}},
                    }
                ]
            }
        }
    else:
        document = {
            "openapi": "3.0.0",
            "servers": [{"url": origin}],
            "paths": {
                "/unlisted": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "query",
                                "schema": {"type": "string"},
                                "example": "private-example",
                            }
                        ]
                    }
                }
            },
        }
    return normalize_import(
        ImportEnvelope(scope_version_id=SCOPE, kind=kind, document=document), ORIGIN
    )


@pytest.mark.parametrize("kind", ["har", "openapi"])
def test_metadata_discards_samples_and_cannot_self_authorize(kind):
    item = imported(kind)
    assert "private-" not in item.model_dump_json()
    assert all(
        t.role_id == "anonymous" and not t.baseline_complete for t in item.catalogue.templates
    )
    config = AssessmentConfiguration(scope_version_id=SCOPE, imports=(item,))
    cat = prepare_catalogue(ORIGIN, [], config)
    _, full, _, _ = freeze_revision({}, cat, config, scope=scope(), run_id="r1")
    assert full.tasks and all(t.state == "blocked" for t in full.tasks)
    assert len(item.source_sha256) == len(item.catalogue_sha256) == 64
    assert CatalogueImport.model_validate_json(item.model_dump_json()) == item


def scope():
    return SimpleNamespace(id=SCOPE, allowed_check_profile=ProfileName.EXTERNAL_ACTIVE_V2)


def test_explicit_template_still_needs_policy_and_unresolved_refs_stay_blocked():
    item = imported("openapi")
    template = item.catalogue.templates[0].model_copy(
        update={
            "baseline_complete": True,
            "inputs": tuple(
                i.model_copy(update={"baseline_value": "ordinary"})
                for i in item.catalogue.templates[0].inputs
            ),
        }
    )
    config = AssessmentConfiguration(scope_version_id=SCOPE, imports=(item,), templates=(template,))
    assert not prepare_catalogue(ORIGIN, [], config).templates[0].baseline_complete
    policy = ActionPolicy(
        template_id=template.id,
        role_id="anonymous",
        classification="read_only",
        approval_ref="operator-reviewed",
    )
    config = config.model_copy(update={"policies": (policy,)})
    cat = prepare_catalogue(ORIGIN, [], config)
    assert cat.templates[0].baseline_complete
    _, plan, _, _ = freeze_revision({}, cat, config, scope=scope(), run_id="r1")
    assert any(t.state == "ready" for t in plan.tasks)


@pytest.mark.parametrize("purpose", [None, "resource_only"])
def test_foreign_import_retained_without_authority(purpose):
    item = imported("openapi", "https://third.invalid")
    grants = (
        ()
        if purpose is None
        else (
            RelatedOriginGrant(
                origin="https://third.invalid",
                purpose=purpose,
                grant_id="owned-resource",
                scope_version_id=str(uuid.uuid4()),
            ),
        )
    )
    config = AssessmentConfiguration(
        scope_version_id=SCOPE, imports=(item,), related_origins=grants
    )
    cat = prepare_catalogue(ORIGIN, [], config)
    assert cat.templates[0].authority == (purpose or "unapproved")
    assert cat.gaps


@pytest.mark.parametrize("change", ["scope", "role", "hash", "sample"])
def test_import_binding_cannot_be_changed(change):
    item = imported()
    raw = item.model_dump(mode="json")
    if change == "scope":
        raw["scope_version_id"] = str(uuid.uuid4())
    elif change == "role":
        raw["role_id"] = "other"
    elif change == "hash":
        raw["catalogue_sha256"] = "0" * 64
    else:
        raw["catalogue"]["templates"][0]["inputs"][0]["baseline_value"] = "private-sample"
    with pytest.raises(ValueError):
        AssessmentConfiguration(scope_version_id=SCOPE, imports=(raw,))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"document":',
        b"{" + b" " * 1048576 + b"}",
        json.dumps({"a": [0] * 2001}).encode(),
        b'{"x": NaN}',
    ],
)
def test_structural_and_byte_bounds(raw):
    with pytest.raises(ValueError):
        decode_envelope(raw)


def test_depth_bound():
    node = {}
    for _ in range(30):
        node = {"nested": node}
    with pytest.raises(ValueError):
        decode_envelope(json.dumps(node).encode())


def test_revision_preserves_denominator_and_claims_without_replay():
    item = imported("openapi")
    template = item.catalogue.templates[0].model_copy(update={"baseline_complete": True})
    config = AssessmentConfiguration(scope_version_id=SCOPE, templates=(template,))
    cat = prepare_catalogue(ORIGIN, [], config)
    saved, first, executable, _ = freeze_revision({}, cat, config, scope=scope(), run_id="r1")
    assert all(t.state == "ready" for t in executable.tasks)
    other = template.model_copy(
        update={
            "id": "second-template",
            "path": "/fresh",
            "route_template": "/fresh",
            "authority": "primary",
        }
    )
    cat2 = cat.model_copy(update={"templates": (*cat.templates, other)})
    saved2, second, execute2, _ = freeze_revision(saved, cat2, config, scope=scope(), run_id="r2")
    assert second.denominator == first.denominator * 2
    assert second.previous_id == first.id and second.revision == 2
    old_ids = {t.id for t in first.tasks}
    assert all(t.state == "blocked" for t in execute2.tasks if t.id in old_ids)
    assert all(t.state == "ready" for t in execute2.tasks if t.id not in old_ids)
    assert len(saved2["assessment_plan_revisions"]) == 2
    for task in first.tasks:
        assert prior_capture_plan_id(saved2, task, cat.templates[0], first.id) == first.id
        assert prior_capture_plan_id(saved2, task, other, first.id) is None
        assert prior_capture_plan_id(saved2, task, template, "invented") is None
    # Even an empty later observation cannot shrink the historical denominator.
    carried = prepare_catalogue(ORIGIN, [], AssessmentConfiguration(scope_version_id=SCOPE), cat2)
    assert {t.id for t in carried.templates} == {template.id, other.id}
    _, third, execute3, _ = freeze_revision(saved2, carried, config, scope=scope(), run_id="r3")
    assert third.denominator == second.denominator
    assert all(t.state == "blocked" for t in execute3.tasks)


def test_prior_legacy_execution_is_not_replayed():
    config = AssessmentConfiguration(scope_version_id=SCOPE)
    cat = DiscoveryCatalogue(origin=ORIGIN)
    saved, first, _, _ = freeze_revision({}, cat, config, scope=scope(), run_id="r1")
    saved.pop("assessment_execution_claims")
    saved.pop("assessment_plan_revisions")
    revised, second, _, _ = freeze_revision(saved, cat, config, scope=scope(), run_id="r2")
    assert [r["plan"]["id"] for r in revised["assessment_plan_revisions"]] == [first.id, second.id]


def test_worker_exposure_discovery_ignores_import_only_source_maps(monkeypatch, capsys):
    from contextlib import nullcontext

    from scopelens.checks.packs.exposure import ExposurePackResult
    from scopelens.domain.assessment import AssessmentPlanVersion, RequestTemplate
    from scopelens.expansion import worker

    base = RequestTemplate(
        id="observed",
        origin=ORIGIN,
        path="/observed.map",
        route_template="/observed.map",
        method="GET",
    )
    foreign = base.model_copy(
        update={"id": "foreign", "origin": "https://foreign.invalid", "authority": "resource_only"}
    )
    imported_only = base.model_copy(
        update={"id": "import-only", "path": "/private.map", "baseline_complete": False}
    )
    cat = DiscoveryCatalogue(origin=ORIGIN, templates=(base, imported_only, foreign))
    plan = AssessmentPlanVersion(
        id="empty",
        revision=1,
        scope_version=str(SCOPE),
        catalogue_hash="test",
        tasks=(),
        denominator=0,
    )
    config = AssessmentConfiguration(scope_version_id=SCOPE)
    monkeypatch.setenv(
        "SCOPELENS_EXPANSION_INPUT",
        json.dumps(
            {
                "catalogue": cat.model_dump(mode="json"),
                "plan": plan.model_dump(mode="json"),
                "configuration": config.model_dump(mode="json"),
            }
        ),
    )
    monkeypatch.setenv("SCOPELENS_SCANNER_TOOLS_ENABLED", "false")
    monkeypatch.setattr(worker, "config_from_env", lambda: None)
    monkeypatch.setattr(
        worker, "Crawler", lambda _: SimpleNamespace(_http=lambda: nullcontext(object()))
    )
    monkeypatch.setattr(worker, "AssessmentControlClient", lambda _: None)
    monkeypatch.setattr(worker.signal, "signal", lambda *_: None)
    seen = []

    def collect(client, origin, **kwargs):
        seen.extend(kwargs["discovered_urls"])
        return ExposurePackResult()

    monkeypatch.setattr(worker, "collect_exposure_pack", collect)
    worker.main()
    assert seen == [ORIGIN + "/observed.map"]


def test_stateful_recipes_reserved_before_dispatch_are_not_replayed():
    from scopelens.domain.identity import IdentityProfile, SessionPolicy
    from scopelens.domain.workflow import WorkflowRecipe

    identity = IdentityProfile.model_validate(
        {
            "id": "A",
            "role": "owner",
            "probe": {"request": {"url": ORIGIN + "/identity"}, "expected_identity": "A"},
        }
    )
    recipe = WorkflowRecipe.model_validate(
        {
            "id": "flow",
            "family": "mass_assignment",
            "resource_id": "owned-record",
            "action_grant_id": "owned-only",
            "authority": "lab",
            "disposable": True,
            "synchronous_write": True,
            "actor_identity": "A",
            "owner_identity": "A",
            "cleanup_identity": "A",
            "readback": {"url": ORIGIN + "/record"},
            "seed": {"pointer": "/seed", "value": "owned"},
            "before": {"pointer": "/content", "value": ""},
            "forbidden_after": {"pointer": "/content", "value": "changed"},
            "mutation": {"method": "POST", "url": ORIGIN + "/mutate"},
            "cleanup": {"method": "POST", "url": ORIGIN + "/restore"},
        }
    )
    session = SessionPolicy(
        identity_id="A", cookie_name="sid", logout={"method": "POST", "url": ORIGIN + "/logout"}
    )
    config = AssessmentConfiguration(
        scope_version_id=SCOPE,
        identities=(identity,),
        workflows=(recipe,),
        session_policies=(session,),
    )
    cat = DiscoveryCatalogue(origin=ORIGIN)
    frozen, _, _, first_config = freeze_revision(
        {}, cat, config, scope=scope(), run_id="unknown-outcome"
    )
    assert first_config.workflows and first_config.session_policies
    assert frozen["assessment_execution_claims"]
    _, _, _, repeated = freeze_revision(frozen, cat, config, scope=scope(), run_id="retry")
    assert not repeated.workflows and not repeated.session_policies
    assert repeated.identities == config.identities


def test_openapi_path_examples_and_external_refs_are_not_retained_or_loaded():
    document = {
        "openapi": "3.0.0",
        "paths": {
            "/records/{id}": {
                "get": {
                    "parameters": [
                        {
                            "in": "path",
                            "name": "id",
                            "required": True,
                            "example": "private-record-key",
                        }
                    ]
                }
            },
            "/external": {"$ref": "https://never-fetch.invalid/private-reference"},
        },
    }
    item = normalize_import(
        ImportEnvelope(scope_version_id=SCOPE, kind="openapi", document=document), ORIGIN
    )
    assert item.catalogue.templates[0].path == "/records/{id}"
    assert "private-" not in item.model_dump_json()
    assert any(g.reason == "external_reference_not_loaded" for g in item.catalogue.gaps)


def test_normalized_browser_intent_is_merged_without_upgrading_imports():
    item = imported("openapi")
    template = item.catalogue.templates[0].model_copy(
        update={"baseline_complete": True, "authority": "scan"}
    )
    captures = [
        {
            "kind": "browser_request_template",
            "data": {"template": template.model_dump(mode="json"), "state": "observed_intent"},
        }
    ]
    config = AssessmentConfiguration(scope_version_id=SCOPE)
    observed = prepare_catalogue(ORIGIN, captures, config)
    assert observed.templates[0].authority == "primary"
    assert observed.templates[0].baseline_complete
    protected = prepare_catalogue(ORIGIN, captures, config.model_copy(update={"imports": (item,)}))
    assert not protected.templates[0].baseline_complete


def test_small_recursive_schema_cannot_expand_exponentially():
    recursive = {
        "type": "object",
        "properties": {str(n): {"$ref": "#/components/schemas/recursive"} for n in range(100)},
    }
    document = {
        "openapi": "3.0.0",
        "paths": {
            "/record": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/recursive"}
                            }
                        }
                    }
                }
            }
        },
        "components": {"schemas": {"recursive": recursive}},
    }
    with pytest.raises(ValueError, match="recursive"):
        normalize_import(
            ImportEnvelope(scope_version_id=SCOPE, kind="openapi", document=document), ORIGIN
        )
