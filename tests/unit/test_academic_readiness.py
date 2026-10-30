"""Policy declarations and admission claims never become execution or security proof."""

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from labs.academic_workflows.scenarios import access_matrix, identities, write_recipe

from scopelens.academic.evidence import load_captures
from scopelens.academic.readiness import project_readiness, validate_configuration
from scopelens.domain.assessment import stable_id
from scopelens.domain.capabilities import canonical_sha256
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import SessionPolicy
from scopelens.domain.registry import load_registry

ORIGIN = "http://127.0.0.1:8080"
NOW = datetime(2026, 9, 29, tzinfo=UTC)


def inputs(**updates):
    config = AssessmentConfiguration(
        scope_version_id=uuid.uuid4(),
        identities=identities(ORIGIN),
        permission_matrix=access_matrix(ORIGIN),
        workflows=(write_recipe(ORIGIN, "marks"),),
        **updates,
    )
    digest = canonical_sha256(config.model_dump(mode="json"))
    ident = uuid.uuid4()
    return dict(
        configuration_id=ident,
        configuration_hash=digest,
        config=config,
        profile="staging-stateful-v1",
        now=NOW,
    )


def scan_inputs(args):
    return {
        **args,
        "scan_id": uuid.uuid4(),
        "frozen": {
            "configuration_id": str(args["configuration_id"]),
            "configuration_hash": args["configuration_hash"],
            "expansion_config": args["config"].model_dump(mode="json"),
            "registry": load_registry(Path("checks_registry")).model_dump(mode="json"),
        },
    }


def capture(kind, proof_type, proof_id, data, run="one"):
    return dict(
        kind=kind,
        source="expansion",
        run_id=run,
        evidence_ref=str(uuid.uuid4()),
        data={"proof_type": proof_type, "proof_id": proof_id, **data},
    )


def response(proof_id, ident, request, document, proof_type="access"):
    return capture(
        "identity_response",
        proof_type,
        proof_id,
        dict(
            identity_id=ident, method=request.method, url=request.url, status=200, document=document
        ),
    )


def access_captures(config, *, forbidden=True):
    matrix = config.permission_matrix
    rule = next(r for r in matrix.rules if not r.allowed)
    obj = matrix.objects[0]
    profiles = {p.id: p for p in config.identities}
    out = []

    def probe(ident):
        p = profiles[ident]
        out.append(
            response(rule.id, ident, p.probe.request, {"identity": p.probe.expected_identity})
        )

    probe(obj.owner_identity)
    out.append(response(rule.id, obj.owner_identity, obj.request, {"marker": obj.marker}))
    probe(obj.owner_identity)
    for _ in range(2):
        probe(rule.identity_id)
        out.append(
            response(
                rule.id,
                rule.identity_id,
                obj.request,
                {"marker": obj.marker} if forbidden else {"error": "forbidden"},
            )
        )
        probe(rule.identity_id)
    return out


def test_configuration_and_admission_remain_unexecuted_and_private():
    args = inputs()
    config = args["config"]
    result = project_readiness(**args)
    assert result.coverage.configured == 4
    assert result.coverage.ready == 4
    assert result.coverage.executed == result.coverage.proven == 0
    assert all(a.identity_evidence == "not_observed" for a in result.actors)
    text = result.model_dump_json()
    for private in (
        "academic-lab-password",
        "student_a",
        "student_b",
        ORIGIN,
        config.permission_matrix.objects[0].marker,
        "/marks",
        "student-a-record",
    ):
        assert private not in text
    assert project_readiness(**args) == result
    scan = scan_inputs(args)
    scan["frozen"]["assessment_execution_claims"] = {
        "permission_matrix:" + stable_id(config.permission_matrix.model_dump(mode="json")): {
            "state": "admitted"
        }
    }
    result = project_readiness(**scan)
    assert result.coverage.admitted == 3
    assert result.coverage.executed == result.coverage.proven == 0
    assert all(
        c.unexecuted_reason == "admission_without_bound_capture"
        for c in result.cases
        if c.kind == "permission"
    )


@pytest.mark.parametrize("forbidden", [True, False])
def test_access_uses_repeated_bound_proof_and_preserves_allowed_controls(forbidden):
    args = scan_inputs(inputs())
    args["artifacts"] = access_captures(args["config"], forbidden=forbidden)
    result = project_readiness(**args)
    case = next(
        c for c in result.cases if c.kind == "permission" and c.expected_permission == "forbidden"
    )
    assert case.execution == "observed"
    assert case.proof == ("confirmed_issue" if forbidden else "pass")
    assert case.baseline == "verified"
    assert len(case.evidence_refs) == 9
    assert result.coverage.proven == result.coverage.fully_assessed == 1
    assert all(
        c.proof == "not_evaluated" for c in result.cases if c.expected_permission == "allowed"
    )


def test_partial_or_mixed_attempts_cannot_prove_access():
    args = scan_inputs(inputs())
    captures = access_captures(args["config"])
    args["artifacts"] = captures[:-3]
    assert project_readiness(**args).coverage.proven == 0
    captures[-1]["run_id"] = "another-attempt"
    args["artifacts"] = captures
    result = project_readiness(**args)
    assert result.coverage.proven == 0
    assert result.coverage.executed == 1


def workflow_captures(config):
    recipe = config.workflows[0]
    profiles = {p.id: p for p in config.identities}
    out = []

    def probe(ident):
        p = profiles[ident]
        out.append(
            response(
                recipe.id,
                ident,
                p.probe.request,
                {"identity": p.probe.expected_identity},
                proof_type="workflow",
            )
        )

    def observed(kind, ident, request, value):
        out.append(
            capture(
                "identity_observation",
                "workflow",
                recipe.id,
                dict(
                    kind=kind,
                    identity_id=ident,
                    url=request.url,
                    method=request.method,
                    status=200,
                    declared_values={
                        recipe.seed.pointer: recipe.seed.value,
                        recipe.before.pointer: value,
                    },
                ),
            )
        )

    probe(recipe.owner_identity)
    observed("baseline", recipe.owner_identity, recipe.readback, recipe.before.value)
    probe(recipe.actor_identity)
    observed("mutation", recipe.actor_identity, recipe.mutation, recipe.forbidden_after.value)
    for _ in range(2):
        probe(recipe.owner_identity)
        observed("readback", recipe.owner_identity, recipe.readback, recipe.forbidden_after.value)
    observed("cleanup_readback", recipe.owner_identity, recipe.readback, recipe.before.value)
    return out


def test_workflow_proof_and_restoration_are_separate_and_fence_covers_other_recipe():
    args = scan_inputs(inputs())
    recipe = args["config"].workflows[0]
    args["artifacts"] = workflow_captures(args["config"])
    result = project_readiness(**args)
    case = next(c for c in result.cases if c.kind == "workflow")
    assert case.proof == "confirmed_issue"
    assert case.execution == "observed"
    assert case.independent_readback == "proven"
    assert case.restoration == "not_proven"
    assert result.coverage.proven == 1 and result.coverage.fully_assessed == 0
    args["cleanup_rows"] = [
        {
            "scan_id": str(args["scan_id"]),
            "recipe_id": recipe.id,
            "resource_id": recipe.resource_id,
            "state": "clean",
        }
    ]
    clean = project_readiness(**args)
    assert clean.coverage.fully_assessed == 1
    assert next(c for c in clean.cases if c.kind == "workflow").restoration == "verified"
    args["cleanup_rows"] = [
        {
            "scan_id": str(uuid.uuid4()),
            "recipe_id": "other-property",
            "resource_id": recipe.resource_id,
            "state": "cleanup_failed",
        }
    ]
    fenced = project_readiness(**args)
    case = next(c for c in fenced.cases if c.kind == "workflow")
    assert case.proof == "confirmed_issue" and case.restoration == "fenced"
    assert "resource_cleanup_fenced" in case.blocked_reasons
    assert fenced.coverage.fully_assessed == 0
    assert fenced.revision != clean.revision != result.revision
    args["cleanup_states"] = {recipe.id: "clean"}
    historical = project_readiness(**args)
    case = next(c for c in historical.cases if c.kind == "workflow")
    assert case.restoration == "verified" and case.resource_fenced
    assert not case.configuration_ready
    assert historical.coverage.fully_assessed == 1


def test_identity_expiry_and_unsupported_sequence_have_explicit_reasons():
    args = inputs()
    config = args["config"]
    args["config"] = config.model_copy(
        update={
            "identities": tuple(
                p.model_copy(update={"expires_at": NOW - timedelta(seconds=1)})
                for p in config.identities
            )
        }
    )
    args["configuration_hash"] = canonical_sha256(args["config"].model_dump(mode="json"))
    result = project_readiness(**args)
    assert result.coverage.blocked == 4
    assert all("declared_identity_expired" in c.blocked_reasons for c in result.cases)
    assert next(f for f in result.features if f.code == "approval_sequence").configured_cases == 0
    assert "explicit_multistep_transition_contract_not_supported" in result.model_dump_json()


def test_session_proof_requires_independent_login_and_identity_facts():
    args = scan_inputs(
        inputs(session_policies=(SessionPolicy(identity_id="student_b", cookie_name="sid"),))
    )
    args["artifacts"] = [
        capture(
            "identity_observation",
            "session",
            "student_b",
            dict(
                kind="session_policy",
                check="rotation",
                identity_id="student_b",
                initial_probe_status=200,
                initial_identity="student_b",
                login_status=200,
                new_probe_status=200,
                new_identity="student_b",
                old_cookie_hash="a" * 64,
                new_cookie_hash="b" * 64,
            ),
        )
    ]
    result = project_readiness(**args)
    assert next(c for c in result.cases if c.kind == "session").proof == "pass"
    args["artifacts"][0]["data"]["new_identity"] = "wrong"
    assert (
        next(c for c in project_readiness(**args).cases if c.kind == "session").proof
        == "inconclusive"
    )


def test_configuration_digest_scope_and_scan_snapshot_are_checked():
    args = inputs()
    config = args["config"]
    raw = config.model_dump(mode="json")
    assert (
        validate_configuration(raw, args["configuration_hash"], config.scope_version_id) == config
    )
    with pytest.raises(ValueError):
        validate_configuration(raw, "0" * 64, config.scope_version_id)
    with pytest.raises(ValueError):
        validate_configuration(raw, args["configuration_hash"], uuid.uuid4())
    args = scan_inputs(args)
    args["frozen"]["configuration_hash"] = "0" * 64
    with pytest.raises(ValueError):
        project_readiness(**args)


def test_loader_ignores_worker_claims_and_wrong_task_scope_and_rejects_integrity():
    scan = SimpleNamespace(
        id=uuid.uuid4(),
        scope_version_id=uuid.uuid4(),
        scope_version=SimpleNamespace(content_hash="scope"),
    )
    task_id = uuid.uuid4()
    body = json.dumps(capture("identity_response", "access", "private-rule", {})).encode()
    row = SimpleNamespace(
        id=uuid.uuid4(),
        producer="reviewed_expansion_capture",
        origin="supervisor",
        scan_id=scan.id,
        scope_version_id=scan.scope_version_id,
        scope_content_hash="scope",
        run_id="one",
        task_id=task_id,
        producer_hash="p",
        truncated=False,
        redaction_state="clean",
        captured_at=datetime.now(UTC),
        content_ref="private-file",
        content_hash=hashlib.sha256(body).hexdigest(),
    )
    store = SimpleNamespace(get=lambda _: body)
    db = SimpleNamespace(get=lambda *a: SimpleNamespace(scan_id=scan.id))
    admitted = load_captures(db, scan, [row], store, 30)
    assert admitted[0]["evidence_ref"] == str(row.id)
    row.origin = "untrusted_observation"
    assert load_captures(db, scan, [row], store, 30) == []
    row.origin = "supervisor"
    row.scope_content_hash = "wrong"
    assert load_captures(db, scan, [row], store, 30) == []
    row.scope_content_hash = "scope"
    row.content_hash = "0" * 64
    with pytest.raises(ValueError, match="integrity"):
        load_captures(db, scan, [row], store, 30)
