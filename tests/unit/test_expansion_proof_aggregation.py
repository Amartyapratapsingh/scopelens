"""Exercise the production collector and report proof path against HTTP fixtures."""

from copy import deepcopy
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from pydantic import SecretStr, ValidationError
from tests.test_identity_expansion import lab as identity_lab
from tests.test_identity_expansion import matrix, profiles
from tests.test_workflow_expansion import lab as workflow_lab
from tests.test_workflow_expansion import read_recipe, write_recipe

from scopelens.checks.engine import validate_outcome
from scopelens.domain.enums import ControlOutcome as State
from scopelens.domain.enums import ProfileName
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import IdentityRequest, SessionPolicy
from scopelens.domain.registry import load_registry
from scopelens.expansion.analysis import expansion_controls
from scopelens.expansion.identity_collector import collect_identity_assessments
from scopelens.workflows.cleanup import SQLiteCleanupJournal


def collect(config, tmp_path):
    class Control:
        secret = staticmethod(lambda ref: SecretStr("synthetic-password"))

        def __init__(self):
            self.journal = SQLiteCleanupJournal(tmp_path / "cleanup.sqlite")

        def claim(self, *args):
            return self.journal.claim(*args)

        def mark(self, *args):
            return self.journal.mark(*args)

    artifacts = []

    def emit(kind, data):
        artifacts.append(
            {
                "kind": kind,
                "data": data,
                "source": "expansion",
                "run_id": "fixture-run",
                "evidence_ref": f"stored-{len(artifacts)}",
            }
        )

    collect_identity_assessments(
        config,
        Control(),
        lambda role: httpx.Client(timeout=2, trust_env=False),
        emit,
        cancelled=lambda: False,
    )
    return artifacts


def evaluate(config, artifacts, *, trusted_refs=None, cleanup_states=None):
    controls = expansion_controls(
        artifacts,
        {"expansion_config": config.model_dump(mode="json")},
        load_registry(Path("checks_registry")),
        trusted_refs=set(a["evidence_ref"] for a in artifacts)
        if trusted_refs is None
        else trusted_refs,
        cleanup_states=cleanup_states,
    )
    outcomes = {c.check_id: c.evaluate(None) for c in controls}
    for outcome in outcomes.values():
        validate_outcome(outcome)
        if outcome.proof:
            assert "pending-intake" not in outcome.proof.evidence_refs
    return outcomes


@pytest.mark.parametrize("family", ["object", "function", "tenant", "property"])
@pytest.mark.parametrize("vulnerable", [False, True])
def test_access_evidence_to_outcome(tmp_path, family, vulnerable):
    with identity_lab(vulnerable=vulnerable) as base:
        config = AssessmentConfiguration(
            scope_version_id=uuid4(),
            identities=profiles(base),
            permission_matrix=matrix(base, family),
        )
        artifacts = collect(config, tmp_path)
    outcome = evaluate(config, artifacts)[f"SL-C09-{family.upper()}-01"]
    assert outcome.status is (State.CONFIRMED_ISSUE if vulnerable else State.PASS)
    assert outcome.is_fully_assessed
    assert outcome.proof.evidence_refs


@pytest.mark.parametrize(
    "tamper",
    [
        "untrusted",
        "other_rule",
        "other_run",
        "duplicate_ref",
        "missing_post_probe",
        "worker_verdict",
    ],
)
def test_bound_access_cannot_use_unrelated_or_missing_proof(tmp_path, tamper):
    with identity_lab(vulnerable=True) as base:
        config = AssessmentConfiguration(
            scope_version_id=uuid4(), identities=profiles(base), permission_matrix=matrix(base)
        )
        artifacts = collect(config, tmp_path)
    trusted = {a["evidence_ref"] for a in artifacts}
    if tamper == "untrusted":
        trusted.clear()
    elif tamper == "other_rule":
        for a in artifacts:
            a["data"]["proof_id"] = "different-rule"
    elif tamper == "other_run":
        artifacts[-1]["run_id"] = "another-attempt"
    elif tamper == "duplicate_ref":
        for a in artifacts:
            a["evidence_ref"] = artifacts[0]["evidence_ref"]
    elif tamper == "missing_post_probe":
        artifacts.pop()
    else:
        artifacts = [a for a in artifacts if a["kind"] != "identity_response"]
        for a in artifacts:
            a["data"]["state"] = "confirmed"
    outcome = evaluate(config, artifacts, trusted_refs=trusted)["SL-C09-OBJECT-01"]
    assert outcome.status is State.INCONCLUSIVE
    assert not outcome.is_fully_assessed


def test_missing_rule_keeps_findings_and_incomplete_coverage(tmp_path):
    with identity_lab(vulnerable=True) as base:
        policy = matrix(base)
        config = AssessmentConfiguration(
            scope_version_id=uuid4(), identities=profiles(base), permission_matrix=policy
        )
        artifacts = collect(config, tmp_path)
    second = policy.rules[0].model_copy(update={"id": "unreached-rule"})
    config = config.model_copy(
        update={"permission_matrix": policy.model_copy(update={"rules": (*policy.rules, second)})}
    )
    outcome = evaluate(config, artifacts)["SL-C09-OBJECT-01"]
    assert outcome.status is State.CONFIRMED_ISSUE
    assert outcome.required_instances == ("rule-a", "unreached-rule")
    assert outcome.completed_instances == ("rule-a",)
    assert not outcome.is_fully_assessed


@pytest.mark.parametrize("vulnerable", [False, True])
def test_lifecycle_proof_uses_records_not_worker_verdict(tmp_path, vulnerable):
    with identity_lab(vulnerable=vulnerable) as base:
        config = AssessmentConfiguration(
            scope_version_id=uuid4(),
            identities=profiles(base),
            session_policies=(
                SessionPolicy(
                    identity_id="a",
                    cookie_name="sid",
                    logout=IdentityRequest(method="POST", url=base + "/logout"),
                ),
            ),
        )
        artifacts = collect(config, tmp_path)
    for a in artifacts:
        if a["kind"] == "session_observation":
            a["data"]["state"] = "pass" if vulnerable else "confirmed"
    outcome = evaluate(config, artifacts)["SL-C08-SESSION-01"]
    assert outcome.status is (State.CONFIRMED_ISSUE if vulnerable else State.PASS)
    assert outcome.is_fully_assessed


@pytest.mark.parametrize(
    "family,check",
    [("mass_assignment", "SL-C09-MASS-01"), ("workflow_authorization", "SL-C11-WORKFLOW-01")],
)
@pytest.mark.parametrize("vulnerable", [False, True])
def test_workflow_independent_proof_and_durable_cleanup(tmp_path, family, check, vulnerable):
    with workflow_lab(vulnerable=vulnerable) as base:
        recipe = write_recipe(base, family)
        config = AssessmentConfiguration(
            scope_version_id=uuid4(), identities=profiles(base), workflows=(recipe,)
        )
        artifacts = collect(config, tmp_path)
    outcome = evaluate(config, artifacts, cleanup_states={recipe.id: "clean"})[check]
    assert outcome.status is (State.CONFIRMED_ISSUE if vulnerable else State.PASS)
    assert outcome.is_fully_assessed
    pending = evaluate(config, artifacts, cleanup_states={recipe.id: "mutation_sent"})[check]
    assert not pending.is_fully_assessed
    assert pending.status is (State.CONFIRMED_ISSUE if vulnerable else State.INCONCLUSIVE)
    forged = deepcopy(artifacts)
    for a in forged:
        if a["kind"] == "identity_observation" and a["data"].get("kind") == "cleanup_readback":
            a["data"]["declared_values"] = {}
    assert not evaluate(config, forged, cleanup_states={recipe.id: "clean"})[
        check
    ].is_fully_assessed


@pytest.mark.parametrize(
    "family,check",
    [
        ("graphql_authorization", "SL-C09-GRAPHQL-01"),
        ("private_cache", "SL-C05-CACHE-01"),
        ("path_traversal", "SL-C10-TRAVERSAL-01"),
        ("template_injection", "SL-C03-TEMPLATE-01"),
    ],
)
@pytest.mark.parametrize("vulnerable", [False, True])
def test_read_recipe_proof_pipeline(tmp_path, family, check, vulnerable):
    with workflow_lab(vulnerable=vulnerable) as base:
        recipe = read_recipe(base, family)
        config = AssessmentConfiguration(
            scope_version_id=uuid4(), identities=profiles(base), read_probes=(recipe,)
        )
        artifacts = collect(config, tmp_path)
    outcome = evaluate(config, artifacts)[check]
    assert outcome.status is (State.CONFIRMED_ISSUE if vulnerable else State.PASS)
    assert outcome.is_fully_assessed
    # A worker result's nested observations are not a substitute for stored captures.
    stripped = [a for a in artifacts if a["kind"] != "identity_observation"]
    assert evaluate(config, stripped)[check].status is State.INCONCLUSIVE


def test_stateful_registry_includes_identity_controls():
    registry = load_registry(Path("checks_registry"))
    authenticated = {e.id for e in registry.for_profile(ProfileName.AUTHENTICATED_API_V1)}
    stateful = {e.id for e in registry.for_profile(ProfileName.STAGING_STATEFUL_V1)}
    assert authenticated <= stateful


def test_duplicate_session_policy_rejected():
    policy = SessionPolicy(identity_id="a", cookie_name="sid")
    with pytest.raises(ValidationError, match="duplicate session"):
        AssessmentConfiguration(
            scope_version_id=uuid4(),
            identities=profiles("http://lab.invalid"),
            session_policies=(policy, policy),
        )


@pytest.mark.parametrize(
    "source,kind,accepted",
    [
        ("adaptive", "expanded_active_probe", True),
        ("adaptive", "exposure_pack", True),
        ("adaptive", "identity_response", False),
        ("script", "expanded_active_probe", False),
        ("expansion", "identity_response", True),
    ],
)
def test_adaptive_provenance_does_not_grant_identity_authority(source, kind, accepted):
    from scopelens.expansion.proof_aggregation import admitted_artifacts

    artifact = {
        "source": source,
        "kind": kind,
        "run_id": "run-1",
        "evidence_ref": "stored-1",
        "data": {},
    }
    assert bool(admitted_artifacts([artifact], {"stored-1"})) is accepted
    assert not admitted_artifacts([artifact], set())
