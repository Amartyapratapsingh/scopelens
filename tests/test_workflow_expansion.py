from __future__ import annotations

import threading
from contextlib import contextmanager
from http.server import ThreadingHTTPServer

import httpx
import pytest
from labs.expansion_workflows.app import CANARY, MARKER, handler
from pydantic import SecretStr
from tests.test_identity_expansion import capture, profiles

from scopelens.checks.engine import validate_outcome
from scopelens.domain.identity import IdentityRequest
from scopelens.domain.workflow import ReadProbeRecipe, StateAssertion, WorkflowRecipe
from scopelens.identities.sessions import IdentitySessions
from scopelens.workflows.assessment import as_control_outcome, run_read_probe, run_workflow
from scopelens.workflows.cleanup import SQLiteCleanupJournal


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


def session_factory(base):
    return IdentitySessions(
        profiles(base),
        lambda _: SecretStr("synthetic-password"),
        lambda _: httpx.Client(timeout=2, trust_env=False),
    )


def write_recipe(base, family):
    return WorkflowRecipe(
        id="write-test",
        family=family,
        resource_id="seed-a",
        action_grant_id="fixture-write-grant",
        authority="lab",
        disposable=True,
        synchronous_write=True,
        actor_identity="b",
        owner_identity="a",
        readback=IdentityRequest(url=base + "/record"),
        seed=StateAssertion(pointer="/marker", value=MARKER),
        before=StateAssertion(
            pointer="/privileged" if family == "mass_assignment" else "/status",
            value=False if family == "mass_assignment" else "draft",
        ),
        forbidden_after=StateAssertion(
            pointer="/privileged" if family == "mass_assignment" else "/status",
            value=True if family == "mass_assignment" else "approved",
        ),
        mutation=IdentityRequest(
            method="POST",
            url=base + ("/update" if family == "mass_assignment" else "/approve"),
            json_body={"privileged": True},
        ),
        cleanup=IdentityRequest(method="POST", url=base + "/reset"),
        cleanup_identity="a",
    )


def read_recipe(base, family):
    common = dict(
        id="read-test",
        family=family,
        action_grant_id="fixture-read-grant",
        authority="lab",
        actor_identity="b",
        owner_identity="a",
        synthetic_resource="seed-a",
    )
    denied = StateAssertion(pointer="/error", value="forbidden")
    if family == "graphql_authorization":
        request = IdentityRequest(
            method="POST",
            url=base + "/graphql",
            json_body={
                "operationName": "PrivateObject",
                "query": 'query PrivateObject { object(id: "seed-a") { marker } }',
            },
        )
        return ReadProbeRecipe(
            **common,
            baseline=request,
            probe=request,
            negative_control=IdentityRequest(
                method="POST", url=base + "/graphql", json_body={"operationName": "AbsentObject"}
            ),
            marker=StateAssertion(pointer="/data/object/marker", value=MARKER),
            denied=denied,
        )
    if family == "private_cache":
        return ReadProbeRecipe(
            **common,
            baseline=IdentityRequest(url=base + "/cache"),
            probe=IdentityRequest(url=base + "/cache"),
            negative_control=IdentityRequest(url=base + "/cache?variant=fresh"),
            marker=StateAssertion(pointer="/marker", value=MARKER),
            denied=denied,
        )
    if family == "path_traversal":
        return ReadProbeRecipe(
            **common,
            baseline=IdentityRequest(url=base + "/canary-baseline"),
            probe=IdentityRequest(url=base + "/file?path=../canary.txt"),
            negative_control=IdentityRequest(url=base + "/file?path=canary.txt"),
            marker=StateAssertion(pointer="/body", value=CANARY),
            denied=denied,
        )
    return ReadProbeRecipe(
        **common,
        baseline=IdentityRequest(url=base + "/render?value=17*23"),
        probe=IdentityRequest(url=base + "/render?value={{17*23}}"),
        negative_control=IdentityRequest(url=base + "/render?value={{17*24}}"),
        marker=StateAssertion(pointer="/result", value="391"),
        denied=StateAssertion(pointer="/result", value="{{17*23}}"),
    )


@pytest.mark.parametrize("family", ["mass_assignment", "workflow_authorization"])
@pytest.mark.parametrize("vulnerable", [False, True])
def test_real_write_readback_cleanup(tmp_path, family, vulnerable):
    journal = SQLiteCleanupJournal(tmp_path / "cleanup.sqlite")
    with (
        lab(vulnerable=vulnerable) as base,
        session_factory(base) as sessions,
        session_factory(base) as cleanup,
    ):
        recipe = write_recipe(base, family)
        result = run_workflow(recipe, sessions, cleanup, journal, capture([]), admit=lambda _: True)
        assert result.state == ("confirmed" if vulnerable else "pass")
        assert result.cleanup_state == "clean"
        assert journal.state(recipe.id, recipe.resource_id) == "clean"
        validate_outcome(as_control_outcome(result, recipe))


@pytest.mark.parametrize(
    "family", ["graphql_authorization", "private_cache", "path_traversal", "template_injection"]
)
@pytest.mark.parametrize("vulnerable", [False, True])
def test_real_read_packs(family, vulnerable):
    with lab(vulnerable=vulnerable) as base, session_factory(base) as sessions:
        recipe = read_recipe(base, family)
        result = run_read_probe(recipe, sessions, capture([]), admit=lambda _: True)
        assert result.state == ("confirmed" if vulnerable else "pass")
        validate_outcome(as_control_outcome(result, recipe))


def test_failed_cleanup_suppresses_new_mutation_after_restart(tmp_path):
    path = tmp_path / "cleanup.sqlite"
    with (
        lab(vulnerable=True, cleanup_fails=True) as base,
        session_factory(base) as sessions,
        session_factory(base) as cleanup,
    ):
        recipe = write_recipe(base, "mass_assignment")
        first = run_workflow(
            recipe, sessions, cleanup, SQLiteCleanupJournal(path), capture([]), admit=lambda _: True
        )
        assert first.state == "confirmed" and first.cleanup_state == "cleanup_failed"
        # Restore fixture baseline manually as a test setup operation; journal still blocks
        # a repeat even if some external action restored state without recorded proof.
        recipe = recipe.model_copy(
            update={
                "before": StateAssertion(pointer="/privileged", value=True),
                "forbidden_after": StateAssertion(pointer="/privileged", value=False),
            }
        )
        second = run_workflow(
            recipe, sessions, cleanup, SQLiteCleanupJournal(path), capture([]), admit=lambda _: True
        )
        assert second.state == "blocked"
        assert "suppressed" in second.reason
        assert not any(o["kind"] == "mutation" for o in second.observations)


def test_cancellation_after_mutation_still_uses_cleanup_channel(tmp_path):
    with (
        lab(vulnerable=True) as base,
        session_factory(base) as sessions,
        session_factory(base) as cleanup,
    ):
        recipe = write_recipe(base, "mass_assignment")
        records = []

        def capture_and_cancel(item):
            records.append(item)
            if item["kind"] == "mutation":
                sessions.cancelled = lambda: True
            return str(len(records))

        result = run_workflow(
            recipe,
            sessions,
            cleanup,
            SQLiteCleanupJournal(tmp_path / "journal"),
            capture_and_cancel,
            admit=lambda _: True,
        )
        assert result.state == "blocked"
        assert result.cleanup_state == "clean"
        assert any(r["kind"] == "cleanup_readback" for r in records)


def test_absent_write_grant_never_mutates(tmp_path):
    with (
        lab(vulnerable=True) as base,
        session_factory(base) as sessions,
        session_factory(base) as cleanup,
    ):
        result = run_workflow(
            write_recipe(base, "mass_assignment"),
            sessions,
            cleanup,
            SQLiteCleanupJournal(tmp_path / "journal"),
            capture([]),
            admit=lambda _: False,
        )
        assert result.state == "blocked" and result.cleanup_state == "not_needed"
        assert result.observations == ()


def test_journal_duplicate_claim_is_durable(tmp_path):
    path = tmp_path / "journal"
    assert SQLiteCleanupJournal(path).claim("r", "o")
    assert not SQLiteCleanupJournal(path).claim("r", "o")


def test_journal_prevents_different_recipe_mutating_same_resource(tmp_path):
    journal = SQLiteCleanupJournal(tmp_path / "journal")
    assert journal.claim("recipe-a", "object-a")
    assert not journal.claim("recipe-b", "object-a")
    journal.mark("recipe-a", "object-a", "clean")
    assert journal.claim("recipe-b", "object-a")


def test_cleanup_rpc_loss_preserves_partial_findings(tmp_path):
    class RevokedJournal(SQLiteCleanupJournal):
        def mark(self, recipe_id, resource_id, state):
            if state in {"clean", "cleanup_failed"}:
                raise RuntimeError("revoked cleanup capability")
            return super().mark(recipe_id, resource_id, state)

    with (
        lab(vulnerable=True) as base,
        session_factory(base) as sessions,
        session_factory(base) as cleanup,
    ):
        recipe = write_recipe(base, "mass_assignment")
        result = run_workflow(
            recipe,
            sessions,
            cleanup,
            RevokedJournal(tmp_path / "journal"),
            capture([]),
            admit=lambda _: True,
        )
        assert result.state == "confirmed"
        assert result.cleanup_state == "cleanup_failed"
        assert result.evidence_refs
        assert (
            SQLiteCleanupJournal(tmp_path / "journal").state(recipe.id, recipe.resource_id)
            == "mutation_sent"
        )


def test_recovery_cleans_without_replaying_mutation(tmp_path):
    from scopelens.workflows.assessment import recover_cleanup

    journal = SQLiteCleanupJournal(tmp_path / "journal")
    with lab(vulnerable=True) as base, session_factory(base) as sessions:
        recipe = write_recipe(base, "mass_assignment")
        assert sessions.verify("b")
        assert journal.claim(recipe.id, recipe.resource_id)
        sessions.request("b", recipe.mutation)
        result = recover_cleanup(recipe, sessions, journal, capture([]), admit=lambda _: True)
        assert result.state == "inconclusive"
        assert result.cleanup_state == "clean"
        assert not any(o["kind"] == "mutation" for o in result.observations)
        assert journal.state(recipe.id, recipe.resource_id) == "clean"


def test_out_of_order_proof_never_confirms(tmp_path):
    from scopelens.workflows.assessment import evaluate_mutation_proof, evaluate_read_proof

    with (
        lab(vulnerable=True) as base,
        session_factory(base) as sessions,
        session_factory(base) as cleanup,
    ):
        write = write_recipe(base, "mass_assignment")
        result = run_workflow(
            write,
            sessions,
            cleanup,
            SQLiteCleanupJournal(tmp_path / "journal"),
            capture([]),
            admit=lambda _: True,
        )
        assert result.state == "confirmed"
        assert (
            evaluate_mutation_proof(write, tuple(reversed(result.observations)))[0]
            == "inconclusive"
        )
        read = read_recipe(base, "template_injection")
        observed = run_read_probe(read, sessions, capture([]), admit=lambda _: True)
        assert observed.state == "confirmed"
        assert (
            evaluate_read_proof(read, tuple(reversed(observed.observations)))[0] == "inconclusive"
        )
