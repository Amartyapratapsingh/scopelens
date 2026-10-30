"""Local HTTP development acceptance, not deployed provenance or customer findings."""

import json
import threading
from contextlib import contextmanager
from hashlib import sha256
from http.server import ThreadingHTTPServer

import httpx
import pytest
from labs.academic_workflows.app import handler
from labs.academic_workflows.scenarios import access_matrix, identities, write_recipe
from pydantic import SecretStr

from scopelens.checks.engine import validate_outcome
from scopelens.domain.identity import IdentityRequest
from scopelens.identities.assessment import run_access_comparisons
from scopelens.identities.sessions import IdentitySessions
from scopelens.workflows.assessment import as_control_outcome, run_workflow
from scopelens.workflows.cleanup import SQLiteCleanupJournal


@contextmanager
def academic_lab(**kwargs):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler(**kwargs))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def sessions(origin, *, password="synthetic-only"):
    return IdentitySessions(
        identities(origin),
        lambda _: SecretStr(password),
        lambda _: httpx.Client(timeout=2, trust_env=False),
    )


def capture_into(records):
    def capture(record):
        records.append(record)
        return "local-test:" + sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()

    return capture


@pytest.mark.parametrize("vulnerable", [True, False])
def test_student_object_access_and_authorized_controls(vulnerable):
    with academic_lab(vulnerable=vulnerable) as origin, sessions(origin) as clients:
        captured = []
        results = run_access_comparisons(access_matrix(origin), clients, capture_into(captured))
        by_identity = {r.identity_id: r for r in results}
        assert by_identity["student_a"].state == "pass"
        assert by_identity["staff"].state == "pass"
        assert by_identity["student_b"].state == ("confirmed" if vulnerable else "pass")
        assert all(r.authorized_baseline and r.evidence_refs for r in results)


@pytest.mark.parametrize("field", ["marks", "attendance"])
@pytest.mark.parametrize("vulnerable", [True, False])
def test_unauthorized_change_requires_independent_readback_and_restoration(
    tmp_path, field, vulnerable
):
    with (
        academic_lab(vulnerable=vulnerable) as origin,
        sessions(origin) as clients,
        sessions(origin) as cleanup,
    ):
        recipe = write_recipe(origin, field)
        journal = SQLiteCleanupJournal(tmp_path / "journal.sqlite")
        evidence = []
        result = run_workflow(
            recipe, clients, cleanup, journal, capture_into(evidence), admit=lambda _: True
        )
        assert result.state == ("confirmed" if vulnerable else "pass")
        assert result.cleanup_state == "clean"
        assert len([x for x in evidence if x["kind"] == "readback"]) == 2
        assert [x["identity_id"] for x in evidence if x["kind"] == "readback"] == ["staff", "staff"]
        assert journal.state(recipe.id, recipe.resource_id) == "clean"
        restored = cleanup.request("staff", recipe.readback).json()
        assert restored["marks"] == 61 and restored["attendance"] == 72
        validate_outcome(as_control_outcome(result, recipe))


def test_cleanup_failure_retains_proof_and_blocks_other_property(tmp_path):
    with (
        academic_lab(vulnerable=True, cleanup_fails=True) as origin,
        sessions(origin) as clients,
        sessions(origin) as cleanup,
    ):
        journal = SQLiteCleanupJournal(tmp_path / "journal.sqlite")
        evidence = []
        marks = run_workflow(
            write_recipe(origin, "marks"),
            clients,
            cleanup,
            journal,
            capture_into(evidence),
            admit=lambda _: True,
        )
        assert marks.state == "confirmed" and marks.cleanup_state == "cleanup_failed"
        assert len(marks.evidence_refs) >= 4
        assert not as_control_outcome(marks, write_recipe(origin, "marks")).completed_instances
        attendance = run_workflow(
            write_recipe(origin, "attendance"),
            clients,
            cleanup,
            journal,
            capture_into(evidence),
            admit=lambda _: True,
        )
        assert attendance.state == "blocked"
        assert (
            cleanup.request("staff", IdentityRequest(url=origin + "/records/student_a")).json()[
                "attendance"
            ]
            == 72
        )
        assert len([r for r in evidence if r["kind"] == "mutation"]) == 1


def test_invalid_identity_never_reports_a_pass_or_sends_mutation(tmp_path):
    with (
        academic_lab(vulnerable=True) as origin,
        sessions(origin, password="incorrect") as clients,
        sessions(origin) as cleanup,
    ):
        evidence = []
        result = run_workflow(
            write_recipe(origin, "marks"),
            clients,
            cleanup,
            SQLiteCleanupJournal(tmp_path / "journal.sqlite"),
            capture_into(evidence),
            admit=lambda _: True,
        )
        assert result.state == "blocked"
        assert not any(r["kind"] == "mutation" for r in evidence)


@pytest.mark.parametrize(
    "origin",
    [
        "https://portal.school.test",
        "http://127.0.0.1.attacker.test:80",
        "http://user:secret@127.0.0.1:8000",
    ],
)
def test_development_recipes_cannot_be_retargeted_to_customer_hosts(origin):
    with pytest.raises(ValueError):
        write_recipe(origin, "marks")


@pytest.mark.parametrize("field", ["marks", "attendance", "academic_status", "approval_state"])
@pytest.mark.parametrize("vulnerable", [True, False])
def test_operator_selected_protected_assignment_and_allowed_field_control(
    tmp_path, field, vulnerable
):
    from labs.academic_workflows.app import BASELINE
    from labs.academic_workflows.scenarios import assignment_recipe

    with (
        academic_lab(vulnerable=vulnerable) as origin,
        sessions(origin) as clients,
        sessions(origin) as cleanup,
    ):
        journal = SQLiteCleanupJournal(tmp_path / "assignment.sqlite")
        for ordinary in (True, False):
            evidence = []
            recipe = assignment_recipe(origin, field, ordinary_control=ordinary)
            result = run_workflow(
                recipe, clients, cleanup, journal, capture_into(evidence), admit=lambda _: True
            )
            assert result.state == ("confirmed" if vulnerable and not ordinary else "pass")
            assert result.cleanup_state == "clean"
            assert next(r for r in evidence if r["kind"] == "mutation")["status"] == (
                200 if vulnerable or ordinary else 403
            )
            view = cleanup.request("staff", recipe.readback).json()
            assert all(view[key] == value for key, value in BASELINE.items())
            validate_outcome(as_control_outcome(result, recipe))


@pytest.mark.parametrize("vulnerable", [True, False])
def test_staff_function_permission_is_separate_from_record_access(vulnerable):
    with academic_lab(vulnerable=vulnerable) as origin, sessions(origin) as clients:
        results = run_access_comparisons(
            access_matrix(origin, functions=True), clients, capture_into([])
        )
        function_results = [r for r in results if r.family == "function"]
        assert len(function_results) == 3
        assert next(r for r in function_results if r.identity_id == "staff").state == "pass"
        assert all(
            r.state == ("confirmed" if vulnerable else "pass")
            for r in function_results
            if r.identity_id != "staff"
        )


@pytest.mark.parametrize("actor", ["student_b", "staff"])
@pytest.mark.parametrize("vulnerable", [True, False])
def test_approval_forbidden_draft_transition_has_independent_proof(tmp_path, actor, vulnerable):
    from labs.academic_workflows.scenarios import approval_recipe

    with (
        academic_lab(vulnerable=vulnerable) as origin,
        sessions(origin) as clients,
        sessions(origin) as cleanup,
    ):
        recipe = approval_recipe(origin, actor=actor)
        records = []
        result = run_workflow(
            recipe,
            clients,
            cleanup,
            SQLiteCleanupJournal(tmp_path / "approval.sqlite"),
            capture_into(records),
            admit=lambda _: True,
        )
        assert result.state == ("confirmed" if vulnerable else "pass")
        assert result.cleanup_state == "clean"
        assert next(r for r in records if r["kind"] == "mutation")["status"] == (
            200 if vulnerable else 403 if actor == "student_b" else 409
        )
        assert cleanup.request("staff", recipe.readback).json()["approval_state"] == "draft"


@pytest.mark.parametrize("vulnerable", [True, False])
def test_legitimate_approval_order_and_role_controls_restore(vulnerable):
    with academic_lab(vulnerable=vulnerable) as origin, sessions(origin) as clients:
        assert all(clients.verify(name) for name in ("student_a", "student_b", "staff"))
        readback = IdentityRequest(url=origin + "/records/student_a")
        for actor, operation, expected in (
            ("student_a", "submit", "submitted"),
            ("staff", "review", "reviewed"),
            ("staff", "approve", "approved"),
        ):
            response = clients.request(
                actor,
                IdentityRequest(method="POST", url=origin + "/records/student_a/" + operation),
            )
            assert response.status_code == 200
            assert clients.verify(actor, allow_login=False)
            assert clients.request("staff", readback).json()["approval_state"] == expected
        assert (
            clients.request(
                "staff", IdentityRequest(method="POST", url=origin + "/records/student_a/reset")
            ).status_code
            == 200
        )
        assert clients.request("staff", readback).json()["approval_state"] == "draft"


@pytest.mark.parametrize("vulnerable", [True, False])
def test_logout_proof_replays_cookie_without_cross_role_leak(vulnerable):
    from labs.academic_workflows.scenarios import session_policies

    from scopelens.identities.lifecycle import check_session_policy

    with academic_lab(vulnerable=vulnerable) as origin, sessions(origin) as clients:
        assert clients.verify("staff")
        for policy in session_policies(origin)[:2]:
            evidence = []
            results = check_session_policy(policy, clients, capture_into(evidence))
            assert {r.rule_id.rsplit(":", 1)[-1]: r.state for r in results} == {
                "rotation": "pass",
                "logout": "confirmed" if vulnerable else "pass",
            }
            assert clients.verify("staff", allow_login=False)
            assert clients.client("staff").cookies.get("sid") not in json.dumps(evidence)
            assert "synthetic-only" not in json.dumps(evidence)
        assert len({id(client.cookies) for client in clients.clients.values()}) == 3


def test_expired_profile_blocks_read_comparison_and_mutation(tmp_path):
    with (
        academic_lab(vulnerable=True) as origin,
        IdentitySessions(
            identities(origin, expired=True),
            lambda _: SecretStr("synthetic-only"),
            lambda _: httpx.Client(timeout=2, trust_env=False),
        ) as clients,
        sessions(origin) as cleanup,
    ):
        compared = run_access_comparisons(access_matrix(origin), clients, capture_into([]))
        assert next(r for r in compared if r.identity_id == "student_b").state == "blocked"
        evidence = []
        result = run_workflow(
            write_recipe(origin, "marks"),
            clients,
            cleanup,
            SQLiteCleanupJournal(tmp_path / "expiry.sqlite"),
            capture_into(evidence),
            admit=lambda _: True,
        )
        assert result.state == "blocked"
        assert not any(r["kind"] == "mutation" for r in evidence)
        assert not clients.client("student_b").cookies


def test_server_expiry_is_separate_from_logout_and_does_not_relogin(tmp_path):
    from scopelens.identities.lifecycle import clone_cookies

    with (
        academic_lab(vulnerable=True) as origin,
        sessions(origin) as clients,
        sessions(origin) as cleanup,
    ):
        assert clients.verify("student_b") and clients.verify("staff")
        cookie = clone_cookies(clients.client("student_b").cookies)
        assert (
            clients.request(
                "student_b", IdentityRequest(method="POST", url=origin + "/expire")
            ).status_code
            == 200
        )
        clients.client("student_b").cookies = cookie
        assert not clients.verify("student_b", allow_login=False)
        assert clients.verify("staff", allow_login=False)
        evidence = []
        result = run_workflow(
            write_recipe(origin, "marks"),
            clients,
            cleanup,
            SQLiteCleanupJournal(tmp_path / "server-expiry.sqlite"),
            capture_into(evidence),
            admit=lambda _: True,
        )
        assert result.state == "blocked" and not any(r["kind"] == "mutation" for r in evidence)


def test_cancelled_mutation_uses_independent_cleanup_and_recovery_never_replays(tmp_path):
    from scopelens.workflows.assessment import recover_cleanup

    with (
        academic_lab(vulnerable=True) as origin,
        sessions(origin) as clients,
        sessions(origin) as cleanup,
    ):
        journal = SQLiteCleanupJournal(tmp_path / "cancel.sqlite")
        recipe = write_recipe(origin, "marks")
        records = []
        cancelled = False

        def capture(record):
            nonlocal cancelled
            records.append(record)
            if record["kind"] == "mutation":
                cancelled = True
            return "local-test:" + str(len(records))

        clients.cancelled = lambda: cancelled
        result = run_workflow(recipe, clients, cleanup, journal, capture, admit=lambda _: True)
        assert result.state == "blocked" and result.cleanup_state == "clean"
        assert [r["kind"] for r in records][-2:] == ["cleanup", "cleanup_readback"]
        # Explicit synthetic interrupted intent. Recovery reads current state and never sends mutation.
        assert journal.claim(recipe.id, recipe.resource_id)
        journal.mark(recipe.id, recipe.resource_id, "mutation_sent")
        recovered = recover_cleanup(recipe, cleanup, journal, capture, admit=lambda _: True)
        assert recovered.cleanup_state == "clean" and recovered.state == "inconclusive"
        assert len([r for r in records if r["kind"] == "mutation"]) == 1


@pytest.mark.parametrize(
    "origin,service",
    [
        ("http://customer.test:8080", "labs-academic-a"),
        ("http://labs-academic-a:8080/", "labs-academic-a"),
        ("http://labs-academic-a:8080", "other"),
        ("http://labs-academic-a:8081", "labs-academic-a"),
    ],
)
def test_named_deployed_binding_cannot_be_changed(origin, service):
    with pytest.raises(ValueError):
        identities(origin, lab_service=service)


@pytest.mark.parametrize("vulnerable", [True, False])
def test_allowed_profile_field_persists_without_changing_protected_state(vulnerable):
    from labs.academic_workflows.app import BASELINE

    with academic_lab(vulnerable=vulnerable) as origin, sessions(origin) as clients:
        assert clients.verify("student_a") and clients.verify("staff")
        response = clients.request(
            "student_a",
            IdentityRequest(
                method="POST",
                url=origin + "/records/student_a/profile",
                json_body={"display_name": "Synthetic allowed update"},
            ),
        )
        assert response.status_code == 200
        view = clients.request("staff", IdentityRequest(url=origin + "/records/student_a")).json()
        assert view["display_name"] == "Synthetic allowed update"
        assert all(
            view[field] == BASELINE[field]
            for field in ("marks", "attendance", "academic_status", "approval_state")
        )
        assert (
            clients.request(
                "staff", IdentityRequest(method="POST", url=origin + "/records/student_a/reset")
            ).status_code
            == 200
        )
        assert (
            clients.request("staff", IdentityRequest(url=origin + "/records/student_a")).json()[
                "display_name"
            ]
            == BASELINE["display_name"]
        )


def test_wrong_role_cookie_cannot_satisfy_session_probe(tmp_path):
    from scopelens.identities.lifecycle import clone_cookies

    with (
        academic_lab(vulnerable=True) as origin,
        sessions(origin) as clients,
        sessions(origin) as cleanup,
    ):
        assert clients.verify("student_b") and clients.verify("staff")
        clients.client("student_b").cookies = clone_cookies(clients.client("staff").cookies)
        assert not clients.verify("student_b", allow_login=False)
        records = []
        result = run_workflow(
            write_recipe(origin, "marks"),
            clients,
            cleanup,
            SQLiteCleanupJournal(tmp_path / "wrong-role.sqlite"),
            capture_into(records),
            admit=lambda _: True,
        )
        assert result.state == "blocked" and not any(r["kind"] == "mutation" for r in records)


def test_deployed_driver_refuses_local_test_capture_provenance():
    from scripts.verify_academic_workflows_lab import verify_report

    with academic_lab(vulnerable=True) as origin, sessions(origin) as clients:
        records = []
        results = run_access_comparisons(access_matrix(origin), clients, capture_into(records))
        assert any(r.state == "confirmed" for r in results)
        # These records came from real HTTP but were never supervisor admitted.
        local_artifacts = [
            {
                "source": "expansion",
                "kind": "identity_observation",
                "run_id": "local-test-run",
                "evidence_ref": "local-test:" + str(index),
                "data": row,
            }
            for index, row in enumerate(records)
        ]
        metadata = [
            {"id": a["evidence_ref"], "trusted": False, "producer": "local-test"}
            for a in local_artifacts
        ]
        with pytest.raises(AssertionError, match="no supervisor-admitted"):
            verify_report(
                {"profile": "staging-stateful-v1"},
                "staging-stateful-v1",
                metadata,
                local_artifacts,
                {},
                variant="bad",
            )


def test_deployed_combined_configuration_keeps_exact_resource_and_cleanup_contract():
    from scripts.verify_academic_workflows_lab import configuration

    value = configuration(
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "origin": "http://172.28.0.22:8080",
            "lab_binding": {"service": "labs-academic-a"},
        },
        "encrypted-synthetic-reference",
        "combined",
    )
    assert len(value["workflows"]) == 6
    assert {r["resource_id"] for r in value["workflows"]} == {"student-a-record"}
    assert {r["cleanup"]["url"] for r in value["workflows"]} == {
        "http://172.28.0.22:8080/records/student_a/reset"
    }
    assert not value["session_policies"] and value["permission_matrix"] is None


def test_lifecycle_fix_flag_applies_to_logout_and_record_permissions(monkeypatch):
    from types import SimpleNamespace

    from labs.academic_workflows import app as fixture
    from labs.academic_workflows.scenarios import session_policies

    from scopelens.identities.lifecycle import check_session_policy

    flag = {"fixed": False}
    monkeypatch.setattr(fixture, "Path", lambda _: SimpleNamespace(exists=lambda: flag["fixed"]))
    with academic_lab(vulnerable=True, fix_flag="/tmp/academic-fixed") as origin:
        for fixed in (False, True):
            flag["fixed"] = fixed
            with sessions(origin) as clients:
                results = check_session_policy(
                    session_policies(origin)[0], clients, capture_into([])
                )
                assert [r.state for r in results] == ["pass", "pass" if fixed else "confirmed"]
            with sessions(origin) as clients:
                results = run_access_comparisons(access_matrix(origin), clients, capture_into([]))
                assert next(r for r in results if r.identity_id == "student_b").state == (
                    "pass" if fixed else "confirmed"
                )
