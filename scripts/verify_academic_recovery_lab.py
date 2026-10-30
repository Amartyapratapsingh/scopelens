"""Real deployed academic failure/cancel/recovery gate, fixed to the owned .24 lab.

Runs no target HTTP outside the API/broker. Docker access only reads sanitized fixture
telemetry, controls tmpfs flags, and restarts this one synthetic container for operator
repair. Never inserts cleanup rows, issues tokens, or writes backend persistence.
"""

import argparse
import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import httpx
from labs.academic_faults.app import FLAGS
from labs.academic_faults.scenarios import ORIGIN, SERVICE, configuration
from labs.academic_workflows.app import PASSWORD
from sqlalchemy import select

from scopelens.config import Settings
from scopelens.domain.registry import load_registry
from scopelens.domain.workflow import WorkflowRecipe
from scopelens.expansion.proof_aggregation import admitted_artifacts, identity_workflow_outcomes
from scopelens.expansion.recovery import RECOVERY_PRODUCER, RecoverySpec, evaluate_recovery
from scopelens.persistence.models import CleanupRow, ScanRow
from scopelens.persistence.session import session_scope
from scopelens.workflows.assessment import evaluate_mutation_proof

CONTAINER = "scopelens-labs-academic-faults"
TERMINAL = {"completed", "completed_partial", "failed", "cancelled"}


def redacted(value):
    raw = json.dumps(value)
    assert PASSWORD not in raw and "sid=" not in raw, "secret appeared in gate output"


def docker_python(code):
    return subprocess.run(
        ["docker", "exec", CONTAINER, "python", "-c", code],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout


def lifecycle_flag(name, *, present=True):
    if name not in FLAGS:
        raise ValueError("unknown academic fault lifecycle flag")
    action = "p.touch()" if present else "p.unlink(missing_ok=True)"
    docker_python(f"from pathlib import Path; p=Path('/tmp/academic-faults/{name}'); {action}")


def fixture_requests():
    raw = docker_python(
        "from pathlib import Path; p=Path('/tmp/academic-faults/requests.jsonl'); "
        "print(p.read_text() if p.exists() else '')"
    )
    return [json.loads(row) for row in raw.splitlines() if row]


def fixture_writes(rows):
    return [r for r in rows if r["method"] == "POST" and r["path"].startswith("/records/")]


def operator_restore():
    """Restart restores the fixture's in-memory seed; it cannot release a DB fence."""
    subprocess.run(["docker", "restart", CONTAINER], check=True, capture_output=True, timeout=30)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        health = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Health.Status}}", CONTAINER],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout.strip()
        if health == "healthy":
            return
        time.sleep(1)
    raise AssertionError("academic fault fixture did not become healthy after operator repair")


def readonly_cleanup(settings, scan_id):
    with session_scope(settings) as db:
        rows = db.scalars(select(CleanupRow).where(CleanupRow.scan_id == UUID(scan_id))).all()
        return [
            {
                "id": str(r.id),
                "scan_id": str(r.scan_id),
                "recipe_id": r.recipe_id,
                "resource_id": r.resource_id,
                "state": r.state,
            }
            for r in rows
        ]


class Gate:
    def __init__(self, client, settings, output, deadline):
        self.client, self.settings, self.output, self.deadline = client, settings, output, deadline

    def save(self, label, value):
        redacted(value)
        path = self.output / (label + ".json")
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(value, indent=2))
        temporary.replace(path)

    def request(self, method, path, body=None):
        response = self.client.request(method, path, json=body)
        response.raise_for_status()
        return response.json()

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body):
        return self.request("POST", path, body)

    def wait(self, scan_id, *, recovery=False):
        stop = time.monotonic() + self.deadline
        path = f"/api/cleanup-recoveries/{scan_id}" if recovery else f"/api/scans/{scan_id}"
        while time.monotonic() < stop:
            view = self.get(path)
            if view["status"] in TERMINAL:
                return view
            time.sleep(1)
        self.post(f"/api/scans/{scan_id}/cancel", {})
        raise AssertionError("academic fault scan deadline exceeded; cancellation requested")

    def authority(self, field=None):
        expires = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
        scope = self.post(
            "/api/scopes",
            {
                "authority_domain": "lab",
                "scheme": "http",
                "lab_service": SERVICE,
                "lab_port": 8080,
                "allowed_methods": ["GET", "HEAD", "POST"],
                "allowed_check_profile": "staging-stateful-v1",
                "authorization_expires_at": expires,
                "owner_note": "Owned synthetic academic fault gate; no real academic records",
            },
        )
        secret = self.post(
            "/api/assessments/credentials",
            {
                "scope_version_id": scope["id"],
                "value": PASSWORD,
                "expires_at": expires,
            },
        )
        frozen = configuration(scope, secret["reference"], field)
        config = self.post("/api/assessments/configurations", frozen)
        return scope, config

    def scan(self, label, scope, config):
        view = self.post(
            "/api/scans",
            {
                "scope_version_id": scope["id"],
                "assessment_configuration_id": config["id"],
            },
        )
        self.save(
            label + "-queued",
            {
                "scan_id": view["id"],
                "scope_id": scope["id"],
                "configuration_id": config["id"],
                "configuration_hash": config["content_hash"],
            },
        )
        return view["id"]

    def artifacts(self, scan_id, producer):
        metadata = self.get(f"/api/scans/{scan_id}/evidence")
        rows, artifacts = [], []
        for row in metadata:
            if row["producer"] != producer:
                continue
            assert (
                row["trusted"]
                and row["origin"] == "supervisor"
                and row["run_id"]
                and row["producer_hash"]
            )
            assert not row["truncated"] and row["redaction_state"] in {"clean", "redacted"}
            response = self.client.get(f"/api/scans/{scan_id}/evidence/{row['id']}/download")
            response.raise_for_status()
            assert hashlib.sha256(response.content).hexdigest() == row["content_hash"]
            rows.append(row)
            artifacts.append(
                {**response.json(), "evidence_ref": row["id"], "run_id": row["run_id"]}
            )
        redacted(artifacts)
        return rows, artifacts

    def recovery(self, label, cleanup, *, restored):
        scope, config = self.authority()
        before = fixture_writes(fixture_requests())
        created = self.post(
            "/api/cleanup-recoveries",
            {
                "cleanup_id": cleanup["id"],
                "scope_version_id": scope["id"],
                "assessment_configuration_id": config["id"],
            },
        )
        self.save(label + "-queued", created)
        view = self.wait(created["id"], recovery=True)
        assert view["result"] and view["result"]["verified"] is restored, view
        metadata, artifacts = self.artifacts(created["id"], RECOVERY_PRODUCER)
        selected = next(a for a in artifacts if a["evidence_ref"] == view["result"]["evidence_ref"])
        with session_scope(self.settings) as db:
            scan = db.get(ScanRow, UUID(created["id"]))
            spec = RecoverySpec.model_validate(scan.assessment_plan["cleanup_recovery"])
            assert evaluate_recovery(spec, selected)[0] is restored
            assert str(scan.scope_version_id) == scope["id"]
            assert not scan.assessment_plan["expansion_config"].get("workflows")
            fence = db.get(CleanupRow, UUID(cleanup["id"]))
            assert fence.state == ("clean" if restored else cleanup["state"])
        assert fixture_writes(fixture_requests()) == before, (
            "recovery replayed a fixture mutation/reset"
        )
        self.save(
            label,
            {
                "view": view,
                "evidence": selected,
                "metadata": metadata,
                "fixture_writes_unchanged": True,
                "operator_fixture_restored": restored,
            },
        )
        return view


def verify_failure(gate, scan_id, config):
    view = gate.wait(scan_id)
    assert view["status"] == "completed_partial", view
    report = gate.get(f"/api/scans/{scan_id}/export.json")
    metadata, artifacts = gate.artifacts(scan_id, "reviewed_expansion_capture")
    trusted = {r["id"] for r in metadata}
    admitted = admitted_artifacts(artifacts, trusted)
    cleanup = readonly_cleanup(gate.settings, scan_id)
    assert len(cleanup) == 1 and cleanup[0]["state"] == "cleanup_failed", cleanup
    recipe = WorkflowRecipe.model_validate(config["configuration"]["workflows"][0])
    observations = tuple(
        a["data"]
        for a in admitted
        if a["kind"] == "identity_observation" and a["data"].get("proof_id") == recipe.id
    )
    assert evaluate_mutation_proof(recipe, observations)[0] == "confirmed"
    assert any(o["kind"] == "cleanup" and o["status"] == 503 for o in observations)
    replay = identity_workflow_outcomes(
        admitted,
        {"expansion_config": config["configuration"]},
        load_registry(Path(__file__).resolve().parents[1] / "checks_registry"),
        cleanup_states={recipe.id: "cleanup_failed"},
    )["SL-C11-WORKFLOW-01"]
    outcome = next(r for r in report["check_outcomes"] if r["check_id"] == replay.check_id)
    assert outcome["status"] == replay.status.value == "confirmed_issue"
    assert not outcome["completed_instances"] and outcome["incomplete_reasons"]
    assert set(outcome["evidence_refs"]) == set(replay.proof.evidence_refs) <= trusted
    gate.save("failure", {"view": view, "report": report, "proof": artifacts, "cleanup": cleanup})
    return cleanup[0]


def blocked_other_property(gate):
    before = fixture_writes(fixture_requests())
    scope, config = gate.authority("attendance")
    scan_id = gate.scan("blocked-attendance", scope, config)
    view = gate.wait(scan_id)
    report = gate.get(f"/api/scans/{scan_id}/export.json")
    outcome = next(r for r in report["check_outcomes"] if r["check_id"] == "SL-C11-WORKFLOW-01")
    assert outcome["status"] == "inconclusive" and not outcome["completed_instances"]
    assert outcome["incomplete_reasons"]
    assert not readonly_cleanup(gate.settings, scan_id), (
        "blocked scan acquired a second resource fence"
    )
    assert fixture_writes(fixture_requests()) == before, (
        "resource fence allowed another property write"
    )
    gate.save(
        "blocked-attendance", {"view": view, "report": report, "fixture_writes_unchanged": True}
    )


def cancelled_held_mutation(gate):
    lifecycle_flag("hold-mutation")
    scope, config = gate.authority("marks")
    scan_id = gate.scan("cancelled", scope, config)
    stop = time.monotonic() + gate.deadline
    while time.monotonic() < stop:
        applied = docker_python(
            "from pathlib import Path; print(Path('/tmp/academic-faults/mutation-applied').exists())"
        ).strip()
        if applied == "True":
            break
        assert gate.get(f"/api/scans/{scan_id}")["status"] not in TERMINAL, (
            "scan ended before held mutation"
        )
        time.sleep(0.2)
    else:
        gate.post(f"/api/scans/{scan_id}/cancel", {})
        raise AssertionError("held mutation marker never appeared; scan cancelled")
    before = fixture_writes(fixture_requests())
    assert before[-1] == {"method": "POST", "path": "/records/student_a/marks", "status": 200}
    view = gate.post(f"/api/scans/{scan_id}/cancel", {})
    assert view["status"] == "cancelled" and view["cancel_requested_at"]
    with session_scope(gate.settings) as db:
        scan = db.get(ScanRow, UUID(scan_id))
        assert scan.egress_token_hash and scan.egress_token_epoch < scan.cancel_epoch
        epochs = {
            "issued_epoch": scan.egress_token_epoch,
            "cancel_epoch": scan.cancel_epoch,
            "revocation_check": "persisted epoch mismatch used by broker authorization",
        }
    cleanup = readonly_cleanup(gate.settings, scan_id)
    assert len(cleanup) == 1 and cleanup[0]["state"] in {"pending", "mutation_sent"}
    lifecycle_flag("release-mutation")
    # Allow the released handler and cancellation outbox to finish; request telemetry
    # must remain stable across the supervisor's documented 30 second stop window.
    time.sleep(35)
    assert fixture_writes(fixture_requests()) == before, (
        "cancelled scan sent another write or reset"
    )
    assert readonly_cleanup(gate.settings, scan_id) == cleanup, (
        "revoked worker altered durable intent"
    )
    gate.save(
        "cancelled",
        {
            "view": view,
            "cleanup": cleanup,
            "revocation": epochs,
            "fixture_writes": before,
            "mutation_outcome": "unknown; response held at cancellation",
        },
    )
    return cleanup[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/academic-recovery-deployed"))
    parser.add_argument("--deadline", type=int, default=600)
    parser.add_argument("--recover-cleanup", type=UUID)
    parser.add_argument("--restore-fixture", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.recover_cleanup and list(args.output.glob("*-queued.json")):
        raise SystemExit(
            "Saved fault scans exist. Inspect/recover their fences; use a fresh output directory. Original mutations must not be replayed."
        )
    settings = Settings()
    with httpx.Client(
        base_url="http://127.0.0.1:8090", timeout=30, follow_redirects=False
    ) as client:
        gate = Gate(client, settings, args.output, args.deadline)
        gate.post(
            "/api/auth/login",
            {
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        if args.recover_cleanup:
            pending = gate.get("/api/cleanup-recoveries/pending")
            cleanup = next((r for r in pending if r["id"] == str(args.recover_cleanup)), None)
            assert cleanup is not None, "requested cleanup is not an owned pending fence"
            source = gate.get(f"/api/scans/{cleanup['scan_id']}")
            assert source["target_origin"] == ORIGIN, (
                "cleanup does not belong to the academic fault fixture"
            )
            assert cleanup["resource_id"] == "student-a-record" and cleanup["recipe_id"] in {
                "academic-marks",
                "academic-attendance",
            }
            if args.restore_fixture:
                gate.save("operator-repair-before-requests", fixture_requests())
                operator_restore()
            gate.recovery("operator-recovery", cleanup, restored=True)
            print(
                "Original fence recovered through fresh trusted readback; no mutation replay",
                flush=True,
            )
            return
        assert not args.restore_fixture, "--restore-fixture requires --recover-cleanup"
        assert not fixture_writes(fixture_requests()), (
            "start from a freshly recreated synthetic fault fixture"
        )
        scope, config = gate.authority("marks")
        assert scope["origin"] == ORIGIN
        source = gate.scan("failure", scope, config)
        print(f"Academic failed reset scan: {source}", flush=True)
        failed = verify_failure(gate, source, config)
        blocked_other_property(gate)
        gate.recovery("unrestored-recovery", failed, restored=False)
        gate.save("failure-fixture-requests", fixture_requests())
        operator_restore()
        gate.recovery("failed-reset-recovered", failed, restored=True)
        print(
            "Failed reset proof retained; fresh read-only recovery released its fence", flush=True
        )
        cancelled = cancelled_held_mutation(gate)
        gate.save("cancel-fixture-requests", fixture_requests())
        operator_restore()
        gate.recovery("cancelled-recovered", cancelled, restored=True)
        gate.save(
            "receipts",
            {
                "failed_cleanup_id": failed["id"],
                "cancelled_cleanup_id": cancelled["id"],
                "both_recovered_with_trusted_readback": True,
                "source_mutations_replayed": False,
            },
        )
        print(
            "Held mutation cancelled; durable unknown intent recovered without mutation replay",
            flush=True,
        )


if __name__ == "__main__":
    main()
