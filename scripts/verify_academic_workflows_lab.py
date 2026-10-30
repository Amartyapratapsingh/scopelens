"""Deployed academic gate. Uses only API-admitted owned synthetic lab bindings.

Local HTTP test capture references are never accepted as supervisor evidence. This
script does not start services, access customer origins, print credentials or reset
fixtures. Fix the vulnerable container through its lifecycle before --fixed-retest.
"""

import argparse
import hashlib
import json
import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import httpx
from labs.academic_workflows.app import PASSWORD
from labs.academic_workflows.scenarios import LAB_BINDINGS, deployed_configuration

from scopelens.academic.models import AcademicPlan, AcademicReadiness
from scopelens.config import Settings
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.registry import load_registry
from scopelens.expansion.proof_aggregation import admitted_artifacts, identity_workflow_outcomes
from scopelens.workflows.assessment import evaluate_mutation_proof

CASES = (
    "identities",
    "marks",
    "attendance",
    "assignment-academic_status",
    "ordinary-field-control",
    "approval-student",
    "approval-out-of-order",
    "expired",
    "combined",
)
CONTROLS = {
    "SL-C09-OBJECT-01",
    "SL-C09-FUNCTION-01",
    "SL-C08-SESSION-01",
    "SL-C09-MASS-01",
    "SL-C11-WORKFLOW-01",
}
TERMINAL = {"completed", "completed_partial", "failed", "cancelled"}


def configuration(scope, reference, case):
    value = deployed_configuration(scope, reference, expired=case == "expired")
    if case in {"identities", "expired"}:
        value["workflows"] = []
    elif case == "combined":
        value["permission_matrix"] = None
        value["session_policies"] = []
    else:
        value["permission_matrix"] = None
        value["session_policies"] = []
        recipe_id = "academic-" + case
        value["workflows"] = [r for r in value["workflows"] if r["id"] == recipe_id]
        if len(value["workflows"]) != 1:
            raise ValueError("unknown academic deployed case")
    frozen = AssessmentConfiguration.model_validate(value).model_dump(mode="json")
    # The opt-in timed-expiry extension has not entered this stable gate's API
    # contract. Preserve the historical raw declaration when it is unused.
    for policy in frozen["session_policies"]:
        if policy.get("expiry_after_seconds") is None:
            policy.pop("expiry_after_seconds", None)
    return frozen


def assert_redacted(value):
    serialized = value if isinstance(value, str) else json.dumps(value)
    assert PASSWORD not in serialized, "fixture credential leaked into gate output"
    assert "sid=" not in serialized, "session cookie leaked into gate output"


def verify_report(report, html, metadata, artifacts, frozen, *, variant, expired=False):
    """Recompute bound proofs from downloaded intake artifacts and persisted cleanup."""
    assert_redacted({"report": report, "metadata": metadata, "artifacts": artifacts, "html": html})
    assert report["profile"] == "staging-stateful-v1"
    assert "staging-stateful-v1" in html
    trusted = {
        row["id"]
        for row in metadata
        if row["trusted"] and row["producer"] == "reviewed_expansion_capture"
    }
    for artifact in artifacts:
        data = artifact.get("data", {})
        if data.get("kind") == "session_policy":
            keys = ["old_cookie_hash", "new_cookie_hash"]
            if data.get("check") != "rotation":
                keys.append("replayed_cookie_hash")
            assert all(re.fullmatch(r"[0-9a-f]{64}", data.get(key) or "") for key in keys), (
                "session fingerprint was redacted or invalid"
            )
    admitted = admitted_artifacts(artifacts, trusted)
    assert admitted, "no supervisor-admitted academic captures"
    assert all(a["evidence_ref"] in trusted for a in admitted)
    config = AssessmentConfiguration.model_validate(frozen)
    cleanup = {row["recipe_id"]: row["state"] for row in report["assessment_summary"]["cleanup"]}
    replay = identity_workflow_outcomes(
        admitted,
        {"expansion_config": frozen},
        load_registry(Path(__file__).resolve().parents[1] / "checks_registry"),
        cleanup_states=cleanup,
    )
    outcomes = {
        row["check_id"]: row for row in report["check_outcomes"] if row["check_id"] in replay
    }
    assert set(outcomes) == set(replay), "academic outcome missing from report"
    for control, proof in replay.items():
        row = outcomes[control]
        assert row["status"] == proof.status.value, "report differs from independent proof replay"
        assert set(row["completed_instances"]) == set(proof.completed_instances)
        assert set(row["required_instances"]) == set(proof.required_instances)
        assert set(row["evidence_refs"]) == set(proof.proof.evidence_refs)
        assert set(row["evidence_refs"]) <= trusted
        assert control in html, "HTML omitted academic outcome"
        if expired:
            assert row["status"] == "inconclusive", "expired identity must not become a pass"
            assert set(row["required_instances"]) - set(row["completed_instances"])
            assert row["incomplete_reasons"]
        else:
            expected = "confirmed_issue" if variant == "bad" else "pass"
            if config.workflows and all(
                r.id == "academic-ordinary-field-control" for r in config.workflows
            ):
                expected = "pass"
            assert row["status"] == expected, {
                "control": control,
                "expected": expected,
                "observed": row["status"],
            }
            assert set(row["required_instances"]) == set(row["completed_instances"])
            assert not row["incomplete_reasons"]
    for recipe in config.workflows:
        rows = [
            a["data"]
            for a in admitted
            if a["kind"] == "identity_observation"
            and a["data"].get("proof_type") == "workflow"
            and a["data"].get("proof_id") == recipe.id
        ]
        expected = (
            "confirmed"
            if variant == "bad" and recipe.id != "academic-ordinary-field-control"
            else "pass"
        )
        assert evaluate_mutation_proof(recipe, tuple(rows))[0] == expected
        assert cleanup.get(recipe.id) == "clean", "persistent cleanup ledger is not clean"
        assert [r["identity_id"] for r in rows if r["kind"] == "readback"] == ["staff", "staff"]
        assert len([r for r in rows if r["kind"] == "cleanup_readback"]) == 1
        if recipe.id == "academic-ordinary-field-control":
            assert next(r for r in rows if r["kind"] == "mutation")["status"] == 200
    if expired:
        assert not any(
            a["kind"] == "identity_response" and a["data"].get("identity_id") == "student_b"
            for a in admitted
        ), "expired profile unexpectedly issued a request"
    relevant_findings = [f for f in report["findings"] if f["check_id"] in outcomes]
    confirmed_controls = {
        key for key, row in outcomes.items() if row["status"] == "confirmed_issue"
    }
    assert {f["check_id"] for f in relevant_findings} == confirmed_controls
    assert all(
        f["evidence_status"] == "confirmed" and set(f["evidence_refs"]) <= trusted
        for f in relevant_findings
    )
    summary = {r["check_id"]: r for r in report["assessment_summary"]["checks"]}
    for control, row in outcomes.items():
        assert summary[control]["required"] == len(set(row["required_instances"]))
        assert summary[control]["completed"] == len(set(row["completed_instances"]))
    return {control: row["status"] for control, row in outcomes.items()}


class Gate:
    def __init__(self, client, output, deadline):
        self.client, self.output, self.deadline = client, output, deadline

    def post(self, path, body):
        response = self.client.post(path, json=body)
        response.raise_for_status()
        return response.json()

    def get(self, path):
        response = self.client.get(path)
        response.raise_for_status()
        return response

    def wait(self, scan_id):
        stop = time.monotonic() + self.deadline
        while time.monotonic() < stop:
            view = self.get(f"/api/scans/{scan_id}").json()
            if view["status"] in TERMINAL:
                return view
            time.sleep(2)
        self.post(f"/api/scans/{scan_id}/cancel", {})
        raise AssertionError(
            "academic scan exceeded deadline; cancellation requested, cleanup fences retained"
        )

    def verify(self, scan_id, frozen, label, *, variant, expired=False):
        view = self.wait(scan_id)
        assert view["target_origin"] in LAB_BINDINGS.values()
        response = self.get(f"/api/scans/{scan_id}/export.json")
        report = response.json()
        html = self.get(f"/api/scans/{scan_id}/export.html").text
        metadata = self.get(f"/api/scans/{scan_id}/evidence").json()
        artifacts = []
        for row in metadata:
            if row["producer"] != "reviewed_expansion_capture":
                continue
            assert (
                row["trusted"]
                and row["origin"] == "supervisor"
                and row["run_id"]
                and row["producer_hash"]
            )
            assert not row["truncated"] and row["redaction_state"] in {"clean", "redacted"}
            raw = self.get(f"/api/scans/{scan_id}/evidence/{row['id']}/download").content
            assert hashlib.sha256(raw).hexdigest() == row["content_hash"], (
                "intake artifact digest mismatch"
            )
            item = json.loads(raw)
            assert item["source"] == "expansion"
            assert item.get("run_id", row["run_id"]) == row["run_id"]
            artifacts.append({**item, "evidence_ref": row["id"], "run_id": row["run_id"]})
        controls = verify_report(
            report, html, metadata, artifacts, frozen, variant=variant, expired=expired
        )
        summary = self.get(f"/api/scans/{scan_id}/summary").json()
        assert summary["scan_id"] == scan_id and summary["profile"] == report["profile"]
        assert summary["findings_count"] == len(report["findings"])
        assert summary["overall_score"] == report["score"]["score"]
        assert summary["coverage_percent"] == report["score"]["coverage_percent"]
        findings = self.get(f"/api/scans/{scan_id}/findings").json()
        assert {f["id"] for f in findings} == {f["id"] for f in report["findings"]}
        # Only validated and redacted artifacts may be written.
        (self.output / f"{label}.json").write_text(response.text)
        (self.output / f"{label}.html").write_text(html)
        (self.output / f"{label}-proof.json").write_text(json.dumps(artifacts, indent=2))
        return view, report, controls


def save_json(path, value):
    """Keep the previous receipt intact if a process stops during a write."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2))
    temporary.replace(path)


def saved_configuration(gate, scan_id, case, variant, receipt=None):
    """Bind a saved scan to its immutable, exact owned academic recipe."""
    UUID(scan_id)
    view = gate.get(f"/api/scans/{scan_id}").json()
    readiness = gate.get(f"/api/academic/scans/{scan_id}/readiness").json()
    config = gate.get(f"/api/assessments/configurations/{readiness['configuration_id']}").json()
    frozen = config["configuration"]
    digest = hashlib.sha256(
        json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert digest == config["content_hash"] == readiness["configuration_hash"]
    assert frozen["scope_version_id"] == view["scope_version_id"]
    assert readiness["scope_version_id"] == view["scope_version_id"]
    if receipt:
        assert config["id"] == receipt["configuration_id"]
        assert digest == receipt["configuration_hash"], "saved configuration hash changed"
        assert view["scope_version_id"] == receipt["scope_version_id"]
    scope = gate.get(f"/api/scopes/{view['scope_version_id']}").json()
    service = "labs-academic-a" if variant == "bad" else "labs-academic-b"
    assert scope["origin"] == view["target_origin"] == LAB_BINDINGS[service]
    reference = frozen["identities"][0]["login"]["request"]["secret_fields"]["password"]
    expected = configuration(scope, reference, case)
    if case == "expired":
        # The negative case's timestamp is an immutable original declaration.
        expected["identities"][1]["expires_at"] = frozen["identities"][1]["expires_at"]
        assert datetime.fromisoformat(expected["identities"][1]["expires_at"]) < datetime.now(UTC)
    assert frozen == expected, "saved case differs from exact academic lab recipe"
    return scope, config


def fresh_binding(gate, service):
    expires = (datetime.now(UTC) + timedelta(hours=4)).isoformat()
    scope = gate.post(
        "/api/scopes",
        {
            "authority_domain": "lab",
            "scheme": "http",
            "lab_service": service,
            "lab_port": 8080,
            "allowed_methods": ["GET", "HEAD", "POST"],
            "allowed_check_profile": "staging-stateful-v1",
            "authorization_expires_at": expires,
            "owner_note": "Owned synthetic academic development cases; no real records",
        },
    )
    assert scope["origin"] == LAB_BINDINGS[service]
    credential = gate.post(
        "/api/assessments/credentials",
        {"scope_version_id": scope["id"], "value": PASSWORD, "expires_at": expires},
    )
    return scope, credential


def verify_projections(gate, receipt):
    """Check deployed typed planning and readiness through read-only GET routes."""
    config_path = f"/api/assessments/configurations/{receipt['configuration_id']}"
    original = gate.get(config_path).json()
    scope_path = f"/api/scopes/{receipt['scope_version_id']}"
    before = gate.get(scope_path).json()
    summaries = []
    for kind, identity in (
        ("configurations", receipt["configuration_id"]),
        ("scans", receipt["scan_id"]),
    ):
        prefix = f"/api/academic/{kind}/{identity}"
        readiness = AcademicReadiness.model_validate(gate.get(prefix + "/readiness").json())
        plan = AcademicPlan.model_validate(gate.get(prefix + "/plan").json())
        assert (
            str(readiness.configuration_id)
            == str(plan.configuration_id)
            == receipt["configuration_id"]
        )
        assert (
            readiness.configuration_hash == plan.configuration_hash == receipt["configuration_hash"]
        )
        assert (
            str(readiness.scope_version_id)
            == str(plan.scope_version_id)
            == receipt["scope_version_id"]
        )
        assert plan.readiness_revision == readiness.revision
        assert plan.coverage == readiness.coverage
        assert {r.case.id for r in plan.agenda} == {r.id for r in readiness.cases}
        assert len(plan.agenda) == len(readiness.cases) == plan.budget.baseline_reserved
        assert plan.budget.baseline_ready + plan.budget.baseline_blocked == len(plan.agenda)
        assert not plan.execution_authority and not plan.budget.execution_budget_reserved
        assert all(not row.executed for row in plan.followups)
        payload = {
            "readiness": readiness.model_dump(mode="json"),
            "plan": plan.model_dump(mode="json"),
        }
        assert_redacted(payload)
        save_json(
            gate.output / f"{receipt['case']}-{receipt['variant']}-{kind}-projection.json", payload
        )
        summaries.append({"kind": kind, "cases": len(plan.agenda), "revision": plan.revision})
    assert gate.get(config_path).json() == original, "read-only routes changed frozen configuration"
    assert gate.get(scope_path).json()["scan_count"] == before["scan_count"], (
        "read-only planning queued a scan"
    )
    return summaries


def fixed_retests(gate, receipts):
    """Resume only saved synthetic originals, checking actual API target/config bindings."""
    receipt_path = gate.output / "fixed-retests.json"
    completed = json.loads(receipt_path.read_text()) if receipt_path.exists() else []
    authorization_path = gate.output / "fixed-retest-authorizations.json"
    renewals = json.loads(authorization_path.read_text()) if authorization_path.exists() else {}
    new_binding = None
    candidates = [r for r in receipts if r["variant"] == "bad" and r["finding_ids"]]
    assert candidates, "no saved vulnerable academic finding is available to retest"
    for original in candidates:
        if original["variant"] != "bad" or not original["finding_ids"]:
            continue
        _, config = saved_configuration(
            gate, original["scan_id"], original["case"], "bad", original
        )
        original_frozen = config["configuration"]
        for index, finding_id in enumerate(original["finding_ids"]):
            UUID(finding_id)
            finding = gate.get(f"/api/findings/{finding_id}").json()
            original_report = gate.get(f"/api/scans/{original['scan_id']}/export.json").json()
            assert finding_id in {f["id"] for f in original_report["findings"]}
            assert finding["check_id"] in CONTROLS
            previous = next((r for r in completed if r["finding_id"] == finding_id), None)
            scan_path = gate.output / f"fixed-retest-{finding_id}-scan-id.txt"
            renewal = renewals.get(original["scan_id"])
            if previous or scan_path.exists():
                retest_id = previous["scan_id"] if previous else scan_path.read_text().strip()
                _, retest_config = saved_configuration(
                    gate, retest_id, original["case"], "bad", renewal or original
                )
            else:
                if renewal is None:
                    if new_binding is None:
                        new_binding = fresh_binding(gate, "labs-academic-a")
                    scope, credential = new_binding
                    renewed = json.loads(json.dumps(original_frozen))
                    renewed["scope_version_id"] = scope["id"]
                    for identity in renewed["identities"]:
                        identity["login"]["request"]["secret_fields"]["password"] = credential[
                            "reference"
                        ]
                    assert renewed == configuration(
                        scope, credential["reference"], original["case"]
                    )
                    retest_config = gate.post("/api/assessments/configurations", renewed)
                    renewal = {
                        "configuration_id": retest_config["id"],
                        "configuration_hash": retest_config["content_hash"],
                        "scope_version_id": scope["id"],
                        "original_configuration_id": original["configuration_id"],
                        "original_configuration_hash": original["configuration_hash"],
                    }
                    renewals[original["scan_id"]] = renewal
                    save_json(authorization_path, renewals)
                else:
                    retest_config = gate.get(
                        f"/api/assessments/configurations/{renewal['configuration_id']}"
                    ).json()
                created = gate.post(
                    f"/api/findings/{finding_id}/retest",
                    {
                        "scope_version_id": renewal["scope_version_id"],
                        "assessment_configuration_id": renewal["configuration_id"],
                    },
                )
                retest_id = created["scan_id"]
                scan_path.write_text(retest_id)
                _, retest_config = saved_configuration(
                    gate, retest_id, original["case"], "bad", renewal
                )
            frozen = retest_config["configuration"]
            if renewal:
                assert renewal["original_configuration_id"] == original["configuration_id"]
                assert renewal["original_configuration_hash"] == original["configuration_hash"]
            comparison = json.loads(json.dumps(frozen))
            comparison["scope_version_id"] = original_frozen["scope_version_id"]
            for identity, original_identity in zip(
                comparison["identities"], original_frozen["identities"], strict=True
            ):
                identity["login"]["request"]["secret_fields"] = original_identity["login"][
                    "request"
                ]["secret_fields"]
            assert comparison == original_frozen, "renewed retest changed the declared case"
            print(
                f"academic/{original['case']}: verify same-origin retest scan {retest_id}",
                flush=True,
            )
            fresh, _, controls = gate.verify(
                retest_id, frozen, f"fixed-retest-{original['case']}-{index}", variant="fixed"
            )
            assert fresh["scope_version_id"] == (renewal or original)["scope_version_id"]
            saved_configuration(gate, original["scan_id"], original["case"], "bad", original)
            result = gate.get(f"/api/findings/{finding_id}").json()
            assert result["status"] == "resolved" and result["retest_state"] == "fixed", (
                "fresh relevant complete proof did not close finding"
            )
            completed = [r for r in completed if r["finding_id"] != finding_id]
            completed.append(
                {
                    "finding_id": finding_id,
                    "scan_id": retest_id,
                    "state": "fixed",
                    "controls": controls,
                    "original_configuration_hash": original["configuration_hash"],
                    "configuration_hash": retest_config["content_hash"],
                    "scope_version_id": fresh["scope_version_id"],
                }
            )
            save_json(receipt_path, completed)
            print(f"academic/{original['case']}: same-origin fixed retest verified", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/academic-workflows/deployed"))
    parser.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    parser.add_argument("--variants", nargs="+", choices=["bad", "fixed"], default=["bad", "fixed"])
    parser.add_argument("--deadline", type=int, default=600)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Continue saved receipts and verify any existing unfinished scan before new work",
    )
    parser.add_argument(
        "--refresh-identities",
        action="store_true",
        help="With --resume, repeat only identity login/logout cases after repairing evidence intake",
    )
    parser.add_argument(
        "--fixed-retest",
        action="store_true",
        help="Resume saved vulnerable findings after the designated container lifecycle fix",
    )
    args = parser.parse_args()
    if not 10 <= args.deadline <= 3600:
        parser.error("deadline must be between 10 and 3600 seconds")
    if args.refresh_identities and not args.resume:
        parser.error("--refresh-identities requires --resume")
    args.output.mkdir(parents=True, exist_ok=True)
    receipt_path = args.output / "receipts.json"
    if receipt_path.exists() and not (args.resume or args.fixed_retest):
        parser.error("saved receipts already exist; use --resume to preserve completed work")
    settings = Settings()
    with httpx.Client(
        base_url="http://127.0.0.1:8090", timeout=30, follow_redirects=False, trust_env=False
    ) as client:
        gate = Gate(client, args.output, args.deadline)
        gate.post(
            "/api/auth/login",
            {
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        if args.fixed_retest:
            fixed_retests(gate, json.loads((args.output / "receipts.json").read_text()))
            return
        receipts = (
            json.loads(receipt_path.read_text()) if args.resume and receipt_path.exists() else []
        )
        if args.refresh_identities:
            archive = args.output / "receipts-before-identity-refresh.json"
            if not archive.exists():
                save_json(archive, receipts)
        for variant in args.variants:
            service = "labs-academic-a" if variant == "bad" else "labs-academic-b"
            new_binding = None
            for case in args.cases:
                # Expiry is a blocked fixed negative, distinct from logout vulnerability.
                if case == "expired" and variant == "bad":
                    continue
                previous = next(
                    (r for r in receipts if r["variant"] == variant and r["case"] == case), None
                )
                refresh = args.refresh_identities and case == "identities"
                if previous and not refresh:
                    _, config = saved_configuration(
                        gate, previous["scan_id"], case, variant, previous
                    )
                    _, report, controls = gate.verify(
                        previous["scan_id"],
                        config["configuration"],
                        f"{case}-{variant}",
                        variant=variant,
                        expired=case == "expired",
                    )
                    assert controls == previous["controls"]
                    assert set(previous["finding_ids"]) == {
                        f["id"] for f in report["findings"] if f["check_id"] in controls
                    }
                    print(
                        f"academic/{case}/{variant}: revalidated completed scan {previous['scan_id']}",
                        flush=True,
                    )
                    continue
                scan_path = args.output / f"{case}-{variant}-scan-id.txt"
                archive_path = args.output / f"{case}-{variant}-pre-repair-scan-id.txt"
                if refresh and scan_path.exists() and not archive_path.exists():
                    archive_path.write_text(scan_path.read_text())
                # A refreshed capture already queued before interruption must be resumed.
                refreshed_pending = (
                    refresh
                    and scan_path.exists()
                    and archive_path.exists()
                    and scan_path.read_text().strip() != archive_path.read_text().strip()
                )
                refreshed_completed = (
                    refreshed_pending
                    and previous
                    and previous["scan_id"] == scan_path.read_text().strip()
                )
                if args.resume and scan_path.exists() and (not refresh or refreshed_pending):
                    scan_id = scan_path.read_text().strip()
                    scope, config = saved_configuration(
                        gate,
                        scan_id,
                        case,
                        variant,
                        previous if refreshed_completed else None,
                    )
                    frozen = config["configuration"]
                    print(f"academic/{case}/{variant}: verify existing scan {scan_id}", flush=True)
                else:
                    # Historical bindings may be expired. New execution always gets a
                    # newly admitted scope and credential; old configurations remain intact.
                    if new_binding is None:
                        new_binding = fresh_binding(gate, service)
                    scope, credential = new_binding
                    frozen = configuration(scope, credential["reference"], case)
                    config = gate.post("/api/assessments/configurations", frozen)
                    scan = gate.post(
                        "/api/scans",
                        {
                            "scope_version_id": scope["id"],
                            "assessment_configuration_id": config["id"],
                            "adaptive": False,
                        },
                    )
                    scan_id = scan["id"]
                    print(f"academic/{case}/{variant}: scan {scan_id}", flush=True)
                    scan_path.write_text(scan_id)
                _, report, controls = gate.verify(
                    scan_id, frozen, f"{case}-{variant}", variant=variant, expired=case == "expired"
                )
                receipt = {
                    "case": case,
                    "variant": variant,
                    "scan_id": scan_id,
                    "scope_version_id": scope["id"],
                    "configuration_id": config["id"],
                    "configuration_hash": config["content_hash"],
                    "controls": controls,
                    "proof_origin": "supervisor-admitted-deployed-captures",
                    "finding_ids": [
                        f["id"] for f in report["findings"] if f["check_id"] in controls
                    ],
                }
                receipts = [
                    r for r in receipts if not (r["case"] == case and r["variant"] == variant)
                ]
                receipts.append(receipt)
                save_json(receipt_path, receipts)
                print(
                    "  trusted proof replay, restoration and report consistency verified",
                    flush=True,
                )


if __name__ == "__main__":
    main()
