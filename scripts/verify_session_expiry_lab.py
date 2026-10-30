"""Deployed expiry gate over exact owned fixture bindings and admitted API scans.

This script never starts services or bypasses coordinator admission. It verifies
downloaded supervisor evidence and actual server receipt of both replay cookies.
"""

import argparse
import hashlib
import json
import re
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import httpx
from labs.session_expiry.app import PASSWORD

from scopelens.config import Settings
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import (
    IdentityProfile,
    IdentityRequest,
    LoginRecipe,
    SessionPolicy,
    SessionProbe,
)
from scopelens.domain.registry import load_registry
from scopelens.expansion.proof_aggregation import admitted_artifacts, identity_workflow_outcomes
from scopelens.identities.lifecycle import evaluate_session_proof

LAB_BINDINGS = {
    "labs-session-expiry-a": "http://172.28.0.25:8080",
    "labs-session-expiry-b": "http://172.28.0.26:8080",
}
SERVICES = {"bad": "labs-session-expiry-a", "fixed": "labs-session-expiry-b"}
CONTROL = "SL-C08-SESSION-01"
INSTANCE = "session:student:expiry"
TERMINAL = {"completed", "completed_partial", "failed", "cancelled"}


def configuration(scope, reference):
    service = (scope.get("lab_binding") or {}).get("service")
    if service not in LAB_BINDINGS or scope["origin"] != LAB_BINDINGS[service]:
        raise ValueError("expiry gate requires an exact owned synthetic fixture binding")
    origin = scope["origin"]
    profile = IdentityProfile(
        id="student",
        role="student",
        login=LoginRecipe(
            request=IdentityRequest(
                method="POST",
                url=origin + "/login",
                json_body={"username": "student"},
                secret_fields={"password": reference},
            )
        ),
        probe=SessionProbe(
            request=IdentityRequest(url=origin + "/me"),
            expected_identity="student",
            unauthenticated_pointer="/error",
            unauthenticated_value="unauthenticated",
        ),
    )
    return AssessmentConfiguration(
        scope_version_id=UUID(scope["id"]),
        identities=(profile,),
        session_policies=(
            SessionPolicy(
                identity_id="student",
                cookie_name="sid",
                login_rotates=False,
                expiry_after_seconds=1,
            ),
        ),
    ).model_dump(mode="json")


def assert_redacted(value):
    serialized = value if isinstance(value, str) else json.dumps(value)
    assert PASSWORD not in serialized and "sid=" not in serialized, "fixture credentials leaked"


def assert_fixture_proof(record, proof):
    assert proof["server_ttl_seconds"] == 1
    seen = [
        row for row in proof["sessions"] if row["cookie_hash"] == record["replayed_cookie_hash"]
    ]
    assert len(seen) == 1 and seen[0]["expired_probe_count"] >= 2, (
        "server did not receive the same declared expired cookie twice"
    )
    assert seen[0]["server_age_seconds"] >= 1


def fixture_proof(service):
    assert service in LAB_BINDINGS
    command = [
        "docker",
        "exec",
        "scopelens-" + service,
        "python",
        "-c",
        "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/fixture-proof').read().decode())",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=10, check=True)
    result = json.loads(completed.stdout)
    assert_redacted(result)
    return result


def verify_report(report, html, metadata, artifacts, frozen, *, variant, server_proof):
    assert variant in SERVICES
    assert_redacted(
        {
            "report": report,
            "html": html,
            "metadata": metadata,
            "artifacts": artifacts,
            "server_proof": server_proof,
        }
    )
    config = AssessmentConfiguration.model_validate(frozen)
    assert len(config.session_policies) == len(config.identities) == 1
    assert config.identities[0].probe.request.url == LAB_BINDINGS[SERVICES[variant]] + "/me"
    trusted = {
        row["id"]
        for row in metadata
        if row["trusted"] and row["producer"] == "reviewed_expansion_capture"
    }
    admitted = admitted_artifacts(artifacts, trusted)
    captures = [
        a
        for a in admitted
        if a["kind"] == "identity_observation"
        and a["data"].get("kind") == "session_policy"
        and a["data"].get("check") == "expiry"
    ]
    assert len(captures) == 1, "unique admitted expiry observation required"
    record = captures[0]["data"]
    for field in ("old_cookie_hash", "new_cookie_hash", "replayed_cookie_hash"):
        assert re.fullmatch(r"[0-9a-f]{64}", record.get(field) or ""), (
            "invalid persisted fingerprint"
        )
    expected = "confirmed" if variant == "bad" else "pass"
    assert (
        evaluate_session_proof(config.session_policies[0], config.identities[0], record)[0]
        == expected
    )
    assert_fixture_proof(record, server_proof)
    registry = load_registry(Path(__file__).resolve().parents[1] / "checks_registry")
    replay = identity_workflow_outcomes(admitted, {"expansion_config": frozen}, registry)[CONTROL]
    rows = [row for row in report["check_outcomes"] if row["check_id"] == CONTROL]
    assert len(rows) == 1
    row = rows[0]
    assert (
        row["status"] == replay.status.value == ("confirmed_issue" if variant == "bad" else "pass")
    )
    assert row["required_instances"] == row["completed_instances"] == [INSTANCE]
    assert (
        tuple(row["required_instances"]) == replay.required_instances == replay.completed_instances
    )
    assert not row["incomplete_reasons"]
    assert set(row["evidence_refs"]) == set(replay.proof.evidence_refs) <= trusted
    assert CONTROL in html and report["profile"] == "staging-stateful-v1"
    findings = [f for f in report["findings"] if f["check_id"] == CONTROL]
    assert bool(findings) is (variant == "bad")
    assert all(
        f["evidence_status"] == "confirmed" and set(f["evidence_refs"]) <= trusted for f in findings
    )
    summary = next(s for s in report["assessment_summary"]["checks"] if s["check_id"] == CONTROL)
    assert summary["required"] == summary["completed"] == 1
    missing = identity_workflow_outcomes([], {"expansion_config": frozen}, registry)[CONTROL]
    assert not missing.is_fully_assessed and missing.required_instances == (INSTANCE,)
    assert not admitted_artifacts(artifacts, set())
    return record


def save_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2))
    temporary.replace(path)


class Gate:
    def __init__(self, client, output, deadline):
        self.client, self.output, self.deadline = client, output, deadline

    def get(self, path):
        response = self.client.get(path)
        response.raise_for_status()
        return response

    def post(self, path, body):
        response = self.client.post(path, json=body)
        response.raise_for_status()
        return response.json()

    def wait(self, scan_id):
        stop = time.monotonic() + self.deadline
        while time.monotonic() < stop:
            view = self.get(f"/api/scans/{scan_id}").json()
            if view["status"] in TERMINAL:
                return view
            time.sleep(2)
        self.post(f"/api/scans/{scan_id}/cancel", {})
        raise AssertionError("expiry scan exceeded deadline; cancellation requested")

    def saved_configuration(self, receipt):
        UUID(receipt["scan_id"])
        view = self.get(f"/api/scans/{receipt['scan_id']}").json()
        readiness = self.get(f"/api/academic/scans/{receipt['scan_id']}/readiness").json()
        config = self.get(f"/api/assessments/configurations/{receipt['configuration_id']}").json()
        frozen = config["configuration"]
        digest = hashlib.sha256(
            json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert (
            digest
            == config["content_hash"]
            == receipt["configuration_hash"]
            == readiness["configuration_hash"]
        )
        assert config["id"] == readiness["configuration_id"] == receipt["configuration_id"]
        assert (
            frozen["scope_version_id"]
            == view["scope_version_id"]
            == receipt["scope_version_id"]
            == readiness["scope_version_id"]
        )
        scope = self.get(f"/api/scopes/{receipt['scope_version_id']}").json()
        service = SERVICES[receipt["variant"]]
        assert scope["origin"] == view["target_origin"] == LAB_BINDINGS[service]
        reference = frozen["identities"][0]["login"]["request"]["secret_fields"]["password"]
        assert frozen == configuration(scope, reference), "saved expiry case changed"
        return scope, config

    def verify(self, receipt, frozen):
        scan_id, variant = receipt["scan_id"], receipt["variant"]
        view = self.wait(scan_id)
        assert view["target_origin"] == LAB_BINDINGS[SERVICES[variant]]
        self.saved_configuration(receipt)
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
            assert hashlib.sha256(raw).hexdigest() == row["content_hash"]
            item = json.loads(raw)
            assert item["source"] == "expansion"
            assert item.get("run_id", row["run_id"]) == row["run_id"]
            artifacts.append({**item, "evidence_ref": row["id"], "run_id": row["run_id"]})
        proof_path = self.output / f"{variant}-server-proof.json"
        server = (
            json.loads(proof_path.read_text())
            if receipt.get("verified")
            else fixture_proof(SERVICES[variant])
        )
        record = verify_report(
            report, html, metadata, artifacts, frozen, variant=variant, server_proof=server
        )
        readiness = self.get(f"/api/academic/scans/{scan_id}/readiness").json()
        cases = [
            c for c in readiness["cases"] if c["kind"] == "session" and c["family"] == "expiry"
        ]
        assert len(cases) == 1 and cases[0]["admitted"] and cases[0]["execution"] == "observed"
        assert cases[0]["proof"] == ("confirmed_issue" if variant == "bad" else "pass")
        summary = self.get(f"/api/scans/{scan_id}/summary").json()
        assert summary["scan_id"] == scan_id and summary["profile"] == report["profile"]
        assert summary["findings_count"] == len(report["findings"])
        assert summary["overall_score"] == report["score"]["score"]
        assert summary["coverage_percent"] == report["score"]["coverage_percent"]
        findings = self.get(f"/api/scans/{scan_id}/findings").json()
        assert {f["id"] for f in findings} == {f["id"] for f in report["findings"]}
        assert_redacted({"summary": summary, "findings": findings, "readiness": readiness})
        (self.output / f"{variant}.json").write_text(response.text)
        (self.output / f"{variant}.html").write_text(html)
        save_json(self.output / f"{variant}-proof.json", artifacts)
        save_json(proof_path, server)
        save_json(self.output / f"{variant}-readiness.json", readiness)
        return {
            **receipt,
            "verified": True,
            "proof_origin": "supervisor-admitted-deployed-captures",
            "control": CONTROL,
            "instance": INSTANCE,
            "status": "confirmed_issue" if variant == "bad" else "pass",
            "waited_seconds": record["expiry_waited_seconds"],
            "server_seen_replays": 2,
        }


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
            "owner_note": "Owned synthetic timed server expiry fixture",
        },
    )
    assert scope["origin"] == LAB_BINDINGS[service]
    credential = gate.post(
        "/api/assessments/credentials",
        {
            "scope_version_id": scope["id"],
            "value": PASSWORD,
            "expires_at": expires,
        },
    )
    return scope, credential


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("runs/session-expiry/deployed"))
    parser.add_argument("--variants", nargs="+", choices=("bad", "fixed"), default=["bad", "fixed"])
    parser.add_argument("--deadline", type=int, default=600)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if not 10 <= args.deadline <= 3600:
        parser.error("deadline must be between 10 and 3600 seconds")
    args.output.mkdir(parents=True, exist_ok=True)
    path = args.output / "receipts.json"
    if path.exists() and not args.resume:
        parser.error("saved receipts exist; use --resume to preserve pending and completed scans")
    receipts = json.loads(path.read_text()) if path.exists() else []
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
        for variant in args.variants:
            previous = next((r for r in receipts if r["variant"] == variant), None)
            if previous:
                _, config = gate.saved_configuration(previous)
                receipt = previous
            else:
                scope, credential = fresh_binding(gate, SERVICES[variant])
                config = gate.post(
                    "/api/assessments/configurations", configuration(scope, credential["reference"])
                )
                scan = gate.post(
                    "/api/scans",
                    {
                        "scope_version_id": scope["id"],
                        "assessment_configuration_id": config["id"],
                        "adaptive": False,
                    },
                )
                receipt = {
                    "variant": variant,
                    "scan_id": scan["id"],
                    "scope_version_id": scope["id"],
                    "configuration_id": config["id"],
                    "configuration_hash": config["content_hash"],
                    "verified": False,
                }
                receipts.append(receipt)
                save_json(path, receipts)
            print(f"session-expiry/{variant}: verify scan {receipt['scan_id']}", flush=True)
            result = gate.verify(receipt, config["configuration"])
            receipts = [r for r in receipts if r["variant"] != variant] + [result]
            save_json(path, receipts)
            print(
                "  persisted expiry proof, server cookie receipts, and reports verified", flush=True
            )


if __name__ == "__main__":
    main()
