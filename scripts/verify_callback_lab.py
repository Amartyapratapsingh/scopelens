"""Deployed callback gate for the exact owned synthetic fixture, never external sites."""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy import select

from scopelens.callbacks.runtime import (
    CallbackClosureRow,
    CallbackDispatchIntentRow,
    CallbackDispatchRecordRow,
)
from scopelens.callbacks.service import NonceRow, ReceiptRow
from scopelens.config import Settings
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.persistence.session import session_scope

COLLECTOR = "http://172.28.0.17:8091"
TARGET_PEER = "172.28.0.18"
CONTROLS = {"ssrf": "SL-C07-SSRF-02", "xxe": "SL-C03-XXE-02"}


def scanner_peer(run=subprocess.run):
    """VM relay forwards to enforcing proxy; that proxy opens the collector connection.

    Resolve the running proxy's actual lab interface. Do not infer scanner attribution
    from the VM's NAT address or a host-provided X-Forwarded-For header.
    """
    result = run(
        [
            "docker",
            "ps",
            "--filter",
            "label=com.docker.compose.project=scopelens-dev",
            "--filter",
            "label=com.docker.compose.service=proxy",
            "--format",
            "{{.ID}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    ids = result.stdout.split()
    if len(ids) != 1:
        raise RuntimeError("one running ScopeLens enforcing proxy required")
    result = run(
        ["docker", "inspect", "--format", "{{json .NetworkSettings.Networks}}", ids[0]],
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(result.stdout).get("scopelens_labs_net", {}).get("IPAddress", "")
    address = ipaddress.ip_address(value)
    if address not in ipaddress.ip_network("172.28.0.0/24") or value in {
        TARGET_PEER,
        "172.28.0.17",
    }:
        raise RuntimeError("distinct enforcing proxy lab address required")
    return value


def configuration(scope, family, variant, peer):
    if scope["origin"] != "http://172.28.0.18:8080":
        raise ValueError("exact labs-callbacks scope required")
    return {
        "scope_version_id": scope["id"],
        "callback_recipes": [
            {
                "id": f"owned-{family}-{variant}",
                "recipe": {
                    "family": family,
                    "target_url": scope["origin"]
                    + f"/{variant}/{family}"
                    + ("?url=baseline" if family == "ssrf" else ""),
                    "method": "GET" if family == "ssrf" else "POST",
                    "parameter": "url" if family == "ssrf" else None,
                    "callback_origin": COLLECTOR,
                    "expected_target_peers": [TARGET_PEER],
                    "scanner_peers": [peer],
                    "approved_staging": True,
                    "unexpected_external_fetch": True,
                    "max_wait_seconds": 1,
                },
            }
        ],
    }


def durable_counts(settings, scan_id):
    """Read only safe count/status columns; never fetch private token URLs or key material."""
    with session_scope(settings) as db:
        nonce_ids = list(db.scalars(select(NonceRow.id).where(NonceRow.scan_id == scan_id)))
        dispatches = (
            db.execute(
                select(CallbackDispatchRecordRow.response_status).where(
                    CallbackDispatchRecordRow.scan_id == scan_id
                )
            )
            .scalars()
            .all()
        )
        intents = db.scalars(
            select(CallbackDispatchIntentRow.nonce_id).where(
                CallbackDispatchIntentRow.scan_id == scan_id
            )
        ).all()
        receipts = db.scalars(select(ReceiptRow.id).where(ReceiptRow.nonce_id.in_(nonce_ids))).all()
        closures = db.scalars(
            select(CallbackClosureRow.nonce_id).where(CallbackClosureRow.scan_id == scan_id)
        ).all()
        return {
            "nonces": len(nonce_ids),
            "intents": len(intents),
            "dispatches": len(dispatches),
            "responses": list(dispatches),
            "receipts": len(receipts),
            "closures": len(closures),
        }


def verify_report(report, html, evidence, captures, family, variant, counts):
    control = CONTROLS[family]
    outcome = next(row for row in report["check_outcomes"] if row["check_id"] == control)
    expected = "confirmed_issue" if variant == "bad" else "inconclusive"
    assert outcome["status"] == expected, f"{family}/{variant}: unexpected control state"
    assert report["profile"] == "staging-stateful-v1" and control in html
    assert counts["nonces"] == counts["intents"] == counts["dispatches"] == counts["closures"] == 3
    assert counts["responses"] == [200, 200, 200]
    assert counts["receipts"] == (2 if variant == "bad" else 0)
    metadata = {row["id"]: row for row in evidence}
    trusted_captures = [
        (ref, capture)
        for ref, capture in captures.items()
        if capture.get("kind") == "callback_capture"
    ]
    assert len(trusted_captures) == 1
    for ref, capture in trusted_captures:
        assert (
            metadata[ref]["trusted"]
            and metadata[ref]["producer"] == "reviewed_callback_broker_capture"
        )
        assert capture["source"] == "callback_broker"
        assert len(capture["data"]["dispatches"]) == 3
        assert capture["data"]["finished_at"] > 0
    if variant == "bad":
        assert outcome["evidence_refs"] and set(outcome["evidence_refs"]) <= set(captures)
        assert set(outcome["required_instances"]) == set(outcome["completed_instances"])
    else:
        assert not outcome["completed_instances"]
        assert all(row.get("check_id") != control for row in report["findings"])
    serialized = json.dumps({"report": report, "evidence": evidence, "captures": captures}) + html
    assert "/callback/" not in serialized and COLLECTOR not in serialized, (
        "private callback URL leaked"
    )
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("runs/callbacks-deployed"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    settings = Settings()
    if not settings.callbacks_enabled or COLLECTOR not in {
        value.rstrip("/") for value in settings.callback_collector_origins
    }:
        raise RuntimeError("owned callback collector configuration required")
    peer = scanner_peer()
    summaries = []
    with httpx.Client(
        base_url="http://127.0.0.1:8090", timeout=30, follow_redirects=False
    ) as client:

        def post(path, data):
            response = client.post(path, json=data)
            response.raise_for_status()
            return response.json()

        def get(path):
            response = client.get(path)
            response.raise_for_status()
            return response

        post(
            "/api/auth/login",
            {
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        scope = post(
            "/api/scopes",
            {
                "authority_domain": "lab",
                "scheme": "http",
                "lab_service": "labs-callbacks",
                "lab_port": 8080,
                "allowed_methods": ["GET", "HEAD", "POST"],
                "allowed_check_profile": "staging-stateful-v1",
                "authorization_expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
            },
        )
        for family in CONTROLS:
            for variant in ("bad", "fixed"):
                label = f"{family}-{variant}"
                frozen = configuration(scope, family, variant, peer)
                AssessmentConfiguration.model_validate(frozen)
                config = post("/api/assessments/configurations", frozen)
                scan = post(
                    "/api/scans",
                    {
                        "scope_version_id": scope["id"],
                        "assessment_configuration_id": config["id"],
                        "adaptive": False,
                    },
                )
                ident = scan["id"]
                (args.output / f"{label}-scan-id.txt").write_text(ident)
                print(f"{label}: scan {ident}", flush=True)
                deadline = time.monotonic() + 600
                while time.monotonic() < deadline:
                    state = get(f"/api/scans/{ident}").json()["status"]
                    if state in {"completed", "completed_partial", "failed", "cancelled"}:
                        break
                    time.sleep(2)
                else:
                    post(f"/api/scans/{ident}/cancel", {})
                    raise RuntimeError("callback lab deadline exceeded; cancellation requested")
                report = get(f"/api/scans/{ident}/export.json").json()
                html = get(f"/api/scans/{ident}/export.html").text
                evidence = get(f"/api/scans/{ident}/evidence").json()
                captures = {}
                for row in evidence:
                    if "callback" in row.get("summary", "").lower():
                        captures[row["id"]] = get(
                            f"/api/scans/{ident}/evidence/{row['id']}/download"
                        ).json()
                counts = durable_counts(settings, ident)
                outcome = verify_report(report, html, evidence, captures, family, variant, counts)
                serialized = json.dumps({"report": report, "captures": captures}) + html
                assert settings.callback_signing_key.get_secret_value() not in serialized
                (args.output / f"{label}.json").write_text(json.dumps(report, indent=2))
                (args.output / f"{label}.html").write_text(html)
                (args.output / f"{label}-captures.json").write_text(json.dumps(captures, indent=2))
                summaries.append(
                    {
                        "case": label,
                        "scan_id": ident,
                        "scan_status": state,
                        "control_status": outcome["status"],
                        "counts": counts,
                        "proof_refs": outcome["evidence_refs"],
                    }
                )
                (args.output / "receipts.json").write_text(json.dumps(summaries, indent=2))
                print(
                    f"  {outcome['status']}; durable callback counts and exports verified",
                    flush=True,
                )


if __name__ == "__main__":
    main()
