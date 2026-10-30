"""Read-only export gate against trusted persisted evidence for an owned lab scan."""

import argparse
import json
from pathlib import Path
from uuid import UUID

import httpx

from scopelens.config import Settings
from scopelens.domain.capabilities import canonical_sha256, snapshot_matches
from scopelens.domain.report_metadata import CapabilitySnapshot
from scopelens.execution.capability_probe import PROBE_SHA256
from scopelens.execution.capability_producer import source_digest
from scopelens.persistence.models import ScanRow
from scopelens.persistence.session import session_scope
from scopelens.writer.report import _capabilities


def verify_capability_projection(plan, report, *, scan_id, scope_id, require_measured=False):
    """The plan is read from the supervisor database, never from an API/worker payload."""
    profile = report["profile"]
    expected = _capabilities(plan, profile, scan_id=str(scan_id), scope_version_id=str(scope_id))
    assert report["capabilities"] == expected, "capability export differs from trusted replay"
    assert "capability_measurement" not in report.get("assessment_plan", {})
    if require_measured or plan.get("capability_snapshot"):
        measurement = plan.get("capability_measurement", {})
        snapshot = CapabilitySnapshot.model_validate(plan["capability_snapshot"]).model_dump()
        assert measurement.get("source_sha256") == source_digest(), "candidate source mismatch"
        assert snapshot_matches(
            snapshot,
            plan,
            scan_id=str(scan_id),
            scope_version_id=str(scope_id),
            profile=profile,
        ), "snapshot binding mismatch"
        assert snapshot["verification_ref"] == "runtime:" + canonical_sha256(measurement)
        assert snapshot["image_bindings"] == measurement["image_bindings"]
        assert all(row["probe_sha256"] == PROBE_SHA256 for row in snapshot["image_bindings"])
        assert snapshot["installed_tools"] == measurement["installed_tools"]
        assert snapshot["installation_complete"] is measurement["installation_complete"]
    if require_measured:
        for key in ("installed_tools", "executable_checks"):
            assert expected[key]["evidence_state"] == "measured", f"{key} is not measured"
            assert expected[key]["count"] is not None
    return expected


def trusted_lab_projection(settings, scan_id, report, *, require_measured=False):
    with session_scope(settings) as session:
        scan = session.get(ScanRow, UUID(str(scan_id)))
        assert scan is not None, "scan missing"
        assert scan.scope_version.lab_binding, "this verifier accepts owned lab scans only"
        plan = dict(scan.assessment_plan or {})
        scope_id = scan.scope_version_id
    return verify_capability_projection(
        plan, report, scan_id=scan_id, scope_id=scope_id, require_measured=require_measured
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-id", required=True, type=UUID)
    parser.add_argument("--output", type=Path, default=Path("runs/runtime-capability-deployed"))
    args = parser.parse_args()
    settings = Settings()
    with httpx.Client(base_url="http://127.0.0.1:8090", timeout=30) as client:
        response = client.post(
            "/api/auth/login",
            json={
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        response.raise_for_status()
        response = client.get(f"/api/scans/{args.scan_id}/export.json")
        response.raise_for_status()
        report = response.json()
    capabilities = trusted_lab_projection(settings, args.scan_id, report, require_measured=True)
    args.output.mkdir(parents=True, exist_ok=True)
    receipt = {
        "scan_id": str(args.scan_id),
        "profile": report["profile"],
        "source_sha256": source_digest(),
        "capabilities": capabilities,
        "private_measurement_exported": False,
        "limitation": "inventory and export parity; not assessment completion or qualification",
    }
    (args.output / f"{args.scan_id}.json").write_text(json.dumps(receipt, indent=2))
    print(f"{args.scan_id}: trusted capability export replay passed")


if __name__ == "__main__":
    main()
