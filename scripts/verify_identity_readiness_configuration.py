"""Operator-run readiness receipt for a fresh, already-approved cookie-only config.

This creates one normal scan only when invoked. It never resolves stored secrets,
performs a login recipe, refreshes scope authority or follows target redirects.
"""

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import httpx
from scripts.verify_html_identity_lab import API, get, post, wait

from scopelens.config import Settings
from scopelens.domain.capabilities import canonical_sha256
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.identities.readiness import evaluate_identity_readiness


def validate(scope, saved, scope_id):
    configuration = AssessmentConfiguration.model_validate(saved["configuration"])
    if (
        configuration.scope_version_id != scope_id
        or scope["expired"]
        or not set(scope["allowed_methods"]) <= {"GET", "HEAD"}
        or scope["allowed_check_profile"] != "authenticated-api-v1"
        or any(
            (
                configuration.permission_matrix,
                configuration.session_policies,
                configuration.workflows,
                configuration.read_probes,
                configuration.browser_workflows,
                configuration.cors_recipes,
                configuration.callback_recipes,
                configuration.templates,
                configuration.imports,
                configuration.policies,
                configuration.related_origins,
            )
        )
        or len(configuration.identities) != 1
    ):
        raise ValueError("fresh read-only cookie-only scope/configuration required")
    profile = configuration.identities[0]
    probe = profile.probe
    if (
        profile.anonymous
        or profile.login
        or not profile.supplied_headers
        or probe is None
        or probe.request.method not in {"GET", "HEAD"}
        or probe.request.json_body
        or probe.request.secret_fields
        or (profile.expires_at and profile.expires_at <= datetime.now(UTC))
        or canonical_sha256(configuration.model_dump(mode="json")) != saved["content_hash"]
    ):
        raise ValueError("fresh supplied-session identity probe required")
    return configuration


def run(args):
    settings = Settings()
    if settings.operator_password is None:
        raise RuntimeError("local operator password is not configured")
    with httpx.Client(base_url=API, timeout=30, follow_redirects=False, trust_env=False) as client:
        post(
            client,
            "/api/auth/login",
            {
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        scope = get(client, f"/api/scopes/{args.scope_version_id}").json()
        saved = get(client, f"/api/assessments/configurations/{args.configuration_id}").json()
        configuration = validate(scope, saved, args.scope_version_id)
        scan = post(
            client,
            "/api/scans",
            {
                "scope_version_id": str(args.scope_version_id),
                "assessment_configuration_id": str(args.configuration_id),
                "adaptive": False,
            },
        )
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "scan-id.txt").write_text(scan["id"] + "\n")
        terminal = wait(client, scan["id"], seconds=300)
        readiness = get(client, f"/api/academic/scans/{scan['id']}/readiness").json()
        assert readiness["configuration_hash"] == saved["content_hash"]
        observations = []
        for row in get(client, f"/api/scans/{scan['id']}/evidence").json():
            if row[
                "producer"
            ] != "reviewed_expansion_capture" or "identity_observation" not in row.get(
                "summary", ""
            ):
                continue
            assert row["trusted"] and row["origin"] == "supervisor" and not row["truncated"]
            raw = get(client, f"/api/scans/{scan['id']}/evidence/{row['id']}/download").content
            assert hashlib.sha256(raw).hexdigest() == row["content_hash"]
            artifact = json.loads(raw)
            record = artifact.get("data", {})
            if (
                artifact.get("kind") != "identity_observation"
                or record.get("kind") != "identity_readiness"
            ):
                continue
            observations.append(
                {
                    "evidence_ref": row["id"],
                    "record": record,
                    "verified": evaluate_identity_readiness(
                        configuration.identities[0],
                        record,
                        configuration_binding=saved["content_hash"],
                    ),
                }
            )
        verified = len(observations) == 1 and observations[0]["verified"]
        receipt = {
            "scan_id": scan["id"],
            "status": terminal["status"],
            "identity_verified": verified,
            "readiness": readiness,
            "observations": observations,
        }
        (args.output / "readiness-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(
            json.dumps(
                {"scan_id": scan["id"], "identity_verified": verified, "status": terminal["status"]}
            )
        )
        if not verified:
            raise RuntimeError(
                "scanner identity readiness unverified; inspect fixed diagnostics in receipt"
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope-version-id", type=UUID, required=True)
    parser.add_argument("--configuration-id", type=UUID, required=True)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args())
