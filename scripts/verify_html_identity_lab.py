"""Deployed cookie-only HTML identity gate against an exact owned fixture.

No customer target, academic mutation or automatic CAPTCHA/login recipe is used.
Only the synthetic fixture's session is seeded locally, outside scanner execution.
"""

import argparse
import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from scopelens.config import Settings
from scopelens.domain.capabilities import canonical_sha256
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.identities.readiness import evaluate_identity_readiness

API = "http://127.0.0.1:8090"
ORIGIN = "http://172.28.0.23:8080"
TERMINAL = {"completed", "completed_partial", "failed", "cancelled"}


def post(client, route, data):
    response = client.post(route, json=data)
    if response.is_error:
        # Request bodies can contain secrets. Never print them or API error bodies.
        raise RuntimeError(f"local API rejected {route}: HTTP {response.status_code}")
    return response.json()


def get(client, route):
    response = client.get(route)
    if response.is_error:
        raise RuntimeError(f"local API rejected {route}: HTTP {response.status_code}")
    return response


def synthetic_cookie():
    code = """import json,urllib.request
request=urllib.request.Request('http://127.0.0.1:8080/login',
 data=json.dumps({'username':'student_a','password':'synthetic-only'}).encode(),
 headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=5) as response:
 print(response.headers['Set-Cookie'].split(';',1)[0])
"""
    result = subprocess.run(
        ["docker", "exec", "scopelens-labs-academic-b", "python", "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    cookie = result.stdout.strip()
    if result.returncode or not cookie.startswith("sid=") or "\n" in cookie:
        raise RuntimeError("synthetic fixture session seeding failed")
    return cookie


def wait(client, scan_id, seconds=300):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        scan = get(client, f"/api/scans/{scan_id}").json()
        if scan["status"] in TERMINAL:
            return scan
        time.sleep(2)
    post(client, f"/api/scans/{scan_id}/cancel", {})
    raise RuntimeError("owned fixture gate exceeded its deadline; cancellation requested")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", choices=("academic", "https"), default="academic")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    origin = ORIGIN if args.fixture == "academic" else "https://172.28.0.12:8443"
    service = "labs-academic-b" if args.fixture == "academic" else "labs-good"
    port = 8080 if args.fixture == "academic" else 8443
    path = "/identity-home" if args.fixture == "academic" else "/app/identity-home"
    account = b"student_a" if args.fixture == "academic" else b"synthetic-https-identity"
    settings = Settings()
    if settings.operator_password is None:
        raise RuntimeError("local operator password must be configured")
    output = args.output or Path(
        "runs/html-identity-deployed"
        if args.fixture == "academic"
        else "runs/https-identity-deployed"
    )
    output.mkdir(parents=True, exist_ok=True)
    expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    summaries = []
    with httpx.Client(base_url=API, timeout=30, follow_redirects=False) as client:
        post(
            client,
            "/api/auth/login",
            {
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        scope = post(
            client,
            "/api/scopes",
            {
                "authority_domain": "lab",
                "scheme": "http" if args.fixture == "academic" else "https",
                "lab_service": service,
                "lab_port": port,
                "allowed_path_prefixes": ["/"] if args.fixture == "academic" else ["/app"],
                "allowed_methods": ["GET", "HEAD"],
                "allowed_check_profile": "authenticated-api-v1",
                "authorization_expires_at": expires,
                "owner_note": "Synthetic cookie-only HTML session readiness gate; read-only",
            },
        )
        assert scope["origin"] == origin
        for label, cookie, expected in (
            (
                "valid",
                synthetic_cookie()
                if args.fixture == "academic"
                else "identity-ready=synthetic-https-valid",
                True,
            ),
            ("invalid", "sid=synthetic-invalid-session", False),
        ):
            credential = post(
                client,
                "/api/assessments/credentials",
                {
                    "scope_version_id": scope["id"],
                    "value": cookie,
                    "expires_at": expires,
                },
            )
            config = AssessmentConfiguration.model_validate(
                {
                    "scope_version_id": scope["id"],
                    "identities": [
                        {
                            "id": "student-test",
                            "role": "student",
                            "supplied_headers": {"Cookie": credential["reference"]},
                            "expires_at": expires,
                            "probe": {
                                "request": {"url": origin + path},
                                "response_format": "html",
                                "html_selector": ".user-menu .dropdown-toggle span.hidden-xs",
                                "expected_identity": "sha256:"
                                + hashlib.sha256(account).hexdigest(),
                            },
                        }
                    ],
                }
            )
            frozen = config.model_dump(mode="json")
            saved = post(client, "/api/assessments/configurations", frozen)
            assert saved["content_hash"] == canonical_sha256(frozen)
            scan = post(
                client,
                "/api/scans",
                {
                    "scope_version_id": scope["id"],
                    "assessment_configuration_id": saved["id"],
                    "adaptive": False,
                },
            )
            print(
                json.dumps({"case": label, "scan_id": scan["id"], "state": "started"}), flush=True
            )
            terminal = wait(client, scan["id"])
            readiness = get(client, f"/api/academic/scans/{scan['id']}/readiness").json()
            assert readiness["configuration_hash"] == saved["content_hash"]
            assert len(readiness["actors"]) == 1
            observations = []
            entry_urls = {"crawler": [], "browser": []}
            for row in get(client, f"/api/scans/{scan['id']}/evidence").json():
                if row["producer"] not in {
                    "reviewed_expansion_capture",
                    "reviewed_crawler_capture",
                    "reviewed_browser_capture",
                }:
                    continue
                assert row["trusted"] and row["origin"] == "supervisor"
                assert not row["truncated"]
                raw = get(client, f"/api/scans/{scan['id']}/evidence/{row['id']}/download").content
                assert hashlib.sha256(raw).hexdigest() == row["content_hash"]
                artifact = json.loads(raw)
                record = artifact.get("data", {})
                if (
                    artifact.get("kind") == "response"
                    and row["producer"] == "reviewed_crawler_capture"
                ):
                    entry_urls["crawler"].append(record.get("url"))
                if (
                    artifact.get("kind") == "browser_state"
                    and row["producer"] == "reviewed_browser_capture"
                ):
                    entry_urls["browser"].append(record.get("url"))
                if record.get("kind") == "identity_readiness":
                    assert artifact["kind"] == "identity_observation"
                    verified = evaluate_identity_readiness(
                        config.identities[0],
                        record,
                        configuration_binding=saved["content_hash"],
                    )
                    observations.append(
                        {
                            "evidence_ref": row["id"],
                            "record": record,
                            "replayed_identity_verified": verified,
                        }
                    )
            receipt = {
                "case": label,
                "scan_id": scan["id"],
                "status": terminal["status"],
                "readiness": readiness,
                "observations": observations,
                "entry_urls": entry_urls,
            }
            serialized = json.dumps(receipt, indent=2)
            assert cookie not in serialized and account.decode() not in serialized
            (output / f"{label}.json").write_text(serialized + "\n")
            assert len(observations) == 1
            assert observations[0]["replayed_identity_verified"] is expected
            assert readiness["actors"][0]["identity_evidence"] == (
                "verified_probe" if expected else "failed_probe"
            )
            assert readiness["coverage"]["configured"] == readiness["coverage"]["proven"] == 0
            if args.fixture == "https":
                assert origin + "/app" in entry_urls["crawler"]
                assert origin + "/app" in entry_urls["browser"]
                assert all(
                    isinstance(url, str) and url.startswith(origin + "/app")
                    for urls in entry_urls.values()
                    for url in urls
                )
            summary = {
                "case": label,
                "scan_id": scan["id"],
                "identity_verified": expected,
                "trusted_observations": len(observations),
            }
            summaries.append(summary)
            print(json.dumps(summary), flush=True)
    (output / "summary.json").write_text(json.dumps(summaries, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, ValueError, KeyError, OSError, httpx.HTTPError):
        # Partial receipts survive; errors cannot print captured cookies or credentials.
        raise SystemExit(
            "HTML identity lab gate failed; inspect local service state and receipts"
        ) from None
