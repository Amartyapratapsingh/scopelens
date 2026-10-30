"""Read-only deployed review-API gate over the existing isolated discovery pair."""

import argparse
import json
from pathlib import Path

import httpx
from scripts.verify_discovery_lab import reviewed_templates

from scopelens.config import Settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--receipts", type=Path, default=Path("runs/discovery-deployed/receipts.json")
    )
    parser.add_argument("--output", type=Path, default=Path("runs/discovery-review-deployed.json"))
    args = parser.parse_args()
    receipts = json.loads(args.receipts.read_text())
    settings, results = Settings(), []
    forbidden = {
        "baseline_value",
        "secret_ref",
        "authority",
        "provenance",
        "json_body",
        "secret_fields",
    }

    def privacy(value):
        if isinstance(value, dict):
            assert not forbidden.intersection(value)
            for child in value.values():
                privacy(child)
        elif isinstance(value, list):
            for child in value:
                privacy(child)

    with httpx.Client(
        base_url="http://127.0.0.1:8090", timeout=30, follow_redirects=False
    ) as client:
        response = client.post(
            "/api/auth/login",
            json={
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        )
        response.raise_for_status()

        def get(path):
            response = client.get(path)
            response.raise_for_status()
            return response

        for receipt in receipts:
            discovery_ids = None
            for kind in ("discovery_scan", "assessment_scan"):
                scan_id = receipt[kind]
                detail = get(f"/api/scans/{scan_id}").json()
                assert detail["target_origin"] in {
                    "http://172.28.0.19:8080",
                    "http://172.28.0.21:8080",
                }
                scope = {"id": detail["scope_version_id"]}
                templates = reviewed_templates(get, scan_id, scope)
                assert {i.location for t in templates for i in t.inputs} >= {
                    "query",
                    "form",
                    "json",
                    "path",
                }
                ids = {t.id for t in templates}
                if discovery_ids is None:
                    discovery_ids = ids
                else:
                    assert ids == discovery_ids, (
                        "assessment did not retain the discovered operations"
                    )
                history = get(f"/api/assessments/scans/{scan_id}/plans").json()
                plan_id = history["revisions"][-1]["plan"]["id"]
                endpoint = f"/api/assessments/scans/{scan_id}/plans/{plan_id}/templates"
                offset, pages, paged_ids = 0, 0, []
                while True:
                    view = get(endpoint + f"?offset={offset}&limit=3").json()
                    privacy(view)
                    assert view["plan_id"] == plan_id
                    paged_ids.extend(t["id"] for t in view["templates"])
                    pages += 1
                    if view["next_offset"] is None:
                        break
                    assert view["next_offset"] > offset
                    offset = view["next_offset"]
                assert paged_ids == sorted(ids)
                assert client.get(endpoint + "?limit=201").status_code == 422
                assert (
                    client.get(
                        f"/api/assessments/scans/{scan_id}/plans/missing/templates"
                    ).status_code
                    == 404
                )
                assert (
                    httpx.get(
                        "http://127.0.0.1:8090" + endpoint, follow_redirects=False
                    ).status_code
                    == 401
                )
                results.append(
                    {
                        "scan_id": scan_id,
                        "plan_id": plan_id,
                        "templates": len(ids),
                        "pages": pages,
                        "privacy": "passed",
                        "authentication_required": True,
                    }
                )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    print(
        json.dumps(
            {"verified_scans": len(results), "target_requests": 0, "receipt": str(args.output)}
        )
    )


if __name__ == "__main__":
    main()
