"""Freeze an operator-selected OSV package corpus; never called by target workers."""

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from scopelens.checks.advisories import AdvisoryBundle, load_bundle

ENDPOINT = "https://api.osv.dev/v1/query"
PACKAGES = {
    "jquery": "npm:jquery",
    "bootstrap": "npm:bootstrap",
    "vue.js": "npm:vue",
    "angular": "npm:@angular/core",
    "react": "npm:react",
    "next.js": "npm:next",
    "nuxt": "npm:nuxt",
    "express": "npm:express",
    "angularjs": "npm:angular",
    "lodash": "npm:lodash",
    "axios": "npm:axios",
    "moment": "npm:moment",
    "django": "PyPI:django",
    "flask": "PyPI:flask",
    "werkzeug": "PyPI:werkzeug",
    "gunicorn": "PyPI:gunicorn",
    "tomcat": "Maven:org.apache.tomcat:tomcat-catalina",
    "jetty": "Maven:org.eclipse.jetty:jetty-server",
}


def fetch_snapshot(client, *, packages=None, max_pages=20):
    packages = PACKAGES if packages is None else packages
    records, receipts = {}, []
    total_bytes = 0
    started = time.monotonic()
    for package in sorted(set(packages.values())):
        ecosystem, name = package.split(":", 1)
        token, seen = None, set()
        for page in range(max_pages):
            if time.monotonic() - started > 180:
                raise ValueError("advisory update deadline exceeded")
            query = {"package": {"ecosystem": ecosystem, "name": name}}
            if token:
                query["page_token"] = token
            raw = bytearray()
            with client.stream("POST", ENDPOINT, json=query) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    total_bytes += len(chunk)
                    if total_bytes > 10 * 1024 * 1024:
                        raise ValueError("advisory update exceeds 10 MiB")
                    raw.extend(chunk)
            payload = json.loads(raw)
            if not isinstance(payload, dict) or not isinstance(payload.get("vulns", []), list):
                raise ValueError("malformed advisory response")
            for record in payload.get("vulns", []):
                if (
                    not isinstance(record, dict)
                    or not record.get("id")
                    or not record.get("modified")
                ):
                    raise ValueError("advisory missing identity or revision")
                old = records.get(record["id"])
                if old is None or record["modified"] >= old["modified"]:
                    records[record["id"]] = record
            token = payload.get("next_page_token")
            if token is not None and not isinstance(token, str):
                raise ValueError("invalid pagination token")
            receipts.append(
                {
                    "package": package,
                    "page": page + 1,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "records": len(payload.get("vulns", [])),
                    "complete": not bool(token),
                }
            )
            if not token:
                break
            if token in seen:
                raise ValueError("advisory pagination loop")
            seen.add(token)
        else:
            raise ValueError("advisory pagination cap reached; snapshot not published")
    now = datetime.now(UTC).isoformat()
    bundle = AdvisoryBundle(
        version="osv-" + now,
        source=ENDPOINT,
        packages=packages,
        records=[records[key] for key in sorted(records)],
        provenance={"fetched_at": now, "queries": receipts},
    )
    return bundle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as client:
        bundle = fetch_snapshot(client)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(".pending.json")
    try:
        temporary.write_text(bundle.model_dump_json(indent=2) + "\n")
        snapshot = load_bundle(temporary)
        temporary.replace(args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "path": str(args.output),
                "records": len(bundle.records),
                "packages": len(bundle.packages),
                "sha256": snapshot["sha256"],
            }
        )
    )


if __name__ == "__main__":
    main()
