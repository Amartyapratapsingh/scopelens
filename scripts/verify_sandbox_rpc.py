"""Real VM-to-broker RPC against an explicitly bound lab, including revocation."""

import json
import subprocess
from pathlib import Path

from sqlalchemy import select

from scopelens.broker.policy import issue_egress_token, revoke_egress
from scopelens.config import Settings
from scopelens.execution.leases import acquire_lease, release_lease
from scopelens.execution.sandbox import ScriptRequest, execute
from scopelens.persistence.models import ScanRow, ScopeVersionRow
from scopelens.persistence.repositories import create_scan_row
from scopelens.persistence.session import session_scope

settings = Settings()
ca = subprocess.run(
    [
        "docker",
        "exec",
        "scopelens-dev-supervisor-1",
        "cat",
        "/var/lib/mitmproxy/mitmproxy-ca-cert.pem",
    ],
    capture_output=True,
    check=True,
).stdout.decode()
with session_scope(settings) as db:
    scope = db.scalar(
        select(ScopeVersionRow)
        .where(ScopeVersionRow.authority_domain == "lab", ScopeVersionRow.host == "172.28.0.11")
        .order_by(ScopeVersionRow.created_at.desc())
    )
    assert scope
    scan = create_scan_row(
        db, operator_id=scope.operator_id, scope_version=scope, score_version=settings.score_version
    )
    scan_id = scan.id
    scan.status = "testing"
    lease = acquire_lease(db, scan_id=scan_id, holder="sandbox-rpc-proof", ttl_seconds=300)
    token = issue_egress_token(db, scan=scan)
    origin = scan.target_origin

source = """import sys,json
config=json.loads(sys.stdin.readline())
for url in config["urls"]:
 print("SCOPELENS_HTTP "+json.dumps({"method":"GET","url":url}),flush=True)
 reply=json.loads(sys.stdin.readline())
 print(json.dumps({"state":reply.get("state"),"status":reply.get("status")}),flush=True)
"""
request = ScriptRequest(
    scan_id=scan_id,
    language="python",
    source=source,
    artifacts={"urls": [origin + "/", "http://redis:6379/", origin + "/", origin + "/"]},
    network="lab-proxy",
    authority="lab",
    egress_token=token,
    proxy_ca_pem=ca,
)
try:
    result = execute(request)
    statuses = result["proxy_requests"]
    assert result["trusted"] is False and result["state"] == "completed", result
    assert statuses[0]["status"] == 200, statuses
    assert statuses[1]["status"] == 403, statuses
    assert statuses[2]["status"] == 200, statuses
    assert statuses[3]["state"] == "denied", statuses
    with session_scope(settings) as db:
        scan = db.get(ScanRow, scan_id)
        revoke_egress(db, scan=scan)
    request.artifacts = {"urls": [origin + "/"]}
    revoked = execute(request)
    assert revoked["proxy_requests"][0]["state"] == "denied", revoked
    Path("runs/m4-verification/sandbox-rpc.json").write_text(
        json.dumps(
            {
                "scan_id": str(scan_id),
                "allowed_and_denied": statuses,
                "revoked": revoked["proxy_requests"],
                "trusted": False,
            },
            indent=2,
        )
    )
    print(
        "PASS: VM lab RPC, cross-scope deny, request cap, revoked capability; stdout remains untrusted"
    )
finally:
    with session_scope(settings) as db:
        scan = db.get(ScanRow, scan_id)
        revoke_egress(db, scan=scan)
        scan.status = "cancelled"
        release_lease(db, scan_id=scan_id, holder=lease.holder, fencing_token=lease.fencing_token)
