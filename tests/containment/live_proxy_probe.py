#!/usr/bin/env python3
"""Live proxy probe: what a worker can and cannot reach through the broker.

Run inside the *supervisor* container (`make verify-proxy-live`), which has database
access and the application code:

    docker compose -f deploy/docker-compose.dev.yml exec -T supervisor \\
        python /probe/live_proxy_probe.py

Why this exists, and why it is separate from `proxy_bypass.py`
==============================================================

`proxy_bypass.py` proves the proxy *mechanism* is closed, with a stub policy, offline and
deterministically. This proves the **live** deployment behaves: real policy service, real
database, real scope, real Redis and PostgreSQL on the control network.

It stands up a real scan whose scope is the lab fixture, mints a real egress token, holds a
real coordinator lease, and then tries to tunnel to Redis and PostgreSQL — the two services
the review named. Those must be refused for being outside the scan's scope, even though the
proxy container can reach them.

It also proves the positive case, so a blanket denial cannot masquerade as containment: the
scope's own host must still be reachable through the same token.

Exit code 0 means every case passed.
"""

from __future__ import annotations

import socket
import sys
import time
from datetime import UTC, datetime, timedelta

import httpx

from scopelens.broker.policy import revoke_egress
from scopelens.config import Settings
from scopelens.domain.lab import LabBinding, load_lab_services
from scopelens.domain.scope import LabScopeCreate
from scopelens.execution.leases import acquire_lease
from scopelens.persistence.models import ScanRow
from scopelens.persistence.repositories import (
    create_scan_row,
    create_scope_version,
    get_operator_by_username,
)
from scopelens.persistence.session import session_scope

_failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}{f' — {detail}' if detail else ''}")
        _failures.append(label)


def connect_via_proxy(
    proxy_host: str, proxy_port: int, target_host: str, target_port: int, token: str
) -> str:
    """Attempt a CONNECT tunnel to ``target_host:target_port``. Returns the status line."""
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
    except OSError as exc:
        return f"proxy unreachable: {exc}"

    sock.sendall(
        f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
        f"Host: {target_host}:{target_port}\r\n"
        f"x-scopelens-egress: {token}\r\n\r\n".encode()
    )
    sock.settimeout(8)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(1)
            if not chunk:
                break
            buf += chunk
    except (TimeoutError, OSError):
        pass
    finally:
        sock.close()
    return buf.split(b"\r\n", 1)[0].decode(errors="replace") or "no response"


def run() -> int:
    settings = Settings()

    with session_scope(settings) as session:
        operator = get_operator_by_username(session, settings.operator_username)
        if operator is None:
            print("FAIL: the operator account is not seeded; run `make seed-operator`")
            return 1

        service = load_lab_services(settings.lab_services_file).get("labs-good")
        binding = LabBinding(
            service=service.id,
            address=service.addresses[0],
            port=8443,
            environment=service.environment,
        )
        load_lab_services(settings.lab_services_file).validate_binding(binding)
        scope = create_scope_version(
            session,
            operator_id=operator.id,
            payload=LabScopeCreate(
                lab_service=service.id,
                scheme="https",
                lab_port=8443,
                allowed_path_prefixes=["/"],
                excluded_paths=["/blocked"],
                authorization_expires_at=datetime.now(UTC) + timedelta(days=1),
            ),
            scheme="https",
            host=binding.address,
            port=binding.port,
            lab_binding=binding,
        )
        # A probe ledger entry, without dispatching an unrelated scanner worker.
        scan = create_scan_row(
            session,
            operator_id=operator.id,
            scope_version=scope,
            score_version=settings.score_version,
        )
        session.flush()

        from scopelens.broker.policy import issue_egress_token

        token = issue_egress_token(session, scan=scan)
        # A live lease: egress is admitted only while a coordinator holds the scan, so
        # without this every probe would be refused for the wrong reason.
        acquire_lease(session, scan_id=scan.id, holder="live-probe", ttl_seconds=300)
        scan_id = scan.id
        session.commit()

    print(f"probe scan {scan_id} (scope service: {service.id})")

    try:
        proxy_host, proxy_port = settings.proxy_host, settings.proxy_http_port
        print(f"probing through {proxy_host}:{proxy_port}")

        print("case 1: the control-plane services the review named must be out of scope")
        for label, host, port in (
            ("Redis", "redis", 6379),
            ("PostgreSQL", "postgres", 5432),
        ):
            status = connect_via_proxy(proxy_host, proxy_port, host, port, token)
            check(f"CONNECT to {label} ({host}:{port}) is refused", "403" in status, status)

        print("case 2: an unknown token is refused whatever the destination")
        status = connect_via_proxy(proxy_host, proxy_port, "redis", 6379, "not-a-real-token")
        check("CONNECT with an unknown token is refused", "403" in status, status)

        print(
            "case 3: the scope's own host is still reachable — the boundary is not a blanket denial"
        )
        with httpx.Client(
            proxy=f"http://{token}:@{proxy_host}:{proxy_port}",
            headers={"x-scopelens-egress": token},
            verify=str(settings.proxy_ca_path),
            timeout=15,
            trust_env=False,
        ) as client:
            response = client.get(f"https://{binding.address}:{binding.port}/")
            check(
                "authorized fixture returns its real HTTP body",
                response.status_code == 200 and "ScopeLens" in response.text,
                str(response.status_code),
            )
            for path in ("/blocked?view=1", "/%62locked", "/%2562locked", "/BLOCKED?x=1"):
                time.sleep(0.6)
                response = client.get(f"https://{binding.address}:{binding.port}{path}")
                check(
                    f"excluded path remains denied: {path}",
                    response.status_code == 403
                    and response.json().get("reason") == "path_explicitly_excluded",
                    response.text[:300],
                )

        print()
        if _failures:
            print(f"FAIL — {len(_failures)} case(s) failed:")
            for name in _failures:
                print(f"  - {name}")
            return 1

        print("PASS — a worker's token cannot tunnel to Redis or PostgreSQL through the broker")
        return 0
    finally:
        with session_scope(settings) as session:
            scan = session.get(ScanRow, scan_id)
            revoke_egress(session, scan=scan)
            scan.cancel_requested_at = datetime.now(UTC)
            scan.status = "cancelled"
            scan.status_reason = "containment probe finished; capability revoked"
            scan.finished_at = datetime.now(UTC)


if __name__ == "__main__":
    sys.exit(run())
