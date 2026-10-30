"""Durable nonce-scoped HTTP receipts; caller identities never come from HTTP headers.

The caller provisions an explicit callback origin and expected target egress addresses.
When scanner and target share NAT, correlation remains inconclusive. A valid signature
proves the collector observed traffic, not that the target exploited a particular flaw.
"""

import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import Boolean, Float, Integer, String, Text, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from scopelens.domain.callback import CallbackNonce, CallbackReceipt


class CallbackBase(DeclarativeBase):
    pass


class NonceRow(CallbackBase):
    __tablename__ = "callback_nonces"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    owner_id: Mapped[str] = mapped_column(String(128), index=True)
    scan_id: Mapped[str] = mapped_column(String(128), index=True)
    task_id: Mapped[str] = mapped_column(String(128))
    family: Mapped[str] = mapped_column(String(16))
    purpose: Mapped[str] = mapped_column(String(16))
    expected_peers: Mapped[str] = mapped_column(Text)
    scanner_peers: Mapped[str] = mapped_column(Text)
    created_at: Mapped[float] = mapped_column(Float)
    expires_at: Mapped[float] = mapped_column(Float, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    receipts: Mapped[int] = mapped_column(Integer, default=0)


class ReceiptRow(CallbackBase):
    __tablename__ = "callback_receipts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce_id: Mapped[str] = mapped_column(String(64), index=True)
    data: Mapped[str] = mapped_column(Text)


def _address(value: str) -> str:
    ip = ipaddress.ip_address(value)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


class CallbackService:
    def __init__(
        self,
        session_factory,
        signing_key: bytes,
        registered_origins: set[str],
        *,
        now: Callable[[], float] = time.time,
    ):
        if len(signing_key) < 32:
            raise ValueError("callback signing key must contain at least 32 bytes")
        for origin in registered_origins:
            p = urlsplit(origin)
            if (
                p.scheme not in {"http", "https"}
                or not p.hostname
                or p.username
                or p.password
                or p.path not in {"", "/"}
                or p.query
                or p.fragment
            ):
                raise ValueError("callback registration requires an exact HTTP origin")
        self.sessions = session_factory
        self.key = signing_key
        self.origins = {u.rstrip("/") for u in registered_origins}
        self.now = now

    def issue(
        self,
        *,
        owner_id: str,
        scan_id: str,
        task_id: str,
        family: str,
        purpose: str,
        callback_origin: str,
        expected_target_peers: set[str],
        scanner_peers: set[str],
        ttl_seconds: int = 60,
    ) -> CallbackNonce:
        origin = callback_origin.rstrip("/")
        expected = {_address(ip) for ip in expected_target_peers}
        scanner = {_address(ip) for ip in scanner_peers}
        if origin not in self.origins or not 1 <= ttl_seconds <= 300:
            raise ValueError("unregistered callback origin or invalid expiry")
        if not expected or not scanner or expected & scanner:
            raise ValueError("distinct known target and scanner egress addresses required")
        if family not in {"ssrf", "xxe"} or purpose not in {"positive", "negative"}:
            raise ValueError("unreviewed callback purpose/family")
        if not owner_id or not scan_id or not task_id:
            raise ValueError("owner, scan and task are required")
        token = secrets.token_urlsafe(32)
        identifier = secrets.token_hex(16)
        now = self.now()
        with self.sessions() as db:
            db.add(
                NonceRow(
                    id=identifier,
                    token_hash=hashlib.sha256(token.encode()).hexdigest(),
                    owner_id=owner_id,
                    scan_id=scan_id,
                    task_id=task_id,
                    family=family,
                    purpose=purpose,
                    expected_peers=json.dumps(sorted(expected)),
                    scanner_peers=json.dumps(sorted(scanner)),
                    created_at=now,
                    expires_at=now + ttl_seconds,
                    revoked=False,
                    receipts=0,
                )
            )
            db.commit()
        return CallbackNonce(
            id=identifier,
            scan_id=scan_id,
            task_id=task_id,
            family=family,
            purpose=purpose,
            url=origin + "/callback/" + token,
            expires_at=now + ttl_seconds,
        )

    def _signature(self, data: dict) -> str:
        return hmac.new(
            self.key,
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, receipt: CallbackReceipt) -> bool:
        raw = receipt.model_dump(exclude={"signature"})
        return hmac.compare_digest(receipt.signature, self._signature(raw))

    def capture(
        self, token: str, *, peer: str, method: str, protocol: str = "http"
    ) -> CallbackReceipt | None:
        if (
            not 20 <= len(token) <= 64
            or method not in {"GET", "HEAD", "POST"}
            or protocol not in {"http", "dns"}
        ):
            return None
        try:
            peer = _address(peer)
        except ValueError:
            return None
        with self.sessions() as db:
            row = db.scalar(
                select(NonceRow)
                .where(NonceRow.token_hash == hashlib.sha256(token.encode()).hexdigest())
                .with_for_update()
            )
            now = self.now()
            if not row or row.revoked or row.expires_at <= now or row.receipts >= 4:
                return None
            expected, scanner = (
                set(json.loads(row.expected_peers)),
                set(json.loads(row.scanner_peers)),
            )
            source = "scanner" if peer in scanner else "target" if peer in expected else "unknown"
            data = dict(
                id=secrets.token_hex(16),
                nonce_id=row.id,
                scan_id=row.scan_id,
                task_id=row.task_id,
                at=now,
                protocol=protocol,
                peer=peer,
                source=source,
                method=method,
            )
            receipt = CallbackReceipt(**data, signature=self._signature(data))
            row.receipts += 1
            db.add(ReceiptRow(id=receipt.id, nonce_id=row.id, data=receipt.model_dump_json()))
            db.commit()
            return receipt

    def receipts(
        self, nonce_id: str, *, owner_id: str, scan_id: str, task_id: str
    ) -> list[CallbackReceipt]:
        with self.sessions() as db:
            nonce = db.get(NonceRow, nonce_id)
            if not nonce or (nonce.owner_id, nonce.scan_id, nonce.task_id) != (
                owner_id,
                scan_id,
                task_id,
            ):
                raise PermissionError("callback does not belong to this owner/scan/task")
            rows = db.scalars(select(ReceiptRow).where(ReceiptRow.nonce_id == nonce_id)).all()
            return [CallbackReceipt.model_validate_json(row.data) for row in rows]

    def revoke_scan(self, *, owner_id: str, scan_id: str):
        with self.sessions() as db:
            rows = db.scalars(
                select(NonceRow)
                .where(NonceRow.owner_id == owner_id, NonceRow.scan_id == scan_id)
                .with_for_update()
            ).all()
            for row in rows:
                row.revoked = True
            db.commit()

    def revoke_nonce(self, nonce_id: str, *, owner_id: str):
        with self.sessions() as db:
            row = db.get(NonceRow, nonce_id)
            if row is None or row.owner_id != owner_id:
                raise PermissionError("nonce not owned")
            row.revoked = True
            db.commit()


def callback_router(service: CallbackService) -> APIRouter:
    router = APIRouter(include_in_schema=False)

    @router.api_route("/callback/{token}", methods=["GET", "HEAD", "POST"])
    def receive(token: str, request: Request):
        if request.client is None:
            raise HTTPException(404)
        # Do not trust forwarded IP headers. Deploy directly or behind an authenticated
        # collector relay that supplies peer identity through a separate trusted channel.
        result = service.capture(token, peer=request.client.host, method=request.method)
        if result is None:
            raise HTTPException(404)
        return Response(status_code=204, headers={"Cache-Control": "no-store"})

    return router
