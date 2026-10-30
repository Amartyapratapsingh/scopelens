"""Trusted callback control and independent proof over durable collector records.

The public receiver only captures transport peer identity. This module belongs in the
private control/supervisor process, never in a scanner worker with the signing key.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.sax.saxutils import escape, quoteattr

import httpx
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Float, ForeignKey, Integer, String, Text, select, text
from sqlalchemy.orm import Mapped, mapped_column

from scopelens.callbacks.probes import CallbackProbeRecipe, evaluate_callback_assessment
from scopelens.callbacks.service import CallbackBase, CallbackService, NonceRow, _address
from scopelens.domain.callback import CallbackAssessment


class CallbackClosureRow(CallbackBase):
    """First authoritative revocation closes the receipt observation window."""

    __tablename__ = "callback_closures"
    nonce_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("callback_nonces.id", ondelete="CASCADE"), primary_key=True
    )
    owner_id: Mapped[str] = mapped_column(String(128))
    scan_id: Mapped[str] = mapped_column(String(128), index=True)
    task_id: Mapped[str] = mapped_column(String(128))
    at: Mapped[float] = mapped_column(Float)
    signature: Mapped[str] = mapped_column(String(64))


class CallbackDispatchIntentRow(CallbackBase):
    """Private immutable request commitment created before releasing the nonce URL."""

    __tablename__ = "callback_dispatch_intents"
    nonce_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("callback_nonces.id", ondelete="CASCADE"), primary_key=True
    )
    owner_id: Mapped[str] = mapped_column(String(128))
    scan_id: Mapped[str] = mapped_column(String(128), index=True)
    task_id: Mapped[str] = mapped_column(String(128))
    recipe_digest: Mapped[str] = mapped_column(String(64))
    callback_url: Mapped[str] = mapped_column(Text)
    method: Mapped[str] = mapped_column(String(16))
    url_sha256: Mapped[str] = mapped_column(String(64))
    body_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(Float)


class CallbackDispatchRecordRow(CallbackBase):
    """Only the trusted broker writes attempts and actual upstream response metadata."""

    __tablename__ = "callback_dispatch_records"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("callback_dispatch_intents.nonce_id", ondelete="CASCADE"), index=True
    )
    owner_id: Mapped[str] = mapped_column(String(128))
    scan_id: Mapped[str] = mapped_column(String(128), index=True)
    task_id: Mapped[str] = mapped_column(String(128))
    sent_at: Mapped[float] = mapped_column(Float)
    response_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)


def _url_digest(url):
    # Apply the same HTTPX normalization as the fixed worker. Do not unquote paths.
    return hashlib.sha256(str(httpx.URL(url)).encode()).hexdigest()


def _closure_data(row):
    return {
        "kind": "callback_closure",
        "nonce_id": row.nonce_id,
        "owner_id": row.owner_id,
        "scan_id": row.scan_id,
        "task_id": row.task_id,
        "at": row.at,
    }


class FrozenCallbackTask(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    owner_id: str = Field(min_length=1, max_length=128)
    scan_id: str = Field(min_length=1, max_length=128)
    recipe_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,48}$")
    recipe: CallbackProbeRecipe

    @property
    def recipe_digest(self):
        value = self.recipe.model_dump(mode="json")
        value["expected_target_peers"] = sorted(value["expected_target_peers"])
        value["scanner_peers"] = sorted(value["scanner_peers"])
        return hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @property
    def task_id(self):
        return "callback:" + self.recipe_id + ":" + self.recipe_digest


class CallbackCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operation: Literal["issue", "query", "revoke", "verify"]
    recipe_id: str
    purpose: Literal["negative", "positive"] | None = None
    nonce_id: str | None = None
    receipt_id: str | None = None


class CallbackDispatchEvidence(BaseModel):
    """Trusted request capture, reconstructed by the supervisor from a broker artifact.

    Never construct this from the worker's assessment verdict or accept its evidence ID.
    callback_url identifies the issued nonce by its stored token hash. Bodies need not be
    retained: only the digest of the exact reviewed XML request is required.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)
    nonce_id: str
    callback_url: str
    method: str
    url: str
    body_sha256: str
    response_status: int
    evidence_ref: str
    sent_at: float


def _receipt_digest(receipt):
    return hashlib.sha256(
        json.dumps(receipt.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class CallbackRuntime:
    def __init__(self, service: CallbackService):
        self.service = service
        self._issue_lock = threading.Lock()

    @contextmanager
    def _serialized_issue(self, task):
        # PostgreSQL advisory locking covers separate control-service processes. SQLite
        # is supported only for local fixtures; the local lock covers their threads.
        with self._issue_lock, self.service.sessions() as db:
            if db.bind.dialect.name == "postgresql":
                key = int.from_bytes(
                    hashlib.sha256(
                        (task.owner_id + ":" + task.scan_id + ":" + task.task_id).encode()
                    ).digest()[:8],
                    "big",
                    signed=True,
                )
                db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
            yield db

    def _nonce(self, task, nonce_id):
        with self.service.sessions() as db:
            row = db.get(NonceRow, nonce_id)
            if row is None or (row.owner_id, row.scan_id, row.task_id, row.family) != (
                task.owner_id,
                task.scan_id,
                task.task_id,
                task.recipe.family,
            ):
                raise PermissionError("callback nonce binding mismatch")
            db.expunge(row)
            return row

    def handle(
        self, task: FrozenCallbackTask, command: CallbackCommand, *, admit: Callable[[], bool]
    ):
        """Caller loads task from frozen configuration and authenticates current capability.

        `admit` must check owner, scan epoch, active task/lease, expiry and cancellation on
        every call; worker-provided identity or configuration cannot select the task.
        """
        if command.recipe_id != task.recipe_id or not admit():
            raise PermissionError("callback task authority unavailable")
        if command.operation == "issue":
            if command.purpose is None or command.nonce_id or command.receipt_id:
                raise ValueError("issue requires only reviewed purpose")
            with self._serialized_issue(task) as db:
                if not admit():
                    raise PermissionError("callback task authority expired while waiting")
                existing = db.scalars(
                    select(NonceRow).where(
                        NonceRow.owner_id == task.owner_id,
                        NonceRow.scan_id == task.scan_id,
                        NonceRow.task_id == task.task_id,
                    )
                ).all()
                expected = ["negative", "positive", "positive"]
                if len(existing) >= 3 or command.purpose != expected[len(existing)]:
                    raise PermissionError("callback issuance sequence exhausted or invalid")
                recipe = task.recipe
                nonce = self.service.issue(
                    owner_id=task.owner_id,
                    scan_id=task.scan_id,
                    task_id=task.task_id,
                    family=recipe.family,
                    purpose=command.purpose,
                    callback_origin=recipe.callback_origin,
                    expected_target_peers=set(recipe.expected_target_peers),
                    scanner_peers=set(recipe.scanner_peers),
                    ttl_seconds=60,
                )
                expected_url, expected_body = _expected_request(recipe, nonce.url, command.purpose)
                db.add(
                    CallbackDispatchIntentRow(
                        nonce_id=nonce.id,
                        owner_id=task.owner_id,
                        scan_id=task.scan_id,
                        task_id=task.task_id,
                        recipe_digest=task.recipe_digest,
                        callback_url=nonce.url,
                        method=recipe.method,
                        url_sha256=_url_digest(expected_url),
                        body_sha256=hashlib.sha256(expected_body).hexdigest(),
                        created_at=self.service.now(),
                    )
                )
                db.commit()
            return {"allowed": True, "nonce": nonce.model_dump()}
        if not command.nonce_id or command.purpose:
            raise ValueError("nonce operation requires exact nonce ID")
        self._nonce(task, command.nonce_id)
        if command.operation == "revoke":
            with self.service.sessions() as db:
                row = db.scalar(
                    select(NonceRow).where(NonceRow.id == command.nonce_id).with_for_update()
                )
                if not row.revoked:
                    row.revoked = True
                    closure = CallbackClosureRow(
                        nonce_id=row.id,
                        owner_id=task.owner_id,
                        scan_id=task.scan_id,
                        task_id=task.task_id,
                        at=self.service.now(),
                    )
                    closure.signature = self.service._signature(_closure_data(closure))
                    db.add(closure)
                    db.commit()
            return {"allowed": True}
        receipts = self.service.receipts(
            command.nonce_id, owner_id=task.owner_id, scan_id=task.scan_id, task_id=task.task_id
        )
        if command.operation == "query":
            return {"allowed": True, "receipts": [r.model_dump() for r in receipts]}
        receipt = next((r for r in receipts if r.id == command.receipt_id), None)
        if receipt is None:
            raise PermissionError("receipt is not stored for this nonce")
        return {
            "allowed": True,
            "valid": self.service.verify(receipt),
            "receipt_digest": _receipt_digest(receipt),
        }

    def bind_request(self, scan_id: str, method: str, url: str, body_hash: str):
        """Private broker entrypoint, after normal scope/lease/epoch authorization.

        Every matching attempt is retained. A retry makes later proof inconclusive.
        Non-matching ordinary traffic returns None; it receives no callback proof credit.
        """
        with self.service.sessions() as db:
            intent = db.scalar(
                select(CallbackDispatchIntentRow)
                .where(
                    CallbackDispatchIntentRow.scan_id == scan_id,
                    CallbackDispatchIntentRow.method == method,
                    CallbackDispatchIntentRow.url_sha256 == _url_digest(url),
                    CallbackDispatchIntentRow.body_sha256 == body_hash,
                )
                .with_for_update()
            )
            if intent is None:
                return None
            nonce = db.get(NonceRow, intent.nonce_id)
            now = self.service.now()
            if nonce is None or nonce.revoked or not nonce.created_at <= now < nonce.expires_at:
                raise PermissionError("callback request authority expired")
            row = CallbackDispatchRecordRow(
                id=uuid.uuid4().hex,
                nonce_id=intent.nonce_id,
                owner_id=intent.owner_id,
                scan_id=intent.scan_id,
                task_id=intent.task_id,
                sent_at=now,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            db.expunge(row)
            return row

    def record_response(self, scan_id: str, dispatch_id: str, response_status: int):
        """Private broker entrypoint; never expose this operation to worker RPC."""
        if not 100 <= response_status <= 599:
            raise ValueError("invalid upstream response status")
        with self.service.sessions() as db:
            row = db.scalar(
                select(CallbackDispatchRecordRow)
                .where(
                    CallbackDispatchRecordRow.id == dispatch_id,
                    CallbackDispatchRecordRow.scan_id == scan_id,
                )
                .with_for_update()
            )
            if row is None or row.response_at is not None:
                raise PermissionError("callback dispatch response unavailable or already recorded")
            row.response_status = response_status
            row.response_at = self.service.now()
            if row.response_at < row.sent_at:
                raise PermissionError("callback response predates dispatch")
            db.commit()
            db.refresh(row)
            db.expunge(row)
            return row

    def stored_dispatch_evidence(self, task: FrozenCallbackTask):
        """Reconstruct proof inputs exclusively from durable trusted broker records.

        The reference must be connected to the supervisor's evidence store by its caller.
        Private callback URLs must never be serialized into a customer report.
        """
        with self.service.sessions() as db:
            intents = db.scalars(
                select(CallbackDispatchIntentRow)
                .where(
                    CallbackDispatchIntentRow.owner_id == task.owner_id,
                    CallbackDispatchIntentRow.scan_id == task.scan_id,
                    CallbackDispatchIntentRow.task_id == task.task_id,
                )
                .order_by(CallbackDispatchIntentRow.created_at, CallbackDispatchIntentRow.nonce_id)
            ).all()
            if len(intents) != 3:
                raise ValueError("callback dispatch sequence incomplete")
            evidence = []
            for intent in intents:
                records = db.scalars(
                    select(CallbackDispatchRecordRow).where(
                        CallbackDispatchRecordRow.nonce_id == intent.nonce_id,
                    )
                ).all()
                if len(records) != 1:
                    raise ValueError("callback dispatch missing or repeated")
                row = records[0]
                if (
                    (row.owner_id, row.scan_id, row.task_id)
                    != (task.owner_id, task.scan_id, task.task_id)
                    or row.response_at is None
                    or row.response_status is None
                ):
                    raise ValueError("callback response incomplete or binding mismatch")
                nonce = self._nonce(task, intent.nonce_id)
                expected_url, body = _expected_request(
                    task.recipe, intent.callback_url, nonce.purpose
                )
                if (
                    intent.recipe_digest != task.recipe_digest
                    or intent.method != task.recipe.method
                    or intent.url_sha256 != _url_digest(expected_url)
                    or intent.body_sha256 != hashlib.sha256(body).hexdigest()
                ):
                    raise ValueError("callback request commitment mismatch")
                evidence.append(
                    CallbackDispatchEvidence(
                        nonce_id=intent.nonce_id,
                        callback_url=intent.callback_url,
                        method=intent.method,
                        url=expected_url,
                        body_sha256=intent.body_sha256,
                        response_status=row.response_status,
                        evidence_ref="callback-dispatch:" + row.id,
                        sent_at=row.sent_at,
                    )
                )
            return sorted(
                evidence,
                key=lambda item: (
                    item.sent_at,
                    self._nonce(task, item.nonce_id).purpose != "negative",
                ),
            )


def create_callback_runtime(
    session_factory, *, collector_origins: set[str], signing_key: bytes, now=None
):
    if not collector_origins:
        raise ValueError("explicit operator callback collector origins required")
    kwargs = {"now": now} if now is not None else {}
    return CallbackRuntime(
        CallbackService(session_factory, signing_key, collector_origins, **kwargs)
    )


def _expected_request(recipe, callback_url, purpose):
    if recipe.family == "ssrf":
        p = urlsplit(recipe.target_url)
        value = (
            callback_url
            if purpose == "positive"
            else callback_url.replace("http", "scopelens-inert", 1)
        )
        pairs = [
            (k, value if k == recipe.parameter else v)
            for k, v in parse_qsl(p.query, keep_blank_values=True)
        ]
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), "")), b""
    root = recipe.xml_root
    body = (
        f'<?xml version="1.0"?><{root}>{escape(callback_url)}</{root}>'
        if purpose == "negative"
        else f'<?xml version="1.0"?><!DOCTYPE {root} [<!ENTITY scopelens SYSTEM {quoteattr(callback_url)}>]><{root}>&scopelens;</{root}>'
    )
    return recipe.target_url, body.encode()


def evaluate_stored_callback_proof(
    runtime, task, dispatches, *, trusted_refs: set[str], finished_at: float
):
    """Recompute proof; no worker verdict/receipt fields are accepted as authority."""
    service = runtime.service
    state, reason = "inconclusive", "Complete independently captured callback sequence required"
    refs, nonce_ids = [], []
    try:
        if len(dispatches) != 3 or len({d.nonce_id for d in dispatches}) != 3:
            raise ValueError(reason)
        expected_peers = {_address(p) for p in task.recipe.expected_target_peers}
        scanner_peers = {_address(p) for p in task.recipe.scanner_peers}
        if not expected_peers or not scanner_peers or expected_peers & scanner_peers:
            raise ValueError("Distinct attributable scanner and target egress required")
        previous = float("-inf")
        for index, dispatch in enumerate(dispatches):
            if dispatch.evidence_ref not in trusted_refs:
                raise ValueError("Trusted broker request evidence required")
            nonce = runtime._nonce(task, dispatch.nonce_id)
            purpose = "negative" if index == 0 else "positive"
            url = urlsplit(dispatch.callback_url)
            token = url.path.removeprefix("/callback/")
            if (
                nonce.purpose != purpose
                or nonce.family != task.recipe.family
                or set(json.loads(nonce.expected_peers)) != expected_peers
                or set(json.loads(nonce.scanner_peers)) != scanner_peers
                or f"{url.scheme}://{url.netloc}" != task.recipe.callback_origin.rstrip("/")
                or url.query
                or url.fragment
                or not url.path.startswith("/callback/")
                or hashlib.sha256(token.encode()).hexdigest() != nonce.token_hash
                or not nonce.created_at <= dispatch.sent_at < nonce.expires_at
                or dispatch.sent_at < previous
                or not dispatch.sent_at <= finished_at
                or not nonce.revoked
            ):
                raise ValueError("Nonce recipe/purpose/time/closed-window binding mismatch")
            expected_url, expected_body = _expected_request(
                task.recipe, dispatch.callback_url, purpose
            )
            if (
                dispatch.method != task.recipe.method
                or dispatch.url != expected_url
                or dispatch.body_sha256 != hashlib.sha256(expected_body).hexdigest()
                or not 200 <= dispatch.response_status < 400
            ):
                raise ValueError("Exact reviewed request and accepted response evidence required")
            previous = dispatch.sent_at
            with service.sessions() as db:
                closure = db.get(CallbackClosureRow, nonce.id)
                if closure is None or (closure.owner_id, closure.scan_id, closure.task_id) != (
                    task.owner_id,
                    task.scan_id,
                    task.task_id,
                ):
                    raise ValueError("Authoritative callback closure missing")
                import hmac

                if (
                    not hmac.compare_digest(
                        closure.signature, service._signature(_closure_data(closure))
                    )
                    or closure.at < dispatches[-1].sent_at + task.recipe.max_wait_seconds
                    or closure.at > finished_at
                ):
                    raise ValueError("Callback observation window closed prematurely")
                closed_at = closure.at
            receipts = service.receipts(
                nonce.id, owner_id=task.owner_id, scan_id=task.scan_id, task_id=task.task_id
            )
            positive = False
            for receipt in receipts:
                if (
                    not service.verify(receipt)
                    or receipt.nonce_id != nonce.id
                    or receipt.scan_id != task.scan_id
                    or receipt.task_id != task.task_id
                    or not dispatch.sent_at <= receipt.at < nonce.expires_at
                    or receipt.at > finished_at
                    or receipt.at > closed_at
                ):
                    raise ValueError("Stored callback receipt signature/binding/time failed")
                peer = _address(receipt.peer)
                source = (
                    "scanner"
                    if peer in scanner_peers
                    else "target"
                    if peer in expected_peers
                    else "unknown"
                )
                if receipt.source != source:
                    raise ValueError("Stored callback source attribution mismatch")
                if purpose == "negative" and source == "target":
                    raise ValueError("Target contacted inert control; family proof unresolved")
                positive |= (
                    source == "target"
                    and receipt.protocol == "http"
                    and receipt.method in {"GET", "HEAD"}
                )
            if purpose == "positive" and not positive:
                raise ValueError("Paired attributable target HTTP callbacks absent")
            refs.append(dispatch.evidence_ref)
            nonce_ids.append(nonce.id)
        if finished_at < previous + task.recipe.max_wait_seconds:
            raise ValueError("Negative-control observation window incomplete")
        state, reason = (
            "confirmed",
            "Two independent target HTTP callbacks matched reviewed dispatches; inert control had no target interaction",
        )
    except (PermissionError, ValueError, KeyError, TypeError):
        # No callback, unknown NAT, DNS-only and unsupported input all remain inconclusive.
        reason = "Durable callback proof incomplete or binding/signature/attribution invalid"
    assessment = CallbackAssessment(
        family=task.recipe.family,
        state=state,
        reason=reason,
        nonce_ids=nonce_ids,
        target_route=urlsplit(task.recipe.target_url).path or "/",
    )
    outcome = evaluate_callback_assessment(assessment, refs[0] if refs else None)
    if outcome.proof:
        outcome = outcome.model_copy(
            update={"proof": outcome.proof.model_copy(update={"evidence_refs": tuple(refs)})}
        )
    return outcome
