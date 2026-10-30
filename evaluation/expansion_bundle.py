"""Evaluator-only immutable input and captured-artifact contracts.

This package never supplies labels to a scan. File hashes establish local consistency,
not remote attestation; the evaluator owns custody of authenticated exports and freezes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,100}$")]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IdentityProbe(Record):
    id: str
    role: str
    expires_at: datetime | None = None
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    url: str
    identity_pointer: str
    expected_identity: str

    @model_validator(mode="after")
    def no_credential_url(self):
        parts = urlsplit(self.url)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or any((parts.username, parts.password, parts.query, parts.fragment))
        ):
            raise ValueError("identity proof URL must exclude credentials/query/fragment")
        if self.expires_at and self.expires_at.tzinfo is None:
            raise ValueError("identity expiry requires timezone")
        return self


class InputBinding(Record):
    control_id: str
    task_id: str
    template_id: str
    plan_id: str
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    route: str
    role_id: str = "anonymous"
    input_key: str | None = None
    identity: IdentityProbe | None = None

    @model_validator(mode="after")
    def bound_route_identity(self):
        if not self.route.startswith("/") or any(c in self.route for c in "?#"):
            raise ValueError("query-free absolute route required")
        if self.role_id != "anonymous" and (not self.identity or self.identity.id != self.role_id):
            raise ValueError("authenticated binding needs exact identity proof criteria")
        if self.role_id == "anonymous" and self.identity:
            raise ValueError("anonymous binding cannot declare authenticated identity")
        return self

    def key(self):
        return self.control_id, self.method, self.route, self.role_id, self.input_key


class TargetBinding(Record):
    target: Name
    scan_id: UUID
    scope_version_id: UUID
    origin: str
    profile: str
    candidate_fingerprint: Digest | None = None
    fixture_fingerprint: Digest | None = None
    scope_fingerprint: Digest | None = None
    ceiling_requests: int | None = Field(default=None, ge=0)
    ceiling_seconds: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    ceiling_cost: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    model_cost: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    model_cost_evidence_ref: str | None = None
    mode: Literal["baseline", "adaptive", "unknown"] = "unknown"
    bindings: tuple[InputBinding, ...]

    @model_validator(mode="after")
    def valid_target(self):
        parts = urlsplit(self.origin)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or any((parts.username, parts.password, parts.query, parts.fragment))
            or parts.path not in {"", "/"}
        ):
            raise ValueError("HTTP origin without credentials/query/fragment required")
        if len({b.key() for b in self.bindings}) != len(self.bindings):
            raise ValueError("duplicate role/input binding")
        if len({b.task_id for b in self.bindings}) != len(self.bindings):
            raise ValueError("duplicate task binding")
        if self.model_cost is not None and not self.model_cost_evidence_ref:
            raise ValueError("measured model cost requires evidence, including zero")
        return self


class Bindings(Record):
    version: Literal["expansion-evaluator-bindings-v1"]
    exported_at: datetime
    trusted_export_ref: str = Field(min_length=1)
    targets: tuple[TargetBinding, ...]

    @model_validator(mode="after")
    def unique(self):
        if self.exported_at.tzinfo is None:
            raise ValueError("export timestamp requires timezone")
        if len({t.target for t in self.targets}) != len(self.targets):
            raise ValueError("duplicate target alias")
        if len({t.scan_id for t in self.targets}) != len(self.targets):
            raise ValueError("duplicate scans cannot inflate case counts")
        return self


class Case(Record):
    id: Name
    target: Name
    family: str
    scenario_group: str
    check_id: str
    route: str
    method: str = "GET"
    role_id: str = "anonymous"
    input_key: str | None = None
    label: Literal["vulnerable", "fixed", "absent"]

    def key(self):
        return self.target, self.check_id, self.method, self.route, self.role_id, self.input_key


class Protocol(Record):
    version: Literal["expansion-evaluation-protocol-v1"]
    partition: Literal["development", "validation", "holdout"]
    contaminated: bool
    curator_ref: str | None = None
    declared_families: tuple[str, ...]
    cases: tuple[Case, ...]

    @model_validator(mode="after")
    def unique(self):
        if len({c.id for c in self.cases}) != len(self.cases):
            raise ValueError("duplicate case identifiers")
        if len({c.key() for c in self.cases}) != len(self.cases):
            raise ValueError("duplicate measurements cannot increase sample size")
        if set(c.family for c in self.cases) - set(self.declared_families):
            raise ValueError("undeclared family")
        return self


class Freeze(Record):
    version: Literal["expansion-evaluation-freeze-v1"] = "expansion-evaluation-freeze-v1"
    created_at: datetime
    evaluator_sha256: Digest
    bindings: Bindings
    protocol: Protocol
    bindings_sha256: Digest
    protocol_sha256: Digest

    @model_validator(mode="after")
    def valid_hashes(self):
        if self.created_at.tzinfo is None:
            raise ValueError("freeze timestamp requires timezone")
        if digest(self.bindings.model_dump(mode="json")) != self.bindings_sha256:
            raise ValueError("bindings hash mismatch")
        if digest(self.protocol.model_dump(mode="json")) != self.protocol_sha256:
            raise ValueError("protocol hash mismatch")
        targets = {t.target: t for t in self.bindings.targets}
        for case in self.protocol.cases:
            target = targets.get(case.target)
            if target is None or not any(
                (case.check_id, case.method, case.route, case.role_id, case.input_key) == b.key()
                for b in target.bindings
            ):
                raise ValueError("case lacks exact evaluator-only binding")
        return self


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_object(path: Path) -> dict:
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("evaluation input exceeds 64 MiB")
    raw = path.read_text()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = yaml.safe_load(raw)
    if not isinstance(value, dict):
        raise ValueError("evaluation input must be a mapping")
    return value


def write_envelope(path: Path, payload: dict) -> str:
    """Create, never replace, one content-addressed local result."""
    envelope = {"sha256": digest(payload), "payload": payload}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(envelope, indent=2, sort_keys=True, allow_nan=False) + "\n")
    path.chmod(0o600)
    return envelope["sha256"]


def read_envelope(path: Path, expected_sha256: str | None = None) -> dict:
    envelope = read_object(path)
    actual = digest(envelope["payload"])
    if actual != envelope.get("sha256") or (
        expected_sha256 is not None and actual != expected_sha256
    ):
        raise ValueError("immutable evaluation artifact hash mismatch")
    return envelope["payload"]


def evaluator_fingerprint() -> str:
    paths = sorted(Path("evaluation").glob("*.py"))
    paths += [
        Path("backend/scopelens") / relative
        for relative in (
            "checks/expanded_active.py",
            "expansion/authenticated_inputs.py",
            "expansion/authenticated_browser.py",
            "identities/sessions.py",
            "domain/assessment.py",
            "domain/identity.py",
        )
    ]
    return digest({str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})


def freeze(bindings: Bindings, protocol: Protocol) -> Freeze:
    return Freeze(
        created_at=datetime.now(UTC),
        evaluator_sha256=evaluator_fingerprint(),
        bindings=bindings,
        protocol=protocol,
        bindings_sha256=digest(bindings.model_dump(mode="json")),
        protocol_sha256=digest(protocol.model_dump(mode="json")),
    )
