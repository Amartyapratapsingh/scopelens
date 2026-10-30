"""Scope records (Build Plan §5.1, Implementation Plan §17.2).

``ScopeVersion`` is immutable once a scan references it. That is enforced in the
persistence layer and asserted by a test, because the whole point of the record is
that a scan's authorization cannot drift underneath it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scopelens.config import Budgets
from scopelens.domain.enums import AuthorityDomain, ProfileName
from scopelens.domain.lab import LabBinding
from scopelens.scope.paths import canonical_path

DEFAULT_ALLOWED_METHODS: tuple[str, ...] = ("GET", "HEAD")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def default_port(scheme: str) -> int:
    return _DEFAULT_PORTS[scheme]


def normalize_host(host: str) -> str:
    """Lowercase, strip a trailing dot and any brackets around an IPv6 literal."""
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


class _ScopeCreateBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scheme: Literal["http", "https"] = "https"
    transport_http_port: int | None = Field(default=None, ge=1, le=65535)
    allowed_path_prefixes: list[str] = Field(default_factory=lambda: ["/"])
    excluded_paths: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=lambda: list(DEFAULT_ALLOWED_METHODS))
    allowed_check_profile: ProfileName = ProfileName.EXTERNAL_CONFIGURATION
    authorization_expires_at: datetime
    owner_note: str = ""
    budgets_override: Budgets | None = None

    @field_validator("allowed_path_prefixes", "excluded_paths")
    @classmethod
    def _paths_start_with_slash(cls, value: list[str]) -> list[str]:
        for path in value:
            if not path.startswith("/"):
                raise ValueError(f"path must start with '/': {path!r}")
            if "?" in path or "#" in path:
                raise ValueError("scope path rules cannot include a query or fragment")
        return [canonical_path(path) for path in value]

    @field_validator("allowed_path_prefixes")
    @classmethod
    def _at_least_one_prefix(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("at least one allowed path prefix is required")
        return value

    @field_validator("allowed_methods")
    @classmethod
    def _methods_are_tokens(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("at least one allowed method is required")
        for method in value:
            if not method.isalpha() or method != method.upper():
                raise ValueError(f"method must be an uppercase HTTP token: {method!r}")
        return value

    @field_validator("authorization_expires_at")
    @classmethod
    def _expiry_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("authorization_expires_at must include a timezone")
        return value


class ProductionScopeCreate(_ScopeCreateBase):
    """A production scope. Rejects private, link-local and metadata destinations."""

    authority_domain: Literal[AuthorityDomain.PRODUCTION] = AuthorityDomain.PRODUCTION
    host: str = Field(min_length=1)
    port: int | None = Field(default=None, ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def _normalize(cls, value: str) -> str:
        return normalize_host(value)


class LabScopeCreate(_ScopeCreateBase):
    """A lab scope: a binding to one named service from the deployment allowlist.

    The operator names the service; the address and port come from the allowlist.
    ``lab_address`` and ``lab_port`` may narrow that choice but can never widen it, and
    there is deliberately **no** ``host``/``port`` field here: two competing port
    sources would let a request silently disagree with its binding. Because the model
    forbids extra fields, sending ``port`` to a lab scope is rejected outright rather
    than quietly ignored.
    """

    authority_domain: Literal[AuthorityDomain.LAB] = AuthorityDomain.LAB
    lab_service: str = Field(min_length=1)
    lab_address: str | None = None
    lab_port: int | None = Field(default=None, ge=1, le=65535)


ScopeCreate = Annotated[
    ProductionScopeCreate | LabScopeCreate,
    Field(discriminator="authority_domain"),
]


class ScopeVersion(BaseModel):
    """An immutable, versioned authorization record for one origin.

    ``content_hash`` covers every field that affects authorization, so any later
    mutation of a version is detectable.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    operator_id: str
    version: int = Field(ge=1)
    authority_domain: AuthorityDomain

    scheme: Literal["http", "https"]
    host: str
    port: int
    transport_http_port: int | None = None

    allowed_path_prefixes: tuple[str, ...]
    excluded_paths: tuple[str, ...] = ()
    allowed_methods: tuple[str, ...] = DEFAULT_ALLOWED_METHODS
    allowed_check_profile: ProfileName
    authorization_expires_at: datetime
    owner_note: str = ""
    budgets_override: Budgets | None = None

    lab_binding: LabBinding | None = None
    created_at: datetime

    @model_validator(mode="after")
    def _authority_consistency(self) -> ScopeVersion:
        if self.authority_domain is AuthorityDomain.LAB and self.lab_binding is None:
            raise ValueError("a lab scope requires a lab_binding")
        if self.authority_domain is AuthorityDomain.PRODUCTION and self.lab_binding is not None:
            raise ValueError("a production scope must not carry a lab_binding")
        return self

    @property
    def origin(self) -> str:
        """``scheme://host:port`` with the default port omitted."""
        if self.port == default_port(self.scheme):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return now >= self.authorization_expires_at

    def content_hash(self) -> str:
        """Stable sha256 over every authorization-relevant field."""
        return compute_scope_hash(
            authority_domain=self.authority_domain,
            scheme=self.scheme,
            host=self.host,
            port=self.port,
            allowed_path_prefixes=self.allowed_path_prefixes,
            excluded_paths=self.excluded_paths,
            allowed_methods=self.allowed_methods,
            allowed_check_profile=self.allowed_check_profile,
            authorization_expires_at=self.authorization_expires_at,
            owner_note=self.owner_note,
            budgets_override=self.budgets_override,
            lab_binding=self.lab_binding,
            **(
                {"transport_http_port": self.transport_http_port}
                if self.transport_http_port is not None
                else {}
            ),
        )


def compute_scope_hash(**fields: object) -> str:
    """Canonical sha256 over scope authorization fields.

    Enums, datetimes, nested models and tuples are normalised so that the same
    logical scope always produces the same digest.
    """

    def normalize(value: object) -> object:
        if isinstance(value, BaseModel):
            return {key: normalize(item) for key, item in value.model_dump().items()}
        if isinstance(value, datetime):
            return value.astimezone(UTC).isoformat()
        if isinstance(value, tuple | list):
            return [normalize(item) for item in value]
        if isinstance(value, dict):
            return {str(key): normalize(item) for key, item in sorted(value.items())}
        if hasattr(value, "value") and not isinstance(value, str):
            return str(value.value)
        return value

    payload = json.dumps(normalize(fields), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
