"""Operator-controlled lab service bindings (Build Plan §5.1).

A lab scope is not "a scope that happens to point at a private address". It is a
binding to one named service from a fixed deployment allowlist, with an explicitly
approved address and port. The allowlist is a file the operator controls
(``deploy/lab_services.yaml``); it is never supplied by a target, a scan parameter
or a model.

This is deliberately narrow. It permits the named lab fixture and nothing else — it
is never a blanket private-network allowlist, and it cannot reach the host, the
control plane, cloud metadata or another scan's containers.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopelens.domain.errors import DomainError


class LabService(BaseModel):
    """One approved lab service identity from the deployment allowlist."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    description: str = ""
    environment: str = Field(min_length=1)
    addresses: tuple[str, ...] = Field(min_length=1)
    ports: tuple[int, ...] = Field(min_length=1)
    schemes: tuple[str, ...] = ("http", "https")

    @field_validator("addresses")
    @classmethod
    def _addresses_are_ip_literals(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # A lab service is bound by address, not by a name that could re-resolve.
        for address in value:
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                raise ValueError(
                    f"lab service address must be an IP literal, got {address!r}; "
                    "a hostname could be re-pointed after approval"
                ) from exc
        return value

    @field_validator("ports")
    @classmethod
    def _ports_in_range(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        for port in value:
            if not 1 <= port <= 65535:
                raise ValueError(f"port out of range: {port}")
        return value

    @field_validator("schemes")
    @classmethod
    def _schemes_allowed(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = set(value) - {"http", "https"}
        if unknown:
            raise ValueError(f"unsupported lab scheme(s): {sorted(unknown)}")
        return value


class LabBinding(BaseModel):
    """The exact service/address/port a lab scope is bound to.

    Stored on ``ScopeVersion`` and revalidated on every connection (M1 broker).
    Immutable once a scan references the scope version.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    service: str = Field(min_length=1)
    address: str = Field(min_length=1)
    port: int = Field(ge=1, le=65535)
    environment: str = Field(min_length=1)

    @field_validator("address")
    @classmethod
    def _address_is_ip_literal(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"lab binding address must be an IP literal, got {value!r}") from exc
        return value

    def describe(self) -> str:
        return f"{self.service} ({self.address}:{self.port} in {self.environment})"


class LabServiceAllowlist(BaseModel):
    """The deployment allowlist, loaded from ``deploy/lab_services.yaml``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "lab-services-v1"
    services: tuple[LabService, ...] = ()

    def get(self, service_id: str) -> LabService | None:
        for service in self.services:
            if service.id == service_id:
                return service
        return None

    def ids(self) -> list[str]:
        return [service.id for service in self.services]

    def validate_binding(self, binding: LabBinding) -> LabService:
        """Return the allowlisted service, or raise ``LabBindingError``.

        Requires an exact match on identity, address, port *and* environment. A
        service that exists but is bound to an unapproved address or port is
        rejected rather than clamped to an approved one.
        """
        service = self.get(binding.service)
        if service is None:
            raise LabBindingError(
                f"unknown lab service {binding.service!r}; approved services: {self.ids() or 'none'}"
            )
        if binding.address not in service.addresses:
            raise LabBindingError(
                f"address {binding.address} is not approved for lab service {service.id!r} "
                f"(approved: {list(service.addresses)})"
            )
        if binding.port not in service.ports:
            raise LabBindingError(
                f"port {binding.port} is not approved for lab service {service.id!r} "
                f"(approved: {list(service.ports)})"
            )
        if binding.environment != service.environment:
            raise LabBindingError(
                f"environment {binding.environment!r} does not match lab service "
                f"{service.id!r} ({service.environment!r})"
            )
        return service


class LabBindingError(DomainError):
    """Raised when a lab binding is not in the operator-controlled allowlist."""


def load_lab_services(path: Path) -> LabServiceAllowlist:
    """Load and validate the lab service allowlist.

    A missing file yields an empty allowlist, which denies every lab registration.
    That is the fail-closed direction: absence of the allowlist must not silently
    permit lab addresses.
    """
    if not path.exists():
        return LabServiceAllowlist()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise LabBindingError(f"{path} must contain a YAML mapping at the top level")
    return LabServiceAllowlist.model_validate(raw)
