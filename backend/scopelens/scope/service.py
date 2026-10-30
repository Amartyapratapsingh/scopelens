"""Scope registration (Build Plan §5.1).

Turns an operator request into an immutable, validated ``ScopeVersion``. Every
rejection path here is a real refusal, not a warning: an unvalidated scope must never
reach the database, because everything downstream trusts this record.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.domain.enums import AuthorityDomain
from scopelens.domain.errors import DomainError
from scopelens.domain.lab import LabBinding, LabServiceAllowlist, load_lab_services
from scopelens.domain.scope import LabScopeCreate, ProductionScopeCreate, default_port
from scopelens.persistence.models import ScopeVersionRow
from scopelens.persistence.repositories import create_scope_version, record_audit
from scopelens.scope.dns import Resolver, ResolverError
from scopelens.scope.validator import ScopeViolation, validate_destination


class ScopeRegistrationError(DomainError):
    """A scope could not be registered. The message is operator-facing."""


def get_lab_allowlist(settings: Settings) -> LabServiceAllowlist:
    return load_lab_services(settings.lab_services_file)


def register_scope(
    session: Session,
    *,
    operator_id: uuid.UUID,
    actor: str,
    payload: ProductionScopeCreate | LabScopeCreate,
    settings: Settings,
    resolver: Resolver,
) -> ScopeVersionRow:
    """Register a scope, dispatching on the declared authority domain."""
    if payload.authorization_expires_at <= datetime.now(UTC):
        raise ScopeRegistrationError(
            "authorization_expires_at is in the past; the scope would be born expired"
        )
    if payload.transport_http_port is not None and payload.scheme != "https":
        raise ScopeRegistrationError("transport_http_port requires a primary HTTPS scope")

    if isinstance(payload, LabScopeCreate):
        row, decision = _register_lab(session, operator_id, payload, settings)
    else:
        row, decision = _register_production(session, operator_id, payload, resolver)

    approved_rates = (
        payload.budgets_override.model_dump(
            include={"max_in_flight", "requests_per_second"}, exclude_unset=True
        )
        if payload.budgets_override is not None
        else {}
    )
    record_audit(
        session,
        actor=actor,
        action="scope.register",
        subject_type="scope_version",
        subject_id=str(row.id),
        outcome="success",
        detail={
            "authority_domain": str(payload.authority_domain),
            "origin": row.scope_key,
            "version": row.version,
            "decision": decision.reason,
            "allowed_check_profile": row.allowed_check_profile,
            **({"budgets_override": approved_rates} if approved_rates else {}),
        },
    )
    return row


def _register_production(
    session: Session,
    operator_id: uuid.UUID,
    payload: ProductionScopeCreate,
    resolver: Resolver,
) -> tuple[ScopeVersionRow, object]:
    port = payload.port or default_port(payload.scheme)

    try:
        addresses = resolver.resolve(payload.host)
    except ResolverError as exc:
        raise ScopeRegistrationError(str(exc)) from exc

    try:
        decision = validate_destination(
            host=payload.host,
            port=port,
            resolved_addresses=addresses,
            authority_domain=AuthorityDomain.PRODUCTION,
        ).require_allowed()
    except ScopeViolation as exc:
        raise ScopeRegistrationError(str(exc)) from exc

    row = create_scope_version(
        session,
        operator_id=operator_id,
        payload=payload,
        scheme=payload.scheme,
        host=payload.host,
        port=port,
        lab_binding=None,
    )
    return row, decision


def _register_lab(
    session: Session,
    operator_id: uuid.UUID,
    payload: LabScopeCreate,
    settings: Settings,
) -> tuple[ScopeVersionRow, object]:
    allowlist = get_lab_allowlist(settings)

    service = allowlist.get(payload.lab_service)
    if service is None:
        raise ScopeRegistrationError(
            f"lab service {payload.lab_service!r} is not in the deployment allowlist "
            f"({settings.lab_services_file}); approved: {allowlist.ids() or 'none'}"
        )

    # The operator may narrow the choice within the approved set, never widen it.
    address = payload.lab_address or service.addresses[0]
    port = payload.lab_port or service.ports[0]

    if payload.scheme not in service.schemes:
        raise ScopeRegistrationError(
            f"scheme {payload.scheme!r} is not approved for lab service {service.id!r} "
            f"(approved: {list(service.schemes)})"
        )
    if payload.transport_http_port is not None and (
        "http" not in service.schemes or payload.transport_http_port not in service.ports
    ):
        raise ScopeRegistrationError("transport HTTP port is not approved by the lab service")

    binding = LabBinding(
        service=service.id,
        address=address,
        port=port,
        environment=service.environment,
    )

    try:
        decision = validate_destination(
            host=address,
            port=port,
            resolved_addresses=[address],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=binding,
            lab_allowlist=allowlist,
        ).require_allowed()
    except ScopeViolation as exc:
        raise ScopeRegistrationError(str(exc)) from exc

    row = create_scope_version(
        session,
        operator_id=operator_id,
        payload=payload,
        scheme=payload.scheme,
        host=address,
        port=port,
        lab_binding=binding,
    )
    return row, decision
