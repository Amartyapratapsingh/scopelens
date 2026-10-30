"""Scope registration routes (Build Plan §5.1).

The lab service list is served to the dashboard so an operator picks a service by
identity rather than typing an address. The address still comes from the allowlist on
the server, never from the request — a request may only narrow within the approved
set, and the server revalidates the binding either way.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from scopelens.api.deps import AppSettings, CurrentOperator, DbSession
from scopelens.domain.enums import AuthorityDomain, ProfileName
from scopelens.domain.scope import ScopeCreate
from scopelens.persistence.models import ScopeVersionRow
from scopelens.persistence.repositories import (
    get_scope_version,
    list_scope_versions,
    scope_row_to_domain,
    scope_version_scan_count,
)
from scopelens.scope.dns import SystemResolver
from scopelens.scope.service import (
    ScopeRegistrationError,
    get_lab_allowlist,
    register_scope,
)

router = APIRouter(prefix="/api", tags=["scopes"])


class LabServiceView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    environment: str
    addresses: list[str]
    ports: list[int]
    schemes: list[str]


class ScopeView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    version: int
    authority_domain: AuthorityDomain
    origin: str
    scheme: str
    host: str
    port: int
    transport_http_port: int | None = None
    allowed_path_prefixes: list[str]
    excluded_paths: list[str]
    allowed_methods: list[str]
    allowed_check_profile: ProfileName
    authorization_expires_at: datetime
    owner_note: str
    lab_binding: dict[str, object] | None
    expired: bool
    content_hash: str
    created_at: datetime
    scan_count: int


def _to_view(row: ScopeVersionRow, session: Session) -> ScopeView:
    record = scope_row_to_domain(row)
    return ScopeView(
        id=record.id,
        version=record.version,
        authority_domain=record.authority_domain,
        origin=record.origin,
        scheme=record.scheme,
        host=record.host,
        port=record.port,
        transport_http_port=record.transport_http_port,
        allowed_path_prefixes=list(record.allowed_path_prefixes),
        excluded_paths=list(record.excluded_paths),
        allowed_methods=list(record.allowed_methods),
        allowed_check_profile=record.allowed_check_profile,
        authorization_expires_at=record.authorization_expires_at,
        owner_note=record.owner_note,
        lab_binding=record.lab_binding.model_dump() if record.lab_binding else None,
        expired=record.is_expired(),
        content_hash=record.content_hash(),
        created_at=record.created_at,
        scan_count=scope_version_scan_count(session, row.id),
    )


@router.get("/lab-services", response_model=list[LabServiceView])
def list_lab_services(operator: CurrentOperator, settings: AppSettings) -> list[LabServiceView]:
    """The operator-controlled deployment allowlist (Build Plan §5.1).

    Operator-only: it enumerates the private lab addresses the deployment authorizes.
    """
    del operator
    allowlist = get_lab_allowlist(settings)
    return [
        LabServiceView(
            id=service.id,
            description=service.description.strip(),
            environment=service.environment,
            addresses=list(service.addresses),
            ports=list(service.ports),
            schemes=list(service.schemes),
        )
        for service in allowlist.services
    ]


@router.get("/scopes", response_model=list[ScopeView])
def list_scopes(operator: CurrentOperator, session: DbSession) -> list[ScopeView]:
    rows = list_scope_versions(session, operator_id=operator.id)
    return [_to_view(row, session) for row in rows]


@router.get("/scopes/{scope_version_id}", response_model=ScopeView)
def get_scope(
    scope_version_id: uuid.UUID, operator: CurrentOperator, session: DbSession
) -> ScopeView:
    row = get_scope_version(session, scope_version_id)
    # A scope belonging to another operator is reported as missing, not as forbidden:
    # a 403 would confirm that the id exists.
    if row is None or row.operator_id != operator.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scope not found")
    return _to_view(row, session)


@router.post("/scopes", response_model=ScopeView, status_code=status.HTTP_201_CREATED)
def register_scope_route(
    payload: Annotated[ScopeCreate, Body()],
    operator: CurrentOperator,
    session: DbSession,
    settings: AppSettings,
) -> ScopeView:
    try:
        row = register_scope(
            session,
            operator_id=operator.id,
            actor=operator.username,
            payload=payload,
            settings=settings,
            resolver=SystemResolver(),
        )
    except ScopeRegistrationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    view = _to_view(row, session)
    # Request-scoped yield dependencies close after the response is sent. Commit the
    # scope and its audit together before an immediate follow-up scan can use this ID.
    session.commit()
    return view
