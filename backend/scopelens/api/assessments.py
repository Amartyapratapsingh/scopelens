"""Owner-bound immutable assessment inputs. Credential values are never returned."""

from __future__ import annotations

import hashlib
import json
import uuid
from urllib.parse import urlsplit

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from scopelens.api.deps import AppSettings, CurrentOperator, DbSession
from scopelens.discovery.intake import ImportEnvelope
from scopelens.domain.enums import ProfileName
from scopelens.domain.expansion import (
    AssessmentConfiguration,
    CatalogueImport,
    ConfigurationView,
    CredentialCreate,
    CredentialView,
    PlanHistoryView,
    PlanTemplateReviewView,
)
from scopelens.expansion.control import credential_references
from scopelens.identities.secrets import EncryptedSecretStore
from scopelens.persistence.models import AssessmentConfigurationRow, ScanRow, ScopeVersionRow
from scopelens.persistence.repositories import record_audit, scope_row_to_domain


class PrivateInputRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def sanitized(request):
            try:
                return await handler(request)
            except RequestValidationError:
                # Pydantic's errors include input values, including malformed imported
                # samples and credentials. None may be echoed in operator API errors.
                return JSONResponse(status_code=422, content={"detail": "invalid assessment input"})

        return sanitized


router = APIRouter(prefix="/api/assessments", tags=["assessments"], route_class=PrivateInputRoute)


@router.post(
    "/imports",
    response_model=CatalogueImport,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": ImportEnvelope.model_json_schema()}},
        }
    },
)
async def import_catalogue(
    request: Request, operator: CurrentOperator, session: DbSession, settings: AppSettings
):
    from scopelens.discovery.intake import MAX_IMPORT_BYTES, decode_envelope, normalize_import

    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > MAX_IMPORT_BYTES:
            raise HTTPException(413, "assessment import exceeds byte limit")
        raw.extend(chunk)
    try:
        envelope = decode_envelope(bytes(raw))
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise HTTPException(422, "invalid or oversized assessment import") from None
    scope, revalidate = owned_scope(session, envelope.scope_version_id, operator)
    revalidate(scope, settings)
    if not ProfileName(scope.allowed_check_profile).expanded:
        raise HTTPException(422, "imports require a versioned expansion profile")
    try:
        result = normalize_import(envelope, scope_row_to_domain(scope).origin)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        raise HTTPException(422, "invalid or oversized assessment import") from None
    record_audit(
        session,
        actor=operator.username,
        action="assessment.import.normalize",
        subject_type="scope",
        subject_id=str(scope.id),
        outcome="normalized",
        detail={
            "kind": result.kind,
            "source_sha256": result.source_sha256,
            "catalogue_sha256": result.catalogue_sha256,
            "templates": len(result.catalogue.templates),
        },
    )
    session.commit()
    return result


@router.get("/scans/{scan_id}/plans", response_model=PlanHistoryView)
def plan_history(scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession):
    scan = session.get(ScanRow, scan_id)
    if scan is None or scan.operator_id != operator.id:
        raise HTTPException(404, "scan not found")
    frozen = scan.assessment_plan or {}
    revisions = []
    for revision in frozen.get("assessment_plan_revisions", []):
        plan = revision["plan"]
        catalogue = revision["catalogue"]
        revisions.append(
            {
                "plan": {
                    **plan,
                    "tasks": [
                        {k: v for k, v in task.items() if k != "input_key"}
                        for task in plan["tasks"]
                    ],
                },
                "catalogue": {
                    "template_ids": [t["id"] for t in catalogue["templates"]],
                    "instance_count": len(catalogue.get("instances", [])),
                    "gap_count": len(catalogue.get("gaps", [])),
                },
                "run_id": revision.get("run_id"),
            }
        )
    return PlanHistoryView(
        scan_id=scan.id,
        revisions=revisions,
        execution_claims=len(frozen.get("assessment_execution_claims", {})),
    )


@router.get("/scans/{scan_id}/plans/{plan_id}/templates", response_model=PlanTemplateReviewView)
def review_templates(
    scan_id: uuid.UUID,
    plan_id: str,
    operator: CurrentOperator,
    session: DbSession,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=200),
):
    """Display a frozen discovery revision; this route grants no execution authority."""
    from scopelens.discovery.review import project_review

    scan = session.get(ScanRow, scan_id)
    if scan is None or scan.operator_id != operator.id:
        raise HTTPException(404, "scan not found")
    try:
        return project_review(
            scan_id=scan.id,
            scope_version_id=scan.scope_version_id,
            profile=scan.profile,
            origin=scope_row_to_domain(scan.scope_version).origin,
            frozen=scan.assessment_plan or {},
            plan_id=plan_id,
            offset=offset,
            limit=limit,
        )
    except LookupError:
        raise HTTPException(404, "assessment plan not found") from None
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        # Stored snapshots can contain private baselines. Never echo validation input.
        raise HTTPException(409, "assessment plan snapshot is inconsistent") from None


def secret_store(settings):
    if not settings.identity_encryption_key:
        raise HTTPException(503, "identity credential store is not configured")
    return EncryptedSecretStore(
        settings.identity_store_path,
        settings.identity_encryption_key.get_secret_value().encode(),
    )


def owned_scope(session, ident, operator):
    row = session.get(ScopeVersionRow, ident)
    if row is None or row.operator_id != operator.id:
        raise HTTPException(404, "scope not found")
    from scopelens.api.scans import _revalidate_scope

    return row, _revalidate_scope


def validate_configuration(config, primary, session, operator, settings):
    primary_domain = scope_row_to_domain(primary)
    approved = {primary_domain.origin: primary_domain}
    if any(item.catalogue.origin != primary_domain.origin for item in config.imports):
        raise HTTPException(422, "import catalogue origin does not match its scope")
    for grant in config.related_origins:
        related, revalidate = owned_scope(session, uuid.UUID(grant.scope_version_id), operator)
        revalidate(related, settings)
        domain = scope_row_to_domain(related)
        if (
            domain.authority_domain != primary_domain.authority_domain
            or domain.origin != grant.origin
        ):
            raise HTTPException(422, "related origin must match its scope and authority domain")
        approved[domain.origin] = domain
    if config.identities and primary_domain.allowed_check_profile not in {
        ProfileName.AUTHENTICATED_API_V1,
        ProfileName.STAGING_STATEFUL_V1,
    }:
        raise HTTPException(422, "identities require an authenticated assessment profile")
    for template in config.templates:
        if template.origin not in approved:
            raise HTTPException(422, "request template origin has no scope grant")
    requests = []
    for identity in config.identities:
        if identity.login:
            requests.append(identity.login.request)
        if identity.probe:
            requests.append(identity.probe.request)
    if config.permission_matrix:
        requests.extend(o.request for o in config.permission_matrix.objects)
    requests.extend(recipe.target.request for recipe in config.cors_recipes)
    requests.extend(p.logout for p in config.session_policies if p.logout)
    for workflow in (*config.workflows, *config.browser_workflows):
        requests.extend([workflow.readback, workflow.mutation, workflow.cleanup])
    for probe in config.read_probes:
        requests.extend([probe.baseline, probe.probe, probe.negative_control])
    if (
        config.workflows or config.read_probes or config.browser_workflows
    ) and primary_domain.allowed_check_profile != ProfileName.STAGING_STATEFUL_V1:
        raise HTTPException(422, "workflow recipes require the staging-stateful-v1 profile")
    identities = {i.id for i in config.identities}
    for recipe in (*config.workflows, *config.read_probes):
        if {recipe.actor_identity, recipe.owner_identity} - identities:
            raise HTTPException(422, "workflow references unknown identity")
    from scopelens.domain.identity import IdentityRequest

    requests.extend(IdentityRequest(url=recipe.foreign_url) for recipe in config.cors_recipes)

    for recipe in config.browser_workflows:
        for url in (recipe.viewer_url, recipe.foreign_url, recipe.upload_form_url):
            if url:
                requests.append(IdentityRequest(url=url))
    from scopelens.broker.policy import BrokerRequest, _check_scope_membership

    for request in requests:
        url = urlsplit(request.url)
        origin = f"{url.scheme}://{url.netloc}"
        scope = approved.get(origin)
        if scope is None:
            raise HTTPException(422, "identity request origin has no scope grant")
        decision = _check_scope_membership(
            scope,
            BrokerRequest(
                method=request.method,
                scheme=url.scheme,
                host=url.hostname,
                port=url.port or (443 if url.scheme == "https" else 80),
                path=url.path or "/",
                egress_token="",
            ),
        )
        if decision:
            raise HTTPException(422, "identity request is outside its scope")
    if config.callback_recipes:
        if primary_domain.allowed_check_profile != ProfileName.STAGING_STATEFUL_V1:
            raise HTTPException(422, "callback recipes require the staging-stateful-v1 profile")
        if not settings.callbacks_enabled:
            raise HTTPException(503, "callback collector is not configured")
        from scopelens.callbacks.service import _address

        origins = {value.rstrip("/") for value in settings.callback_collector_origins}
        for item in config.callback_recipes:
            recipe = item.recipe
            if recipe.callback_origin.rstrip("/") not in origins:
                raise HTTPException(422, "callback collector origin is not operator-approved")
            try:
                target_peers = {_address(value) for value in recipe.expected_target_peers}
                scanner_peers = {_address(value) for value in recipe.scanner_peers}
                if not target_peers or not scanner_peers or target_peers & scanner_peers:
                    raise ValueError("ambiguous peers")
            except ValueError:
                raise HTTPException(
                    422, "distinct known callback target/scanner peers required"
                ) from None
            target = urlsplit(recipe.target_url)
            domain = approved.get(f"{target.scheme}://{target.netloc}")
            if domain is None or _check_scope_membership(
                domain,
                BrokerRequest(
                    method=recipe.method,
                    scheme=target.scheme,
                    host=target.hostname,
                    port=target.port or (443 if target.scheme == "https" else 80),
                    path=target.path or "/",
                    egress_token="",
                ),
            ):
                raise HTTPException(422, "callback target request is outside its approved scope")
    # Import refresh placeholders are discovery metadata, never credential authority.
    references = credential_references(config.model_dump(mode="json", exclude={"imports"}))
    if references:
        store = secret_store(settings)
        for reference in references:
            try:
                store.resolve_with_expiry(
                    reference, owner=str(operator.id), scope_id=str(primary.id)
                )
            except (OSError, ValueError, KeyError, TypeError, InvalidToken):
                # Do not distinguish another owner's reference from a missing,
                # expired or damaged one, and never echo the submitted reference.
                raise HTTPException(
                    422, "credential reference is unavailable for this scope"
                ) from None
    return config


@router.post("/configurations", response_model=ConfigurationView, status_code=201)
def create_configuration(
    payload: AssessmentConfiguration,
    operator: CurrentOperator,
    session: DbSession,
    settings: AppSettings,
):
    scope, revalidate = owned_scope(session, payload.scope_version_id, operator)
    revalidate(scope, settings)
    if not ProfileName(scope.allowed_check_profile).expanded:
        raise HTTPException(422, "configuration requires a versioned expansion profile")
    validate_configuration(payload, scope, session, operator, settings)
    data = payload.model_dump(mode="json")
    digest = hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    row = AssessmentConfigurationRow(
        operator_id=operator.id, scope_version_id=scope.id, configuration=data, content_hash=digest
    )
    session.add(row)
    session.flush()
    record_audit(
        session,
        actor=operator.username,
        action="assessment.configuration.create",
        subject_type="assessment_configuration",
        subject_id=str(row.id),
        outcome="created",
        detail={"content_hash": digest},
    )
    session.commit()
    return ConfigurationView(
        id=row.id, content_hash=digest, created_at=row.created_at, configuration=payload
    )


@router.get("/configurations/{configuration_id}", response_model=ConfigurationView)
def get_configuration(configuration_id: uuid.UUID, operator: CurrentOperator, session: DbSession):
    row = session.get(AssessmentConfigurationRow, configuration_id)
    if row is None or row.operator_id != operator.id:
        raise HTTPException(404, "assessment configuration not found")
    return ConfigurationView(
        id=row.id,
        content_hash=row.content_hash,
        created_at=row.created_at,
        configuration=row.configuration,
    )


@router.post("/credentials", response_model=CredentialView, status_code=201)
def create_credential(
    payload: CredentialCreate, operator: CurrentOperator, session: DbSession, settings: AppSettings
):
    scope, revalidate = owned_scope(session, payload.scope_version_id, operator)
    revalidate(scope, settings)
    try:
        ref = secret_store(settings).put(
            payload.value,
            owner=str(operator.id),
            scope_id=str(scope.id),
            expires_at=payload.expires_at,
        )
    except ValueError as exc:
        raise HTTPException(422, "credential needs a future timezone-aware expiry") from exc
    record_audit(
        session,
        actor=operator.username,
        action="assessment.credential.create",
        subject_type="scope",
        subject_id=str(scope.id),
        outcome="created",
        detail={"reference": ref},
    )
    session.commit()
    return CredentialView(reference=ref, scope_version_id=scope.id, expires_at=payload.expires_at)
