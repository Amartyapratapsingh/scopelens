"""Narrow fixed-worker control channel. A scan token alone cannot retrieve credentials."""

import hashlib
import secrets
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert

from scopelens.broker.policy import scan_for_token
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.execution.leases import lease_is_live
from scopelens.persistence.models import CleanupRow, ScopeVersionRow
from scopelens.persistence.repositories import record_audit


class AssessmentCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")
    egress_token: str = Field(min_length=1, repr=False)
    capability: str = Field(min_length=1, repr=False)
    operation: Literal[
        "credential",
        "cleanup_claim",
        "cleanup_mark",
        "cleanup_state",
        "callback_issue",
        "callback_query",
        "callback_revoke",
        "callback_verify",
    ]
    callback_recipe_id: str | None = None
    callback_purpose: Literal["negative", "positive"] | None = None
    callback_nonce_id: str | None = None
    callback_receipt_id: str | None = None
    reference: str | None = None
    recipe_id: str | None = None
    resource_id: str | None = None
    state: Literal["pending", "mutation_sent", "cleanup_failed", "clean"] | None = None


def credential_references(config):
    refs = set()

    def walk(value, key=""):
        if key == "secret_ref" and isinstance(value, str):
            refs.add(value)
        elif key in {"secret_fields", "secret_headers", "supplied_headers"} and isinstance(
            value, dict
        ):
            refs.update(value.values())
        elif isinstance(value, dict):
            for k, v in value.items():
                walk(v, k)
        elif isinstance(value, list):
            for v in value:
                walk(v)

    walk(config)
    return refs


def command(session, settings, request):
    scan = scan_for_token(session, request.egress_token)
    deny = {"allowed": False, "reason": "assessment_capability_denied"}
    if (
        scan is None
        or scan.cancel_requested_at is not None
        or scan.cancel_epoch != scan.egress_token_epoch
        or not lease_is_live(session, scan.id)
    ):
        return deny
    frozen = scan.assessment_plan or {}
    expected = frozen.get("expansion_capability_hash", "")
    if not expected or not secrets.compare_digest(
        expected, hashlib.sha256(request.capability.encode()).hexdigest()
    ):
        return deny
    if scan.scope_version.authorization_expires_at <= datetime.now(UTC):
        return deny
    config = AssessmentConfiguration.model_validate(frozen["expansion_config"])
    if request.operation == "credential":
        if request.reference not in credential_references(config.model_dump(mode="json")):
            return deny
        from scopelens.api.assessments import secret_store

        try:
            value, expires = secret_store(settings).resolve_with_expiry(
                request.reference, owner=str(scan.operator_id), scope_id=str(scan.scope_version_id)
            )
        except (OSError, ValueError, PermissionError):
            return {"allowed": False, "reason": "credential_unavailable_or_expired"}
        return {
            "allowed": True,
            "value": value.get_secret_value(),
            "expires_at": expires.isoformat(),
        }
    if request.operation.startswith("callback_"):
        if not settings.callbacks_enabled or scan.profile != "staging-stateful-v1":
            return {"allowed": False, "reason": "callback_runtime_unavailable"}
        named = next(
            (r for r in config.callback_recipes if r.id == request.callback_recipe_id), None
        )
        if named is None or named.recipe.callback_origin.rstrip("/") not in {
            value.rstrip("/") for value in settings.callback_collector_origins
        }:
            return deny
        from scopelens.callbacks.deployment import runtime_from_settings
        from scopelens.callbacks.runtime import (
            CallbackCommand,
            FrozenCallbackTask,
        )
        from scopelens.persistence.session import build_session_factory

        runtime = runtime_from_settings(
            settings, session_factory=build_session_factory(session.get_bind())
        )
        task = FrozenCallbackTask(
            owner_id=str(scan.operator_id),
            scan_id=str(scan.id),
            recipe_id=named.id,
            recipe=named.recipe,
        )

        def callback_admitted():
            session.refresh(scan)
            return (
                not scan.cancel_requested_at
                and lease_is_live(session, scan.id)
                and scan.cancel_epoch == scan.egress_token_epoch
                and scan.scope_version.authorization_expires_at > datetime.now(UTC)
                and secrets.compare_digest(
                    (scan.assessment_plan or {}).get("expansion_capability_hash", ""),
                    hashlib.sha256(request.capability.encode()).hexdigest(),
                )
            )

        try:
            return runtime.handle(
                task,
                CallbackCommand(
                    operation=request.operation.removeprefix("callback_"),
                    recipe_id=named.id,
                    purpose=request.callback_purpose,
                    nonce_id=request.callback_nonce_id,
                    receipt_id=request.callback_receipt_id,
                ),
                admit=callback_admitted,
            )
        except (ValueError, PermissionError, OSError):
            return {"allowed": False, "reason": "callback_control_denied"}
    recipe = next(
        (
            r
            for r in (*config.workflows, *config.browser_workflows)
            if r.id == request.recipe_id and r.resource_id == request.resource_id
        ),
        None,
    )
    if recipe is None:
        return deny
    if request.operation == "cleanup_claim":
        # A renewed scope grants fresh authority, not permission to forget an
        # unresolved mutation on the same resource. Serialize claims across all
        # immutable revisions before testing or inserting their individual rows.
        lock_key = int.from_bytes(
            hashlib.sha256(
                (scan.scope_version.scope_key + "\0" + recipe.resource_id).encode()
            ).digest()[:8],
            "big",
            signed=True,
        )
        session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
        unresolved = session.scalar(
            select(CleanupRow.id)
            .join(ScopeVersionRow, CleanupRow.scope_version_id == ScopeVersionRow.id)
            .where(
                ScopeVersionRow.scope_key == scan.scope_version.scope_key,
                CleanupRow.resource_id == recipe.resource_id,
                CleanupRow.state != "clean",
            )
            .limit(1)
        )
        if unresolved is not None:
            return {"allowed": False, "reason": "unresolved_cleanup"}
        session.execute(
            insert(CleanupRow)
            .values(
                scope_version_id=scan.scope_version_id,
                resource_id=recipe.resource_id,
                recipe_id=recipe.id,
                scan_id=scan.id,
                state="clean",
            )
            .on_conflict_do_nothing(constraint="uq_cleanup_resource")
        )
    row = session.scalar(
        select(CleanupRow)
        .where(
            CleanupRow.scope_version_id == scan.scope_version_id,
            CleanupRow.resource_id == recipe.resource_id,
        )
        .with_for_update()
    )
    if request.operation == "cleanup_state":
        return {"allowed": True, "state": row.state if row else None}
    if row is None:
        return deny
    if request.operation == "cleanup_claim":
        if row.state != "clean":
            return {"allowed": False, "reason": "unresolved_cleanup"}
        row.scan_id, row.recipe_id, row.state = scan.id, recipe.id, "pending"
    elif row.scan_id == scan.id and row.recipe_id == recipe.id:
        allowed = {
            "pending": {"mutation_sent", "cleanup_failed", "clean"},
            "mutation_sent": {"cleanup_failed", "clean"},
            "cleanup_failed": set(),
            "clean": set(),
        }
        if request.state not in allowed[row.state]:
            return {"allowed": False, "reason": "invalid_cleanup_transition"}
        row.state = request.state
    else:
        return deny
    row.updated_at = datetime.now(UTC)
    session.flush()
    record_audit(
        session,
        actor="assessment-control",
        action="workflow.cleanup_transition",
        subject_type="scan",
        subject_id=str(scan.id),
        outcome=row.state,
        detail={
            "scope_version_id": str(scan.scope_version_id),
            "configuration_hash": frozen.get("configuration_hash"),
            "recipe_id": recipe.id,
            "resource_id": recipe.resource_id,
        },
    )
    return {"allowed": True, "state": row.state}
