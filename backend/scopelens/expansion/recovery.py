"""Read-only recovery of an unresolved resource fence under fresh scan authority.

A recovery never calls the original mutation or cleanup request. The operator repairs
outside this lane; only a fresh authenticated readback can release the original fence.
The coordinator must use the dedicated task type and trusted intake producer below.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, model_validator
from sqlalchemy import select, text

from scopelens.discovery.catalogue import canonical_origin
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.domain.identity import IdentityProfile, IdentityRequest
from scopelens.domain.task import TaskType
from scopelens.domain.workflow import StateAssertion
from scopelens.evidence.store import EvidenceStoreError
from scopelens.execution.leases import assert_lease_held
from scopelens.execution.ledger import create_scan_with_task
from scopelens.identities.probe import probe_binding, probe_binding_matches, response_probe_value
from scopelens.identities.sessions import (
    IdentitySessions,
    SessionUnavailable,
    response_value,
    same_value,
)
from scopelens.persistence.models import CleanupRow, EvidenceRow, ScanRow, ScopeVersionRow, TaskRow
from scopelens.persistence.repositories import record_audit, scope_row_to_domain

RECOVERY_TASK_TYPE = TaskType.CLEANUP_RECOVERY_VERIFY
RECOVERY_PRODUCER = "reviewed_cleanup_recovery_capture"
RECOVERY_VERSION = "cleanup-recovery-v1"
_TERMINAL = {"completed", "completed_partial", "failed", "cancelled"}


class RecoveryRefused(ValueError):
    """A fixed reason code, safe to include in an API error or audit event."""


class RecoverySpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    version: Literal["cleanup-recovery-v1"] = RECOVERY_VERSION
    recovery_scan_id: uuid.UUID
    cleanup_id: uuid.UUID
    source_scan_id: uuid.UUID
    source_scope_version_id: uuid.UUID
    scope_version_id: uuid.UUID
    scope_content_hash: str
    origin: str
    resource_id: str
    recipe_id: str
    original_state: Literal["pending", "mutation_sent", "cleanup_failed"]
    original_updated_at: datetime
    original_recipe_hash: str
    identity: IdentityProfile
    readback: IdentityRequest
    seed: StateAssertion
    before: StateAssertion
    created_at: datetime

    @model_validator(mode="after")
    def read_only_binding(self):
        if (
            self.readback.method != "GET"
            or self.identity.anonymous
            or self.identity.probe is None
            or self.identity.probe.request.method not in {"GET", "HEAD"}
            or self.readback.secret_fields
            or self.readback.secret_headers
            or self.readback.json_body
            or self.scope_version_id == self.source_scope_version_id
            or self.created_at.tzinfo is None
            or self.original_updated_at.tzinfo is None
        ):
            raise ValueError("fresh read-only recovery binding required")
        requests = [self.readback, self.identity.probe.request]
        if self.identity.login:
            requests.append(self.identity.login.request)
        if any(canonical_origin(request.url) != self.origin for request in requests):
            raise ValueError("recovery request origin mismatch")
        return self

    @property
    def content_hash(self):
        return digest(self.model_dump(mode="json"))


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _recipe(scan, cleanup):
    try:
        config = AssessmentConfiguration.model_validate(
            (scan.assessment_plan or {})["expansion_config"]
        )
    except (KeyError, ValueError, TypeError, AttributeError):
        raise RecoveryRefused("original_recovery_recipe_unavailable") from None
    matches = [
        r
        for r in (*config.workflows, *config.browser_workflows)
        if r.id == cleanup.recipe_id and r.resource_id == cleanup.resource_id
    ]
    if len(matches) != 1:
        raise RecoveryRefused("original_recovery_recipe_unavailable")
    return config, matches[0]


def _identity_contract(profile):
    """Credential references and expiry may refresh; identity semantics cannot."""
    value = profile.model_dump(mode="json", exclude={"expires_at"})

    def scrub(item, key=""):
        if key in {"secret_fields", "secret_headers", "supplied_headers"}:
            return sorted(item)
        if isinstance(item, dict):
            return {k: scrub(v, k) for k, v in item.items()}
        if isinstance(item, list):
            return [scrub(v) for v in item]
        return item

    return scrub(value)


def resource_lock(session, scope_key, resource_id):
    key = int.from_bytes(
        hashlib.sha256((scope_key + "\0" + resource_id).encode()).digest()[:8], "big", signed=True
    )
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def prepare_recovery(
    cleanup, original_scan, original_scope, fresh_scope, fresh_config, *, recovery_scan_id, now=None
):
    now = now or datetime.now(UTC)
    if cleanup.state not in {"pending", "mutation_sent", "cleanup_failed"}:
        raise RecoveryRefused("resource_is_not_fenced")
    if original_scan.status not in _TERMINAL:
        raise RecoveryRefused("original_scan_must_be_terminal")
    if (
        original_scan.id != cleanup.scan_id
        or original_scan.scope_version_id != cleanup.scope_version_id
        or original_scope.id != cleanup.scope_version_id
    ):
        raise RecoveryRefused("original_cleanup_binding_mismatch")
    if (
        fresh_scope.operator_id != original_scan.operator_id
        or fresh_scope.operator_id != original_scope.operator_id
        or fresh_scope.id == original_scope.id
        or fresh_scope.version <= original_scope.version
        or fresh_scope.scope_key != original_scope.scope_key
        or fresh_scope.authority_domain != original_scope.authority_domain
        or fresh_scope.authorization_expires_at <= now
        or scope_row_to_domain(fresh_scope).origin != scope_row_to_domain(original_scope).origin
    ):
        raise RecoveryRefused("fresh_same_origin_authority_required")
    if fresh_config.scope_version_id != fresh_scope.id:
        raise RecoveryRefused("recovery_configuration_scope_mismatch")
    original_config, recipe = _recipe(original_scan, cleanup)
    old_profile = next(
        (p for p in original_config.identities if p.id == recipe.cleanup_identity), None
    )
    profile = next((p for p in fresh_config.identities if p.id == recipe.cleanup_identity), None)
    if (
        old_profile is None
        or profile is None
        or profile.anonymous
        or profile.probe is None
        or _identity_contract(profile) != _identity_contract(old_profile)
        or (profile.expires_at and profile.expires_at <= now)
    ):
        raise RecoveryRefused("original_cleanup_identity_required")
    origin = scope_row_to_domain(fresh_scope).origin
    if (
        recipe.readback.method != "GET"
        or canonical_origin(recipe.readback.url) != origin
        or canonical_origin(profile.probe.request.url) != origin
        or profile.probe.request.method not in {"GET", "HEAD"}
        or recipe.readback.secret_fields
        or recipe.readback.secret_headers
        or recipe.readback.json_body
    ):
        raise RecoveryRefused("read_only_same_origin_recovery_required")
    from scopelens.broker.policy import BrokerRequest, _check_scope_membership

    parsed = urlsplit(recipe.readback.url)
    if _check_scope_membership(
        scope_row_to_domain(fresh_scope),
        BrokerRequest(
            method="GET",
            scheme=parsed.scheme,
            host=parsed.hostname,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            path=parsed.path or "/",
            egress_token="",
        ),
    ):
        raise RecoveryRefused("recovery_readback_outside_fresh_scope")
    # Recovery deliberately strips every action recipe from the scan's credential
    # authority. Readback credentials must be expressed by the identity profile.
    return RecoverySpec(
        recovery_scan_id=recovery_scan_id,
        cleanup_id=cleanup.id,
        source_scan_id=original_scan.id,
        source_scope_version_id=original_scope.id,
        scope_version_id=fresh_scope.id,
        scope_content_hash=fresh_scope.content_hash,
        origin=origin,
        resource_id=cleanup.resource_id,
        recipe_id=cleanup.recipe_id,
        original_state=cleanup.state,
        original_updated_at=cleanup.updated_at,
        original_recipe_hash=digest(recipe.model_dump(mode="json")),
        identity=profile,
        readback=recipe.readback,
        seed=recipe.seed,
        before=recipe.before,
        created_at=now,
    )


def queue_recovery(
    session,
    cleanup,
    original_scan,
    original_scope,
    fresh_scope,
    fresh_config,
    *,
    actor,
    score_version,
):
    """Atomic intent/task/outbox; caller commits after all API validations."""
    resource_lock(session, original_scope.scope_key, cleanup.resource_id)
    session.refresh(cleanup, with_for_update=True)
    existing = session.scalar(
        select(ScanRow).where(
            ScanRow.operator_id == original_scan.operator_id,
            ScanRow.assessment_plan["cleanup_recovery"]["cleanup_id"].astext == str(cleanup.id),
            ScanRow.status.not_in(_TERMINAL),
        )
    )
    if existing is not None:
        raise RecoveryRefused("recovery_already_pending")
    # Validate before inserting anything; then bind the spec to the new scan id.
    prepare_recovery(
        cleanup,
        original_scan,
        original_scope,
        fresh_scope,
        fresh_config,
        recovery_scan_id=uuid.uuid4(),
    )
    scan, task = create_scan_with_task(
        session,
        operator_id=original_scan.operator_id,
        scope_version=fresh_scope,
        score_version=score_version,
        task_type=RECOVERY_TASK_TYPE,
        logical_id="cleanup-recovery-verify",
        actor=actor,
    )
    spec = prepare_recovery(
        cleanup, original_scan, original_scope, fresh_scope, fresh_config, recovery_scan_id=scan.id
    )
    minimal = AssessmentConfiguration(scope_version_id=fresh_scope.id, identities=(spec.identity,))
    scan.assessment_plan = {
        "cleanup_recovery": spec.model_dump(mode="json"),
        "cleanup_recovery_hash": spec.content_hash,
        "adaptive_requested": False,
        "expansion_config": minimal.model_dump(mode="json"),
    }
    record_audit(
        session,
        actor=actor,
        action="cleanup.recovery.request",
        subject_type="cleanup",
        subject_id=str(cleanup.id),
        outcome="queued",
        detail={
            "scan_id": str(scan.id),
            "original_scan_id": str(original_scan.id),
            "original_state": cleanup.state,
            "resource_id": cleanup.resource_id,
            "original_updated_at": cleanup.updated_at.isoformat(),
            "recovery_hash": spec.content_hash,
        },
    )
    return scan, task, spec


def collect_recovery(spec, client_factory, secret_resolver, *, cancelled=lambda: False):
    """Only login + before probe + GET readback + after probe. No mutation recipe exists."""
    spec = RecoverySpec.model_validate(spec)
    proof = {
        "version": RECOVERY_VERSION,
        "recovery_scan_id": str(spec.recovery_scan_id),
        "binding_hash": spec.content_hash,
        "identity_probes": [],
        "readback": None,
    }
    phase = "before"

    def observe(identity_id, request, response):
        if phase not in {"before", "after"} or request != spec.identity.probe.request:
            return
        expected = spec.identity.probe.expected_identity
        actual = response_probe_value(response, spec.identity.probe)
        fact = {
            "phase": phase,
            "identity_id": identity_id,
            "method": request.method,
            "url": request.url,
            "pointer": spec.identity.probe.identity_pointer,
            "probe_binding": probe_binding(spec.identity.probe),
            "status": response.status_code,
            "observed_at": datetime.now(UTC).isoformat(),
        }
        if same_value(actual, expected):
            fact["observed_identity"] = actual
        proof["identity_probes"].append(fact)

    def available():
        if cancelled() or (
            spec.identity.expires_at and spec.identity.expires_at <= datetime.now(UTC)
        ):
            raise SessionUnavailable("recovery_identity_unavailable")

    class Client:
        def __init__(self, client):
            self.client = client

        @property
        def cookies(self):
            return self.client.cookies

        def close(self):
            self.client.close()

        def stream(self, method, url, **kwargs):
            available()
            permitted = [spec.readback, spec.identity.probe.request]
            if spec.identity.login:
                permitted.append(spec.identity.login.request)
            if not any(method == r.method and url == r.url for r in permitted):
                raise SessionUnavailable("recovery_request_not_declared")
            if canonical_origin(url) != spec.origin:
                raise SessionUnavailable("recovery_origin_mismatch")
            kwargs["follow_redirects"] = False
            return self.client.stream(method, url, **kwargs)

    try:
        with IdentitySessions(
            (spec.identity,),
            secret_resolver,
            lambda role: Client(client_factory(role)),
            cancelled=cancelled,
            response_observer=observe,
        ) as sessions:
            available()
            if not sessions.verify(spec.identity.id):
                raise SessionUnavailable("recovery_identity_unverified")
            phase = "readback"
            response = sessions.request(spec.identity.id, spec.readback)
            values = []
            for assertion in (spec.seed, spec.before):
                actual = response_value(response, assertion.pointer)
                fact = {"pointer": assertion.pointer}
                if same_value(actual, assertion.value):
                    fact["value"] = actual
                values.append(fact)
            proof["readback"] = {
                "method": spec.readback.method,
                "url": spec.readback.url,
                "status": response.status_code,
                "observed_at": datetime.now(UTC).isoformat(),
                "values": values,
            }
            phase = "after"
            sessions.verify(spec.identity.id, allow_login=False)
            available()
    except (SessionUnavailable, PermissionError, OSError, ValueError, KeyError, httpx.HTTPError):
        proof["error"] = "recovery_readback_incomplete"
    return {"kind": "cleanup_recovery_capture", "data": proof}


def evaluate_recovery(spec, artifact):
    """Pure proof check. The finalizer separately verifies persisted trusted provenance."""
    try:
        if artifact.get("kind") != "cleanup_recovery_capture":
            return False, "recovery_capture_required"
        proof = artifact["data"]
        if (
            proof.get("error")
            or proof.get("version") != RECOVERY_VERSION
            or proof.get("binding_hash") != spec.content_hash
            or proof.get("recovery_scan_id") != str(spec.recovery_scan_id)
        ):
            return False, "recovery_proof_binding_mismatch"
        probes = proof["identity_probes"]
        if len(probes) != 2 or [p["phase"] for p in probes] != ["before", "after"]:
            return False, "recovery_identity_pair_required"
        times = []
        for probe in probes:
            frozen = spec.identity.probe
            if (
                probe["identity_id"] != spec.identity.id
                or probe["method"] != frozen.request.method
                or probe["url"] != frozen.request.url
                or probe["pointer"] != frozen.identity_pointer
                or not probe_binding_matches(frozen, probe.get("probe_binding"))
                or probe["status"] != 200
                or not same_value(probe.get("observed_identity"), frozen.expected_identity)
            ):
                return False, "recovery_identity_unverified"
            at = datetime.fromisoformat(probe["observed_at"])
            if (
                at.tzinfo is None
                or at < spec.created_at
                or (spec.identity.expires_at and at >= spec.identity.expires_at)
            ):
                return False, "recovery_identity_expired"
            times.append(at)
        readback = proof["readback"]
        at = datetime.fromisoformat(readback["observed_at"])
        if (
            at.tzinfo is None
            or not times[0] <= at <= times[1]
            or readback["method"] != "GET"
            or readback["url"] != spec.readback.url
            or readback["status"] != 200
        ):
            return False, "recovery_readback_unverified"
        values = readback["values"]
        if len(values) != 2:
            return False, "recovery_state_assertions_required"
        for fact, assertion in zip(values, (spec.seed, spec.before), strict=True):
            if (
                fact["pointer"] != assertion.pointer
                or "value" not in fact
                or not same_value(fact["value"], assertion.value)
            ):
                return False, "recovery_original_state_not_restored"
    except (KeyError, TypeError, AttributeError, ValueError):
        return False, "recovery_proof_invalid"
    return True, "original_state_verified_under_fresh_authority"


def finalize_recovery(
    session, scan, *, lease, run_id, evidence_id, store, actor="cleanup-recovery"
):
    """Coordinator-only finalizer: loads the trusted artifact itself, never accepts stdout.

    Caller runs after I/O and commits atomically with the task outcome. Never hold this
    transaction while contacting the target. A failed proof leaves the old row unchanged.
    """
    assert_lease_held(session, scan_id=lease.scan_id, fencing_token=lease.fencing_token)
    session.refresh(scan, with_for_update=True)
    spec = RecoverySpec.model_validate((scan.assessment_plan or {})["cleanup_recovery"])
    now = datetime.now(UTC)
    scope = session.get(ScopeVersionRow, scan.scope_version_id)
    if (
        scan.id != spec.recovery_scan_id
        or lease.scan_id != scan.id
        or scan.scope_version_id != spec.scope_version_id
        or scope.content_hash != spec.scope_content_hash
        or scope.authorization_expires_at <= now
        or scan.cancel_requested_at
        or scan.cancel_epoch != scan.egress_token_epoch
        or not scan.egress_token_hash
        or (scan.assessment_plan or {}).get("cleanup_recovery_hash") != spec.content_hash
    ):
        raise RecoveryRefused("recovery_authority_not_live")
    resource_lock(session, scope.scope_key, spec.resource_id)
    cleanup = session.scalar(
        select(CleanupRow).where(CleanupRow.id == spec.cleanup_id).with_for_update()
    )
    if (
        cleanup is None
        or cleanup.scan_id != spec.source_scan_id
        or cleanup.scope_version_id != spec.source_scope_version_id
        or cleanup.resource_id != spec.resource_id
        or cleanup.recipe_id != spec.recipe_id
        or cleanup.state != spec.original_state
        or cleanup.updated_at != spec.original_updated_at
    ):
        raise RecoveryRefused("original_resource_fence_changed")
    original = session.get(ScanRow, spec.source_scan_id)
    if (
        original.operator_id != scan.operator_id
        or scan.egress_token_hash == original.egress_token_hash
    ):
        raise RecoveryRefused("fresh_recovery_token_required")
    _, recipe = _recipe(original, cleanup)
    if digest(recipe.model_dump(mode="json")) != spec.original_recipe_hash:
        raise RecoveryRefused("original_recovery_recipe_changed")
    evidence = session.get(EvidenceRow, uuid.UUID(str(evidence_id)))
    task = session.get(TaskRow, evidence.task_id) if evidence else None
    valid, reason = False, "trusted_recovery_evidence_required"
    if (
        evidence
        and task
        and evidence.scan_id == scan.id
        and evidence.scope_version_id == scope.id
        and evidence.scope_content_hash == scope.content_hash
        and evidence.origin == "supervisor"
        and evidence.producer == RECOVERY_PRODUCER
        and evidence.producer_hash
        and evidence.role == spec.identity.id
        and evidence.run_id == run_id
        and evidence.captured_at >= spec.created_at
        and task.scan_id == scan.id
        and task.task_type == RECOVERY_TASK_TYPE
        and task.state == "running"
        and task.lease_token == lease.fencing_token
        and not evidence.truncated
        and evidence.redaction_state in {"redacted", "clean"}
    ):
        try:
            payload = store.get(evidence.content_ref)
            if (
                len(payload) == evidence.content_bytes
                and hashlib.sha256(payload).hexdigest() == evidence.content_hash
            ):
                valid, reason = evaluate_recovery(spec, json.loads(payload))
        except (EvidenceStoreError, OSError, ValueError):
            reason = "recovery_evidence_integrity_failed"
    if valid:
        cleanup.state, cleanup.updated_at = "clean", now
    old_refs = [
        str(ref)
        for ref in session.scalars(
            select(EvidenceRow.id).where(EvidenceRow.scan_id == spec.source_scan_id)
        )
    ]
    record_audit(
        session,
        actor=actor,
        action="cleanup.recovery.verify",
        subject_type="cleanup",
        subject_id=str(cleanup.id),
        outcome="clean" if valid else "fenced",
        detail={
            "scan_id": str(scan.id),
            "original_scan_id": str(original.id),
            "resource_id": cleanup.resource_id,
            "original_state": spec.original_state,
            "original_updated_at": spec.original_updated_at.isoformat(),
            "original_evidence_refs": old_refs,
            "recovery_evidence_ref": str(evidence_id),
            "reason": reason,
        },
    )
    scan.assessment_plan = {
        **scan.assessment_plan,
        "cleanup_recovery_result": {
            "verified": valid,
            "reason": reason,
            "evidence_ref": str(evidence_id),
            "verified_at": now.isoformat(),
        },
    }
    session.flush()
    return valid, reason
