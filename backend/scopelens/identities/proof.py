"""Pure proof evaluation from broker-origin records, never worker verdict strings.

The caller resolves records from trusted evidence intake and enforces scan/scope/identity
bindings before invoking this function. A worker-provided list is not trusted intake.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from scopelens.domain.identity import IdentityProfile, PermissionMatrix, RoleComparison
from scopelens.identities.probe import probe_binding, probe_binding_matches, response_probe_document
from scopelens.identities.sessions import pointer, same_value


class CapturedIdentityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    identity_id: str
    method: str
    url: str
    status: int
    document: dict | list | None
    evidence_ref: str = Field(min_length=1)
    probe_binding: str | None = Field(default=None, exclude_if=lambda value: value is None)


def evaluate_access_proof(
    matrix: PermissionMatrix,
    profiles: tuple[IdentityProfile, ...],
    rule_id: str,
    records: tuple[CapturedIdentityResponse, ...],
) -> RoleComparison:
    rule = next(r for r in matrix.rules if r.id == rule_id)
    target = next(o for o in matrix.objects if o.id == rule.object_id)
    identities = {p.id: p for p in profiles}
    refs = []
    baseline = False
    marker_seen = False
    position = 0

    def next_response(identity, request):
        nonlocal position
        while position < len(records):
            record = records[position]
            position += 1
            if (
                record.identity_id == identity
                and record.method == request.method
                and record.url == request.url
            ):
                refs.append(record.evidence_ref)
                return record
        raise ValueError("required broker response absent")

    def verify_session(identity):
        profile = identities[identity]
        if profile.anonymous:
            return
        probe = profile.probe
        if probe is None:
            raise ValueError("identity probe absent")
        record = next_response(identity, probe.request)
        if (
            record.status != 200
            or not probe_binding_matches(probe, record.probe_binding)
            or pointer(record.document, probe.identity_pointer) != probe.expected_identity
        ):
            raise ValueError("broker session identity not established")

    try:
        if rule.family == "tenant":
            owner_tenant = identities[target.owner_identity].tenant
            actor_tenant = identities[rule.identity_id].tenant
            if not owner_tenant or not actor_tenant or owner_tenant == actor_tenant:
                raise ValueError("distinct declared tenants required")
        verify_session(target.owner_identity)
        owner = next_response(target.owner_identity, target.request)
        baseline = (
            owner.status == 200 and pointer(owner.document, target.marker_pointer) == target.marker
        )
        verify_session(target.owner_identity)
        if not baseline:
            raise ValueError("authorized marker baseline absent")
        markers = []
        denials = []
        for _ in range(2):
            verify_session(rule.identity_id)
            record = next_response(rule.identity_id, target.request)
            marker = (
                record.status == 200
                and pointer(record.document, target.marker_pointer) == target.marker
            )
            markers.append(marker)
            denials.append(
                not marker
                and rule.redacted_pointer is not None
                and same_value(pointer(record.document, rule.redacted_pointer), rule.redacted_value)
                and record.status in (*rule.denial_statuses, 200)
            )
            verify_session(rule.identity_id)
        marker_seen = any(markers)
        if all(markers):
            state, reason = (
                ("pass", "authorized access proved by broker responses")
                if rule.allowed
                else (
                    "confirmed",
                    "forbidden seeded marker reproduced in broker responses with verified identity",
                )
            )
        elif not rule.allowed and all(denials):
            state, reason = "pass", "declared denial independently verified in broker responses"
        else:
            state, reason = (
                "inconclusive",
                "broker observations do not meet the declared access proof",
            )
    except (KeyError, ValueError):
        state, reason = "inconclusive", "required trusted response or verified identity missing"
    return RoleComparison(
        rule_id=rule.id,
        object_id=target.id,
        identity_id=rule.identity_id,
        family=rule.family,
        state=state,
        reason=reason,
        evidence_refs=tuple(dict.fromkeys(refs)),
        authorized_baseline=baseline,
        marker_observed=marker_seen,
    )


def select_identity_response(
    identity_id,
    request,
    response,
    profiles: tuple[IdentityProfile, ...],
    matrix: PermissionMatrix,
    *,
    evidence_ref: str,
) -> CapturedIdentityResponse:
    """Keep only exact operator-declared probe/seed/redaction values, never full bodies.

    This executes inside the fixed collector. The trusted supervisor supplies evidence_ref
    after authenticating run/tool provenance; user-generated scripts cannot call that intake.
    Unexpected fields/values are omitted. URL/method originate in the admitted request.
    """
    import json

    fields: list[tuple[str, object]] = []
    selected_probe = None
    for profile in profiles:
        if profile.id == identity_id and profile.probe and request == profile.probe.request:
            selected_probe = profile.probe
            fields.append((profile.probe.identity_pointer, profile.probe.expected_identity))
            if profile.probe.unauthenticated_pointer:
                fields.append(
                    (profile.probe.unauthenticated_pointer, profile.probe.unauthenticated_value)
                )
    for target in matrix.objects:
        if request.url == target.request.url and request.method == target.request.method:
            fields.append((target.marker_pointer, target.marker))
            fields.extend(
                (rule.redacted_pointer, rule.redacted_value)
                for rule in matrix.rules
                if rule.object_id == target.id
                and rule.identity_id == identity_id
                and rule.redacted_pointer
            )
    document = {}
    if selected_probe:
        actual = response_probe_document(response, selected_probe)
    else:
        try:
            actual = response.json()
        except ValueError:
            actual = None
    for path, expected in fields:
        if not same_value(pointer(actual, path), expected):
            continue
        parts = [p.replace("~1", "/").replace("~0", "~") for p in path[1:].split("/")]
        node = document
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            if not isinstance(child, dict):
                break
            node = child
        else:
            node[parts[-1]] = expected
    if len(json.dumps(document).encode()) > 16384:
        document = {}
    return CapturedIdentityResponse(
        identity_id=identity_id,
        method=request.method,
        url=request.url,
        status=response.status_code,
        document=document,
        evidence_ref=evidence_ref,
        probe_binding=probe_binding(selected_probe) if selected_probe else None,
    )
