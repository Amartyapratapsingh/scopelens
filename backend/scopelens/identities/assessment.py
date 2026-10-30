"""Repeatable authorization comparisons over operator-seeded records."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

import httpx

from scopelens.domain.check import ControlOutcome, Location, ProofResult
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as OutcomeStatus
from scopelens.domain.identity import PermissionMatrix, RoleComparison
from scopelens.identities.sessions import (
    IdentitySessions,
    SessionUnavailable,
    response_value,
    same_value,
)

# The capture callback runs in trusted intake and returns its durable artifact reference.
# It receives no cookies, credentials, response body, or synthetic marker value.
Capture = Callable[[dict], str]


def run_access_comparisons(
    matrix: PermissionMatrix, sessions: IdentitySessions, capture: Capture
) -> tuple[RoleComparison, ...]:
    objects = {o.id: o for o in matrix.objects}
    results = []
    for rule in matrix.rules:
        target = objects[rule.object_id]
        refs = []
        baseline = False
        seen = []
        denied = []
        try:
            if rule.family == "tenant":
                owner_tenant = sessions.profiles[target.owner_identity].tenant
                actor_tenant = sessions.profiles[rule.identity_id].tenant
                if not owner_tenant or not actor_tenant or owner_tenant == actor_tenant:
                    raise SessionUnavailable("tenant comparison requires distinct declared tenants")
            if not sessions.verify(target.owner_identity):
                raise SessionUnavailable("owner session verification failed")
            owner = sessions.request(target.owner_identity, target.request)
            baseline = (
                owner.status_code == 200
                and response_value(owner, target.marker_pointer) == target.marker
            )
            refs.append(
                capture(
                    {
                        "kind": "authorization_baseline",
                        "rule_id": rule.id,
                        "identity_id": target.owner_identity,
                        "status": owner.status_code,
                        "marker_seen": baseline,
                        "body_sha256": hashlib.sha256(owner.content).hexdigest(),
                    }
                )
            )
            if not baseline or not sessions.verify(target.owner_identity, allow_login=False):
                raise SessionUnavailable("seeded object baseline or owner session unavailable")
            for attempt in range(2):
                if not sessions.verify(rule.identity_id):
                    raise SessionUnavailable("comparison session expired or verification failed")
                response = sessions.request(rule.identity_id, target.request)
                match = (
                    response.status_code == 200
                    and response_value(response, target.marker_pointer) == target.marker
                )
                seen.append(match)
                # A status by itself may be a WAF response. The matrix must identify
                # the application's denial/redacted view, independently from the marker.
                denial = (
                    rule.redacted_pointer is not None
                    and same_value(
                        response_value(response, rule.redacted_pointer), rule.redacted_value
                    )
                    and (
                        response.status_code in rule.denial_statuses or response.status_code == 200
                    )
                    and not match
                )
                denied.append(denial)
                refs.append(
                    capture(
                        {
                            "kind": "authorization_comparison",
                            "rule_id": rule.id,
                            "identity_id": rule.identity_id,
                            "attempt": attempt,
                            "status": response.status_code,
                            "marker_seen": match,
                            "declared_denial": denial,
                            "body_sha256": hashlib.sha256(response.content).hexdigest(),
                        }
                    )
                )
                if not sessions.verify(rule.identity_id, allow_login=False):
                    raise SessionUnavailable("session expired during comparison")
            if not all(refs):
                raise SessionUnavailable("trusted evidence intake returned no reference")
            if all(seen):
                state = "pass" if rule.allowed else "confirmed"
                reason = (
                    "declared authorized view reproduced"
                    if rule.allowed
                    else "forbidden seeded marker returned twice with verified distinct identity"
                )
            elif not rule.allowed and all(denied):
                state, reason = (
                    "pass",
                    "declared denial/redacted view reproduced with verified session",
                )
            else:
                state, reason = (
                    "inconclusive",
                    "response did not establish declared access or denial consistently",
                )
        except SessionUnavailable as exc:
            state, reason = "blocked", str(exc)
        except (httpx.HTTPError, PermissionError, ValueError, KeyError):
            state, reason = (
                "error",
                "identity request, credential resolution or evidence intake failed",
            )
        results.append(
            RoleComparison(
                rule_id=rule.id,
                object_id=target.id,
                identity_id=rule.identity_id,
                family=rule.family,
                state=state,
                reason=reason,
                evidence_refs=tuple(refs),
                authorized_baseline=baseline,
                marker_observed=any(seen),
            )
        )
    return tuple(results)


def as_control_outcome(result: RoleComparison, matrix: PermissionMatrix) -> ControlOutcome:
    target = next(o for o in matrix.objects if o.id == result.object_id)
    state = {
        "confirmed": OutcomeStatus.CONFIRMED_ISSUE,
        "pass": OutcomeStatus.PASS,
        "blocked": OutcomeStatus.BLOCKED,
        "error": OutcomeStatus.ERROR,
        "inconclusive": OutcomeStatus.INCONCLUSIVE,
    }[result.state]
    return ControlOutcome(
        check_id=f"SL-C09-{result.family.upper()}-01",
        canonical_control=f"authorization.{result.family}",
        category=Category.C09_AUTHORIZATION,
        status=state,
        summary=result.reason,
        proposed_severity=Severity.HIGH if result.state == "confirmed" else None,
        locations=(
            Location(
                route=target.request.url, detail=f"identity:{result.identity_id};object:{target.id}"
            ),
        )
        if result.state == "confirmed"
        else (),
        proof=ProofResult(
            satisfied=result.state in {"pass", "confirmed"},
            status=EvidenceStatus.CONFIRMED
            if result.state == "confirmed"
            else EvidenceStatus.INCONCLUSIVE,
            reasons=(result.reason,),
            evidence_refs=result.evidence_refs,
        ),
        required_instances=(result.rule_id,),
        completed_instances=(result.rule_id,) if result.state in {"pass", "confirmed"} else (),
        incomplete_reasons=() if result.state in {"pass", "confirmed"} else (result.reason,),
    )
