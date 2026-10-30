"""Explicit synthetic scenarios over production identity and workflow contracts."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from urllib.parse import urlsplit

from scopelens.domain.identity import (
    IdentityProfile,
    IdentityRequest,
    LoginRecipe,
    OwnedTestObject,
    PermissionMatrix,
    PermissionRule,
    SessionPolicy,
    SessionProbe,
)
from scopelens.domain.workflow import StateAssertion, WorkflowRecipe

from .app import BASELINE, FUNCTION_MARKER, MARKERS, PROTECTED_FIELDS

LAB_BINDINGS = {
    "labs-academic-a": "http://172.28.0.22:8080",
    "labs-academic-b": "http://172.28.0.23:8080",
}


def local_origin(origin):
    parsed = urlsplit(origin)
    try:
        local = ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        local = False
    if (
        not local
        or parsed.scheme != "http"
        or not parsed.port
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("academic development recipes require an explicit HTTP loopback origin")
    return origin.rstrip("/")


def _origin(origin, lab_service):
    if lab_service is None:
        return local_origin(origin)
    if lab_service not in LAB_BINDINGS or origin != LAB_BINDINGS[lab_service]:
        raise ValueError("academic deployed recipes require an exact named lab service binding")
    return origin


def identities(
    origin, *, lab_service=None, credential_reference="academic-lab-password", expired=False
):
    origin = _origin(origin, lab_service)
    return tuple(
        IdentityProfile(
            id=name,
            role="staff" if name == "staff" else "student",
            login=LoginRecipe(
                request=IdentityRequest(
                    method="POST",
                    url=origin + "/login",
                    json_body={"username": name},
                    secret_fields={"password": credential_reference},
                )
            ),
            probe=SessionProbe(
                request=IdentityRequest(url=origin + "/me"),
                expected_identity=name,
                unauthenticated_pointer="/error",
                unauthenticated_value="unauthenticated",
            ),
            expires_at=datetime.now(UTC) - timedelta(seconds=1)
            if expired and name == "student_b"
            else None,
        )
        for name in ("student_a", "student_b", "staff")
    )


def access_matrix(origin, *, lab_service=None, functions=False):
    origin = _origin(origin, lab_service)
    target = OwnedTestObject(
        id="student-a-record",
        owner_identity="student_a",
        request=IdentityRequest(url=origin + "/records/student_a"),
        marker_pointer="/marker",
        marker=MARKERS["student_a"],
    )
    objects = [target]
    rules = [
        PermissionRule(
            id=f"record-view-{name}",
            object_id=target.id,
            identity_id=name,
            family="object",
            allowed=name != "student_b",
            redacted_pointer="/error",
            redacted_value="forbidden",
        )
        for name in ("student_a", "student_b", "staff")
    ]
    if functions:
        objects.append(
            OwnedTestObject(
                id="staff-approval-function",
                owner_identity="staff",
                request=IdentityRequest(url=origin + "/staff/approval-function"),
                marker_pointer="/marker",
                marker=FUNCTION_MARKER,
            )
        )
        rules.extend(
            PermissionRule(
                id=f"approval-function-{name}",
                object_id="staff-approval-function",
                identity_id=name,
                family="function",
                allowed=name == "staff",
                redacted_pointer="/error",
                redacted_value="forbidden",
            )
            for name in ("student_a", "student_b", "staff")
        )
    return PermissionMatrix(version="academic-lab-v2", objects=tuple(objects), rules=tuple(rules))


def _recipe(origin, *, ident, family, actor, field, mutation, before=None):
    return WorkflowRecipe(
        id=ident,
        family=family,
        resource_id="student-a-record",
        action_grant_id="academic-owned-synthetic-v2-" + ident,
        authority="lab",
        disposable=True,
        synchronous_write=True,
        actor_identity=actor,
        owner_identity="staff",
        cleanup_identity="staff",
        readback=IdentityRequest(url=origin + "/records/student_a"),
        seed=StateAssertion(pointer="/marker", value=MARKERS["student_a"]),
        before=StateAssertion(
            pointer="/" + field, value=BASELINE[field] if before is None else before
        ),
        forbidden_after=StateAssertion(
            pointer="/" + field, value=99 if field in {"marks", "attendance"} else "approved"
        ),
        mutation=mutation,
        cleanup=IdentityRequest(method="POST", url=origin + "/records/student_a/reset"),
    )


def write_recipe(origin, field, *, lab_service=None):
    origin = _origin(origin, lab_service)
    if field not in {"marks", "attendance"}:
        raise ValueError("unknown academic fixture property")
    return _recipe(
        origin,
        ident="academic-" + field,
        family="workflow_authorization",
        actor="student_b",
        field=field,
        mutation=IdentityRequest(
            method="POST", url=origin + "/records/student_a/" + field, json_body={"value": 99}
        ),
    )


def assignment_recipe(origin, field="academic_status", *, lab_service=None, ordinary_control=False):
    origin = _origin(origin, lab_service)
    # The caller selects a field in this fixture's explicit permission contract.
    if field not in PROTECTED_FIELDS:
        raise ValueError("field is not an operator-designated synthetic protected property")
    mutation = (
        {"display_name": "Synthetic allowed update"}
        if ordinary_control
        else {field: 99 if field in {"marks", "attendance"} else "approved"}
    )
    return _recipe(
        origin,
        ident="academic-ordinary-field-control"
        if ordinary_control
        else "academic-assignment-" + field,
        family="mass_assignment",
        actor="student_a",
        field=field,
        mutation=IdentityRequest(
            method="POST", url=origin + "/records/student_a/profile", json_body=mutation
        ),
    )


def approval_recipe(origin, *, lab_service=None, actor="student_b"):
    origin = _origin(origin, lab_service)
    if actor not in {"student_b", "staff"}:
        raise ValueError("approval case actor must match the explicit forbidden transition")
    return _recipe(
        origin,
        ident="academic-approval-student"
        if actor == "student_b"
        else "academic-approval-out-of-order",
        family="workflow_authorization",
        actor=actor,
        field="approval_state",
        mutation=IdentityRequest(method="POST", url=origin + "/records/student_a/approve"),
    )


def session_policies(origin, *, lab_service=None):
    origin = _origin(origin, lab_service)
    return tuple(
        SessionPolicy(
            identity_id=name,
            cookie_name="sid",
            logout=IdentityRequest(method="POST", url=origin + "/logout"),
        )
        for name in ("student_a", "student_b", "staff")
    )


def deployed_configuration(scope, reference, *, expired=False):
    """Accept only the two exact API-returned fixture origins; no external target option."""
    service = (scope.get("lab_binding") or {}).get("service")
    if service not in LAB_BINDINGS or scope["origin"] != LAB_BINDINGS[service]:
        raise ValueError("scope is not an exact owned academic lab binding")
    origin = scope["origin"]
    recipes = [
        write_recipe(origin, field, lab_service=service) for field in ("marks", "attendance")
    ]
    if not expired:
        recipes += [
            assignment_recipe(origin, lab_service=service),
            assignment_recipe(origin, lab_service=service, ordinary_control=True),
        ]
        recipes += [
            approval_recipe(origin, lab_service=service, actor=actor)
            for actor in ("student_b", "staff")
        ]
    return {
        "scope_version_id": scope["id"],
        "identities": [
            p.model_dump(mode="json")
            for p in identities(
                origin, lab_service=service, credential_reference=reference, expired=expired
            )
        ],
        "permission_matrix": access_matrix(origin, lab_service=service, functions=True).model_dump(
            mode="json"
        ),
        "workflows": [r.model_dump(mode="json") for r in recipes],
        "session_policies": []
        if expired
        else [p.model_dump(mode="json") for p in session_policies(origin, lab_service=service)],
    }
