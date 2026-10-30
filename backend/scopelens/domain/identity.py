"""Operator-declared identities and authorization policy. No credential values in plans."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


class IdentityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class IdentityRequest(IdentityRecord):
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    url: str
    json_body: dict = Field(default_factory=dict)
    body_encoding: Literal["json", "form"] = "json"
    secret_fields: dict[str, str] = Field(default_factory=dict)
    secret_headers: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_url(self):
        parsed = urlsplit(self.url)
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise ValueError("absolute HTTP URL without credentials or fragment required")
        if self.body_encoding == "form" and any(
            isinstance(value, (dict, list)) for value in self.json_body.values()
        ):
            raise ValueError("form body fields must be scalar")
        if any(
            k.lower() in {"host", "proxy-authorization", "x-scopelens-egress"}
            for k in self.secret_headers
        ):
            raise ValueError("transport authority headers cannot be supplied by an identity")
        return self


class SessionProbe(IdentityRecord):
    request: IdentityRequest
    response_format: Literal["json", "html"] = Field(
        default="json", exclude_if=lambda v: v == "json"
    )
    html_selector: str | None = Field(
        default=None, min_length=1, max_length=256, exclude_if=lambda v: v is None
    )
    identity_pointer: str = Field(default="/identity", pattern=r"^/")
    expected_identity: str = Field(min_length=1)
    unauthenticated_pointer: str | None = Field(default=None, pattern=r"^/")
    unauthenticated_value: str | None = None
    unauthenticated_statuses: tuple[int, ...] = (401,)

    @model_validator(mode="after")
    def response_contract(self):
        if self.response_format == "json":
            if self.html_selector is not None:
                raise ValueError("HTML selector requires an HTML probe")
            return self
        if self.html_selector is None:
            raise ValueError("HTML probe requires a selector")
        # Intentionally limited CSS: element/class/id compounds and descendant/child
        # combinators. Attribute values and pseudo selectors can embed account text.
        atom = r"(?:[a-zA-Z][a-zA-Z0-9_-]*)?(?:[.#][a-zA-Z_][a-zA-Z0-9_-]*)*"
        parts = re.split(r"\s*>\s*|\s+", self.html_selector.strip())
        forbidden = {
            "script",
            "style",
            "template",
            "noscript",
            "input",
            "textarea",
            "select",
            "option",
            "button",
            "form",
            "head",
            "title",
            "meta",
            "link",
            "iframe",
            "object",
            "embed",
            "svg",
        }
        if (
            not parts
            or any(not part or not re.fullmatch(atom, part) for part in parts)
            or any(re.split(r"[.#]", part)[0].lower() in forbidden for part in parts)
        ):
            raise ValueError("HTML identity selector must use safe element/class/id selectors")
        if self.identity_pointer != "/identity":
            raise ValueError("HTML probe identity pointer must be /identity")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.expected_identity):
            raise ValueError("HTML expected identity must be a sha256 digest")
        if self.unauthenticated_pointer is not None or self.unauthenticated_value is not None:
            raise ValueError("HTML probes cannot declare JSON unauthenticated values")
        return self


class LoginRecipe(IdentityRecord):
    request: IdentityRequest
    success_statuses: tuple[int, ...] = (200, 204)

    @model_validator(mode="after")
    def credentials_are_references(self):
        sensitive = re.compile(
            r"password|passwd|passphrase|secret|token|api[_-]?key|authorization|cookie|credential",
            re.I,
        )

        def visit(value):
            if isinstance(value, dict):
                for key, child in value.items():
                    if sensitive.search(str(key)):
                        raise ValueError(
                            "login credentials/tokens belong in encrypted secret_fields references"
                        )
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(self.request.json_body)
        return self


class IdentityProfile(IdentityRecord):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    role: str
    tenant: str | None = None
    anonymous: bool = False
    login: LoginRecipe | None = None
    probe: SessionProbe | None = None
    supplied_headers: dict[str, str] = Field(default_factory=dict)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def authentication_contract(self):
        if not self.anonymous and self.probe is None:
            raise ValueError("authenticated identity needs an independent session probe")
        if self.anonymous and (self.login or self.supplied_headers):
            raise ValueError("anonymous identity cannot contain credentials")
        if self.expires_at and self.expires_at.tzinfo is None:
            raise ValueError("session expiry must include timezone")
        if any(
            k.lower() in {"host", "proxy-authorization", "x-scopelens-egress"}
            for k in self.supplied_headers
        ):
            raise ValueError("transport authority headers cannot be supplied by an identity")
        return self


class OwnedTestObject(IdentityRecord):
    id: str
    owner_identity: str
    tenant: str | None = None
    request: IdentityRequest
    marker_pointer: str = Field(pattern=r"^/")
    marker: str = Field(min_length=12, max_length=256)
    synthetic: Literal[True] = True


class PermissionRule(IdentityRecord):
    id: str
    object_id: str
    identity_id: str
    family: Literal["object", "function", "tenant", "property"]
    allowed: bool
    # Successful redacted/shared views require an explicit independent expected value.
    denial_statuses: tuple[int, ...] = (403, 404)
    redacted_pointer: str | None = Field(default=None, pattern=r"^/")
    redacted_value: str | int | bool | None = None


class PermissionMatrix(IdentityRecord):
    version: str
    objects: tuple[OwnedTestObject, ...]
    rules: tuple[PermissionRule, ...]

    @model_validator(mode="after")
    def references(self):
        object_ids = [o.id for o in self.objects]
        if len(set(object_ids)) != len(object_ids):
            raise ValueError("duplicate object ids")
        if len({r.id for r in self.rules}) != len(self.rules):
            raise ValueError("duplicate rule ids")
        if any(r.object_id not in object_ids for r in self.rules):
            raise ValueError("unknown object reference")
        owners = {obj.id: obj.owner_identity for obj in self.objects}
        if any(
            not rule.allowed and rule.identity_id == owners[rule.object_id] for rule in self.rules
        ):
            raise ValueError("the authorized baseline owner cannot also be a forbidden identity")
        if any(o.request.method not in {"GET", "HEAD"} for o in self.objects):
            raise ValueError("access comparison objects must use read-only requests")
        return self


class RoleComparison(IdentityRecord):
    rule_id: str
    object_id: str
    identity_id: str
    family: str
    state: Literal["confirmed", "pass", "blocked", "inconclusive", "error"]
    reason: str
    evidence_refs: tuple[str, ...] = ()
    authorized_baseline: bool = False
    marker_observed: bool = False


class SessionPolicy(IdentityRecord):
    identity_id: str
    cookie_name: str
    # These are intentionally explicit mutations and are never inferred from links.
    login_rotates: bool = True
    old_session_revoked_on_login: bool = False
    logout: IdentityRequest | None = None
    logout_revokes: bool = True
    # Opt-in server expiry contract, measured after independently verifying a fresh login.
    expiry_after_seconds: int | None = Field(
        default=None, ge=1, le=60, strict=True, exclude_if=lambda value: value is None
    )
