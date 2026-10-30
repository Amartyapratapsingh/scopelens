"""Immutable discovery and assessment-plan contracts, with no execution authority."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator


def stable_id(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:24]


class Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class InputLocation(Record):
    location: Literal["query", "path", "form", "json", "header", "cookie"]
    name: str = Field(min_length=1, max_length=256)
    pointer: str | None = None
    occurrence: int = Field(default=0, ge=0)
    value_type: Literal["string", "number", "boolean", "null"] = "string"
    baseline_value: str | int | float | bool | None = None
    secret_ref: str | None = None
    required: bool = False
    mutable: bool = True

    @model_validator(mode="after")
    def protect_secret(self):
        if self.secret_ref and (self.baseline_value is not None or self.mutable):
            raise ValueError("secret input must use a reference and cannot be mutated")
        if self.location == "json" and self.pointer is None:
            raise ValueError("JSON input requires an RFC 6901 pointer")
        return self

    @property
    def key(self) -> str:
        return f"{self.location}:{self.pointer or self.name}:{self.occurrence}"


class RequestTemplate(Record):
    id: str
    origin: str
    path: str
    route_template: str
    method: str
    role_id: str = "anonymous"
    content_type: str | None = None
    inputs: tuple[InputLocation, ...] = ()
    json_structure: dict[str, Literal["object", "array"]] = Field(default_factory=dict)
    baseline_complete: bool = True
    baseline_observed: bool = False
    provenance: tuple[str, ...] = ()
    authority: Literal["primary", "scan", "resource_only", "unapproved"] = "primary"

    @model_validator(mode="after")
    def validate_target(self):
        parts = urlsplit(self.origin)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
        ):
            raise ValueError("request origin must be HTTP(S) without credentials")
        if parts.query or parts.fragment or parts.path not in {"", "/"}:
            raise ValueError("origin cannot include a path, query or fragment")
        if not self.path.startswith("/") or "?" in self.path or "#" in self.path:
            raise ValueError("path must be absolute and query-free")
        if self.method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
            raise ValueError("unsupported HTTP method")
        if len({i.key for i in self.inputs}) != len(self.inputs):
            raise ValueError("duplicate input locations")
        return self


class EndpointInstance(Record):
    template_id: str
    path: str
    role_id: str
    source: str
    status: int | None = None
    baseline_observed: bool = False


class RelatedOriginGrant(Record):
    origin: str
    purpose: Literal["scan", "resource_only"]
    grant_id: str = Field(min_length=1)
    scope_version_id: str = Field(min_length=1)


class ActionPolicy(Record):
    """Operator admission for an exact operation. Target declarations cannot create one."""

    template_id: str
    role_id: str
    classification: Literal["read_only", "staging_write", "deny"]
    approval_ref: str = Field(min_length=1)
    control_ids: tuple[str, ...] = ()
    disposable_data_ref: str | None = None
    cleanup_recipe_ref: str | None = None

    @model_validator(mode="after")
    def writes_require_cleanup(self):
        if self.classification == "staging_write" and not (
            self.disposable_data_ref and self.cleanup_recipe_ref
        ):
            raise ValueError("staging writes require disposable data and a cleanup recipe")
        return self


class DiscoveryGap(Record):
    source: str
    reason: str
    template_id: str | None = None


class DiscoveryCatalogue(Record):
    version: str = "discovery-v2"
    origin: str
    templates: tuple[RequestTemplate, ...] = ()
    instances: tuple[EndpointInstance, ...] = ()
    gaps: tuple[DiscoveryGap, ...] = ()


class AssessmentTask(Record):
    id: str
    template_id: str
    control_id: str
    input_key: str | None = None
    state: Literal["ready", "blocked"]
    reason: str
    coverage_weight: int = Field(default=1, ge=1)


class AssessmentPlanVersion(Record):
    id: str
    revision: int = Field(ge=1)
    previous_id: str | None = None
    scope_version: str
    catalogue_hash: str
    profile: str = "external-active-v2"
    tasks: tuple[AssessmentTask, ...]
    denominator: int = Field(ge=0)
    carried_task_ids: tuple[str, ...] = ()

    @model_validator(mode="after")
    def consistent_denominator(self):
        if len({task.id for task in self.tasks}) != len(self.tasks):
            raise ValueError("duplicate assessment tasks")
        if self.denominator != sum(t.coverage_weight for t in self.tasks):
            raise ValueError("denominator must include blocked and carried tasks")
        return self
