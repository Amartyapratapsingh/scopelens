"""Immutable, operator-supplied inputs for an expanded assessment."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, SecretStr, model_validator

from scopelens.callbacks.probes import CallbackProbeRecipe
from scopelens.domain.assessment import (
    ActionPolicy,
    DiscoveryCatalogue,
    Record,
    RelatedOriginGrant,
    RequestTemplate,
)
from scopelens.domain.browser_workflow import BrowserWorkflowRecipe
from scopelens.domain.cors import CORSRecipe
from scopelens.domain.identity import IdentityProfile, PermissionMatrix, SessionPolicy
from scopelens.domain.workflow import ReadProbeRecipe, WorkflowRecipe


class NamedCallbackRecipe(Record):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,48}$")
    recipe: CallbackProbeRecipe


class CatalogueImport(Record):
    """Normalized discovery metadata, never executable authority or stored raw input."""

    scope_version_id: UUID
    kind: Literal["openapi", "har"]
    role_id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalogue_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalogue: DiscoveryCatalogue

    @model_validator(mode="after")
    def metadata_only(self):
        from scopelens.discovery.intake import catalogue_digest

        if self.catalogue_sha256 != catalogue_digest(self.catalogue):
            raise ValueError("normalized catalogue hash mismatch")
        if len(self.catalogue.templates) > 500 or len(self.catalogue.gaps) > 1000:
            raise ValueError("normalized catalogue exceeds bounds")
        for template in self.catalogue.templates:
            if template.role_id != self.role_id or template.baseline_complete:
                raise ValueError("imports require a reviewed baseline before execution")
            if any(i.baseline_value is not None for i in template.inputs):
                raise ValueError("import sample values must not be retained")
            if any(
                i.secret_ref and not i.secret_ref.startswith("refresh:") for i in template.inputs
            ):
                raise ValueError("imports cannot grant credential references")
        return self


class PlanTaskView(Record):
    id: str
    template_id: str
    control_id: str
    state: Literal["ready", "blocked"]
    reason: str
    coverage_weight: int


class PlanSnapshotView(Record):
    id: str
    revision: int
    previous_id: str | None
    scope_version: UUID
    catalogue_hash: str
    profile: str
    tasks: tuple[PlanTaskView, ...]
    denominator: int
    carried_task_ids: tuple[str, ...]


class CatalogueSummaryView(Record):
    template_ids: tuple[str, ...]
    instance_count: int
    gap_count: int


class PlanRevisionView(Record):
    plan: PlanSnapshotView
    catalogue: CatalogueSummaryView
    run_id: str | None = None


class PlanHistoryView(Record):
    scan_id: UUID
    revisions: tuple[PlanRevisionView, ...]
    execution_claims: int = Field(ge=0)


class ReviewInputView(Record):
    id: str
    location: Literal["query", "path", "form", "json", "header", "cookie"]
    name: str
    pointer: str | None
    occurrence: int
    value_type: Literal["string", "number", "boolean", "null"]
    required: bool
    mutable: bool
    refresh_required: bool
    label_redacted: bool


class ReviewTaskCounts(Record):
    planned: int = Field(ge=0)
    ready: int = Field(ge=0)
    blocked: int = Field(ge=0)
    carried: int = Field(ge=0)
    control_ids: tuple[str, ...]


class RequestTemplateReviewView(Record):
    id: str
    origin: str
    route: str
    method: str
    role_id: str
    content_type: str | None
    baseline_complete: bool
    baseline_observed: bool
    label_redacted: bool
    inputs: tuple[ReviewInputView, ...]
    tasks: ReviewTaskCounts


class PlanTemplateReviewView(Record):
    version: Literal["request-template-review-v1"] = "request-template-review-v1"
    scan_id: UUID
    scope_version_id: UUID
    profile: str
    plan_id: str
    revision: int
    catalogue_hash: str
    templates: tuple[RequestTemplateReviewView, ...]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    next_offset: int | None


class AssessmentConfiguration(Record):
    scope_version_id: UUID
    imports: tuple[CatalogueImport, ...] = Field(default=(), max_length=8)
    templates: tuple[RequestTemplate, ...] = Field(default=(), max_length=500)
    policies: tuple[ActionPolicy, ...] = Field(default=(), max_length=500)
    related_origins: tuple[RelatedOriginGrant, ...] = Field(default=(), max_length=20)
    identities: tuple[IdentityProfile, ...] = Field(default=(), max_length=20)
    permission_matrix: PermissionMatrix | None = None
    session_policies: tuple[SessionPolicy, ...] = ()
    workflows: tuple[WorkflowRecipe, ...] = ()
    read_probes: tuple[ReadProbeRecipe, ...] = ()
    browser_workflows: tuple[BrowserWorkflowRecipe, ...] = ()
    cors_recipes: tuple[CORSRecipe, ...] = Field(default=(), max_length=20)
    callback_recipes: tuple[NamedCallbackRecipe, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def unique_references(self):
        identities = {i.id for i in self.identities}
        if any(i.scope_version_id != self.scope_version_id for i in self.imports):
            raise ValueError("import belongs to a different scope version")
        if any(i.role_id != "anonymous" and i.role_id not in identities for i in self.imports):
            raise ValueError("import references unknown identity")
        if len({i.catalogue_sha256 for i in self.imports}) != len(self.imports):
            raise ValueError("duplicate catalogue imports")
        if len(identities) != len(self.identities):
            raise ValueError("duplicate identity IDs")
        if len({t.id for t in self.templates}) != len(self.templates):
            raise ValueError("duplicate request template IDs")
        if len({(p.template_id, p.role_id) for p in self.policies}) != len(self.policies):
            raise ValueError("duplicate action policies")
        if len({g.origin for g in self.related_origins}) != len(self.related_origins):
            raise ValueError("duplicate origin grants")
        if any(t.role_id != "anonymous" and t.role_id not in identities for t in self.templates):
            raise ValueError("request references unknown identity")
        if self.permission_matrix:
            referenced = {o.owner_identity for o in self.permission_matrix.objects}
            referenced.update(r.identity_id for r in self.permission_matrix.rules)
            if referenced - identities:
                raise ValueError("permission matrix references unknown identity")
        if any(p.identity_id not in identities for p in self.session_policies):
            raise ValueError("session policy references unknown identity")
        if len({p.identity_id for p in self.session_policies}) != len(self.session_policies):
            raise ValueError("duplicate session policies")
        recipes = (*self.workflows, *self.read_probes, *self.browser_workflows)
        if len({r.id for r in recipes}) != len(recipes):
            raise ValueError("duplicate workflow recipe IDs")
        if len({r.id for r in (*recipes, *self.callback_recipes, *self.cors_recipes)}) != len(
            recipes
        ) + len(self.callback_recipes) + len(self.cors_recipes):
            raise ValueError("duplicate assessment recipe IDs")
        for recipe in recipes:
            referenced = {recipe.actor_identity}
            for field in ("owner_identity", "viewer_identity", "cleanup_identity"):
                if value := getattr(recipe, field, None):
                    referenced.add(value)
            if referenced - identities:
                raise ValueError("workflow references unknown identity")
        profiles = {p.id: p for p in self.identities}
        for recipe in self.cors_recipes:
            owner = profiles.get(recipe.target.owner_identity)
            anonymous = profiles.get(recipe.anonymous_identity_id)
            if owner is None or anonymous is None or owner.anonymous or not anonymous.anonymous:
                raise ValueError("CORS requires declared authenticated and anonymous profiles")
            if (
                owner.supplied_headers
                or owner.probe.request.secret_headers
                or owner.probe.request.method != "GET"
                or owner.probe.request.json_body
                or owner.probe.request.secret_fields
            ):
                raise ValueError("CORS identity probes require ambient cookies and GET")
            from scopelens.discovery.catalogue import canonical_origin

            if canonical_origin(owner.probe.request.url) != canonical_origin(
                recipe.target.request.url
            ):
                raise ValueError("CORS target must match the identity origin")
            if not any(
                g.grant_id == recipe.foreign_grant_id
                and g.scope_version_id == str(recipe.foreign_scope_version_id)
                and g.origin == canonical_origin(recipe.foreign_url)
                and g.purpose == "scan"
                for g in self.related_origins
            ):
                raise ValueError("CORS requires an exact foreign-origin scan grant")
        for recipe in self.browser_workflows:
            if recipe.family == "csrf":
                viewer = profiles[recipe.viewer_identity]
                if (
                    viewer.anonymous
                    or viewer.supplied_headers
                    or viewer.probe.request.secret_headers
                ):
                    raise ValueError(
                        "CSRF requires a cookie-authenticated viewer, not anonymous or header-only identity"
                    )
        return self


class ConfigurationView(Record):
    id: UUID
    content_hash: str
    created_at: datetime
    configuration: AssessmentConfiguration


class CredentialCreate(Record):
    scope_version_id: UUID
    value: SecretStr = Field(min_length=1, max_length=16384)
    expires_at: datetime


class CredentialView(Record):
    reference: str
    scope_version_id: UUID
    expires_at: datetime
