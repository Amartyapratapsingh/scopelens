"""Explicit disposable workflows. Endpoint and expected state come from operator policy."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from scopelens.domain.identity import IdentityRecord, IdentityRequest


class StateAssertion(IdentityRecord):
    pointer: str = Field(pattern=r"^/")
    value: str | int | bool | None


class WorkflowRecipe(IdentityRecord):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    family: Literal["mass_assignment", "workflow_authorization"]
    resource_id: str
    action_grant_id: str = Field(min_length=1)
    authority: Literal["lab", "staging"]
    disposable: Literal[True]
    synchronous_write: Literal[True]
    actor_identity: str
    owner_identity: str
    readback: IdentityRequest
    seed: StateAssertion
    before: StateAssertion
    forbidden_after: StateAssertion
    mutation: IdentityRequest
    cleanup: IdentityRequest
    cleanup_identity: str

    @model_validator(mode="after")
    def write_contract(self):
        if self.readback.method != "GET":
            raise ValueError("state read-back must use GET")
        if self.before.pointer != self.forbidden_after.pointer:
            raise ValueError("mutation proof must compare the same protected property")
        if self.before.value == self.forbidden_after.value:
            raise ValueError("forbidden state must differ from baseline")
        if self.mutation.method not in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        } or self.cleanup.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("mutation and reset must be explicit write recipes")
        return self


class ReadProbeRecipe(IdentityRecord):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    family: Literal[
        "graphql_authorization", "private_cache", "path_traversal", "template_injection"
    ]
    action_grant_id: str = Field(min_length=1)
    authority: Literal["lab", "staging"]
    actor_identity: str
    owner_identity: str
    baseline: IdentityRequest
    probe: IdentityRequest
    negative_control: IdentityRequest
    marker: StateAssertion
    # For traversal, this identifies the designated non-sensitive canary; for other
    # packs it identifies the operator-seeded resource. No arbitrary local files.
    synthetic_resource: str = Field(min_length=1)
    denied: StateAssertion | None = None
    forbidden: bool = True

    @model_validator(mode="after")
    def no_arbitrary_write(self):
        for request in (self.baseline, self.probe, self.negative_control):
            if request.method not in {"GET", "POST"}:
                raise ValueError("read probes use GET or explicitly reviewed POST queries")
        if self.family == "template_injection" and self.baseline == self.probe:
            raise ValueError("template baseline and evaluated probe must differ")
        return self


class WorkflowResult(IdentityRecord):
    recipe_id: str
    family: str
    state: Literal["confirmed", "pass", "blocked", "inconclusive", "error"]
    reason: str
    cleanup_state: Literal["not_needed", "clean", "cleanup_failed", "pending"] = "not_needed"
    evidence_refs: tuple[str, ...] = ()
    observations: tuple[dict, ...] = ()
