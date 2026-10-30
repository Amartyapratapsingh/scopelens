"""Explicit browser workflows over disposable records; no inferred mutation authority."""

from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from scopelens.domain.identity import IdentityRecord, IdentityRequest
from scopelens.domain.workflow import StateAssertion


class BrowserWorkflowRecipe(IdentityRecord):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    family: Literal["stored_xss", "csrf", "upload_serving"]
    resource_id: str = Field(min_length=1)
    action_grant_id: str = Field(min_length=1)
    authority: Literal["lab", "staging"]
    disposable: Literal[True]
    synchronous_write: Literal[True]
    actor_identity: str
    viewer_identity: str
    cleanup_identity: str
    readback: IdentityRequest
    seed: StateAssertion
    before: StateAssertion
    mutation: IdentityRequest
    mutation_field: str = Field(min_length=1)
    cleanup: IdentityRequest
    viewer_url: str
    foreign_url: str | None = None
    form_fields: dict[str, str] = Field(default_factory=dict)
    upload_form_url: str | None = None
    upload_selector: str | None = None
    upload_submit_selector: str | None = None
    upload_filename: str = "scopelens-canary.txt"
    upload_expected_mode: Literal["private", "attachment"] = "private"

    @model_validator(mode="after")
    def explicit_workflow(self):
        if (
            self.readback.method != "GET"
            or self.mutation.method != "POST"
            or self.cleanup.method not in {"POST", "PUT", "PATCH", "DELETE"}
        ):
            raise ValueError(
                "browser workflow requires GET read-back, POST mutation and explicit reset"
            )
        if (
            self.family in {"stored_xss", "upload_serving"}
            and self.actor_identity == self.viewer_identity
        ):
            raise ValueError("writer and viewer require separate identities")
        if self.family == "csrf" and not self.foreign_url:
            raise ValueError("CSRF needs a registered controlled foreign page")
        if self.family == "upload_serving" and not all(
            (self.upload_form_url, self.upload_selector, self.upload_submit_selector)
        ):
            raise ValueError("upload requires an explicit form and selectors")
        if any(c in self.upload_filename for c in "/\\\r\n") or not self.upload_filename.endswith(
            ".txt"
        ):
            raise ValueError("upload fixture must use a benign .txt filename")
        for url in (self.viewer_url, self.foreign_url, self.upload_form_url):
            if url:
                p = urlsplit(url)
                if (
                    p.scheme not in {"http", "https"}
                    or not p.hostname
                    or p.username
                    or p.password
                    or p.fragment
                ):
                    raise ValueError("absolute HTTP workflow URL required")
        return self
