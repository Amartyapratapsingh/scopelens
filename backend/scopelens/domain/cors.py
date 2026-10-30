"""Frozen read-only CORS recipe with explicit controlled foreign-origin authority."""

from uuid import UUID

from pydantic import Field, model_validator

from scopelens.discovery.catalogue import canonical_origin
from scopelens.domain.identity import IdentityRecord, IdentityRequest, OwnedTestObject


class CORSRecipe(IdentityRecord):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,48}$")
    target: OwnedTestObject
    foreign_url: str
    foreign_scope_version_id: UUID
    foreign_grant_id: str = Field(min_length=1, max_length=128)
    anonymous_identity_id: str = Field(default="anonymous", pattern=r"^[a-zA-Z0-9_-]{1,80}$")

    @model_validator(mode="after")
    def read_only_contract(self):
        request = self.target.request
        if (
            request.method != "GET"
            or request.json_body
            or request.secret_fields
            or request.secret_headers
        ):
            raise ValueError("CORS target must be an unmodified GET using ambient cookies only")
        IdentityRequest(url=self.foreign_url)
        if canonical_origin(self.foreign_url) == canonical_origin(request.url):
            raise ValueError("CORS requires a different controlled origin")
        if self.anonymous_identity_id == self.target.owner_identity:
            raise ValueError("CORS requires a separate anonymous identity")
        return self
