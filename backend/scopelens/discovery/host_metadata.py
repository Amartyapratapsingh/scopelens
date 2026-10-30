"""Additive provenance fields shared by inventory and priority API rows."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HostObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Literal["crawl", "link", "certificate-transparency", "dns"]
    observed_at: datetime
    provider: str
    wildcard: bool = False


class HostMetadata(BaseModel):
    sources: list[Literal["crawl", "link", "certificate-transparency", "dns"]] = Field(
        default_factory=list
    )
    observations: list[HostObservation] = Field(default_factory=list)
    dns_status: Literal["resolvable", "unresolved", "unavailable", "not_checked"] = "not_checked"
    dns_addresses: list[str] = Field(default_factory=list)
    dns_observed_at: datetime | None = None


class HostDiscoveryCoverage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "passive-hosts-v1"
    registrable_domain: str | None = None
    observed_at: datetime | None = None
    state: Literal["complete", "partial", "source_unavailable", "not_applicable", "not_run"] = (
        "not_run"
    )
    coverage_notes: list[str] = Field(default_factory=list)
    target_http_requests: int = 0
    dns_provider: str = "dns.google"
