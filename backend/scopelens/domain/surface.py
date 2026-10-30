"""Attack-surface map (Build Plan §5.7).

What recon produces, and the input every later phase works from. The shape is deliberate:
the map records **what was observed and how**, not conclusions. A fingerprint carries the
evidence that produced it, so a later reader can tell a banner claim from a body signature.

Two distinctions the map keeps, because collapsing either would misreport coverage:

* **Primary vs inventory-only hosts.** Spec §7.2: discovered hosts are listed and shown,
  but only the primary origin is actively tested in v1. A host record says which it is.
* **Route templates vs concrete URLs.** Two URLs that differ only in an identifier are one
  control location, not two. §9.7 requires normalising route parameters — while *not*
  merging different permission boundaries, which is why the normaliser is segment-based and
  keeps the leading path structure rather than flattening it.
"""

from __future__ import annotations

import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

#: Segments that are identifiers rather than routes. Replaced with `{id}` so that
#: `/users/1` and `/users/2` count once, while `/admin/1` stays distinct from `/users/1`.
_UUID_SEGMENT = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_SEGMENT = re.compile(r"^[0-9a-fA-F]{16,}$")
_INT_SEGMENT = re.compile(r"^\d+$")

DiscoveredVia = Literal[
    "link", "form", "robots", "sitemap", "well-known", "redirect", "seed", "browser"
]
ParameterLocation = Literal["query", "form", "path"]


def normalize_route(url_path: str) -> str:
    """Collapse identifier segments into ``{id}``.

    Segment-based on purpose: a regex over the whole path that replaced any digit run would
    merge `/users/1` with `/v2/users`, and Spec §9.7 forbids merging across boundaries that
    carry different meaning. Trailing slashes are removed so `/a` and `/a/` are one route.
    """
    path = url_path.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path

    segments = []
    for segment in path.split("/"):
        if not segment:
            continue
        if (
            _UUID_SEGMENT.match(segment)
            or _HEX_SEGMENT.match(segment)
            or _INT_SEGMENT.match(segment)
        ):
            segments.append("{id}")
        else:
            segments.append(segment)
    return "/" + "/".join(segments)


class EndpointRecord(BaseModel):
    """One URL the crawl actually reached, and what came back."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url: str
    route: str
    method: str = "GET"
    status: int | None = None
    content_type: str | None = None
    discovered_via: DiscoveredVia
    depth: int = Field(ge=0)
    #: Where the link was found. Keeps a route's provenance even when it was reached once.
    discovered_from: str | None = None


class ParameterRecord(BaseModel):
    """An input location. §9.7 scores a field against its work, not the category's."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    location: ParameterLocation
    route: str
    #: A redacted sample. Parameters routinely carry tokens, so the value is redacted at
    #: capture and this field never holds a raw secret.
    sample: str | None = None


class FormInputRecord(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    input_type: str = "text"
    required: bool = False


class FormRecord(BaseModel):
    """A form the crawl found. Recorded, never submitted — v1 is unauthenticated and
    non-destructive, and Spec §12 blocks unapproved state changes outright."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    action: str
    method: str = "GET"
    inputs: tuple[FormInputRecord, ...] = ()
    source_route: str


class TechFingerprint(BaseModel):
    """A passive technology observation, with the evidence that produced it.

    Spec §10.2: a version string is inventory until its security significance is
    established, so ``version`` is a candidate and the evidence field says why.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1)
    version: str | None = None
    evidence: str = Field(min_length=1)
    source: Literal["header", "body", "cookie", "path"]


class HostRecord(BaseModel):
    """A host referenced by the target.

    v1 tests the primary origin and nothing else (Spec §7.2). Everything else is listed as
    inventory so the report can show it without implying it was assessed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    host: str = Field(min_length=1)
    role: Literal["primary", "inventory_only"]
    evidence: str


class Classification(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    is_spa: bool = False
    has_rest_api: bool = False
    has_openapi: bool = False
    has_graphql: bool = False
    evidence: tuple[str, ...] = ()


class CrawlStats(BaseModel):
    """What the crawl did, including what stopped it.

    A truncated crawl reports the limit that stopped it rather than looking complete. The
    difference between "no more pages exist" and "we stopped looking" is the difference
    between a result and a guess.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    pages_fetched: int = 0
    requests_made: int = 0
    max_depth_reached: int = 0
    #: Non-None when a limit ended the crawl earlier than the site ended.
    stopped_by: str | None = None
    skipped_out_of_scope: int = 0
    skipped_excluded: int = 0
    errors: int = 0
    time_allowance_seconds: float = 0
    elapsed_seconds: float = 0
    budget_extensions: int = 0
    pending_frontier: int = 0


class AttackSurfaceMap(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    origin: str
    endpoints: tuple[EndpointRecord, ...] = ()
    parameters: tuple[ParameterRecord, ...] = ()
    forms: tuple[FormRecord, ...] = ()
    tech: tuple[TechFingerprint, ...] = ()
    hosts: tuple[HostRecord, ...] = ()
    classification: Classification = Field(default_factory=Classification)
    stats: CrawlStats = Field(default_factory=CrawlStats)

    def routes(self) -> list[str]:
        seen: dict[str, None] = {}
        for endpoint in self.endpoints:
            seen.setdefault(endpoint.route, None)
        return sorted(seen)

    def endpoint_for_route(self, route: str) -> EndpointRecord | None:
        for endpoint in self.endpoints:
            if endpoint.route == route:
                return endpoint
        return None

    def parameters_for_route(self, route: str) -> list[ParameterRecord]:
        return [p for p in self.parameters if p.route == route]


def new_id() -> str:
    return uuid.uuid4().hex
