"""API exposure and integration controls (category C07). Build Plan §5.8, Spec §10.2.

Both controls here are OBSERVE-stance and both are written to avoid the mistake Spec §10.2
names first: *"An admin page, GraphQL introspection, an API method, a version string or a
discovered subdomain is inventory until its security significance is established."*

So neither control reports a weakness it cannot establish:

* advertised HTTP methods are recorded, and the report says plainly that advertised is not
  a flaw. Destructive verbs are never invoked to prove support (Spec §10.2, F39).
* the API inventory is recorded as surface. Discovering an API route is not finding a
  broken authorization check, and this profile has no identities with which to test one.
"""

from __future__ import annotations

from scopelens.checks.engine import CheckContext
from scopelens.domain.check import ControlOutcome, Location, ProofResult, potential
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as Outcome

CATEGORY = Category.C07_API

#: Methods that are unremarkable to advertise.
ORDINARY_METHODS = frozenset({"get", "head", "options", "post"})

#: Path shapes that look like an API surface. Used for inventory only.
API_PATH_MARKERS = ("/api", "/rest", "/v1", "/v2", "/graphql", "/openapi", "/swagger", "/rpc")


def evaluate_method_exposure(ctx: CheckContext) -> ControlOutcome:
    """SL-C07-METHODS-01 — the origin advertises HTTP methods beyond the ordinary (F39).

    A finding here is *informational* and says exactly what was observed: a response
    advertised these methods. Whether any of them is reachable without the right authority is
    a different question, and one this profile cannot answer — so it is not implied.
    """
    advertising = [r for r in ctx.data.responses if r.has_header("allow")]
    if not advertising:
        return ControlOutcome(
            check_id="SL-C07-METHODS-01",
            canonical_control="api.http_method_exposure",
            category=CATEGORY,
            status=Outcome.PASS,
            summary="no response advertised an Allow header",
        )

    ref = ctx.evidence_ref("crawl") or ctx.default_evidence_ref
    locations: list[Location] = []
    reasons: list[str] = []

    for response in advertising:
        advertised = {
            method.strip().lower()
            for method in (response.header("allow") or "").split(",")
            if method.strip()
        }
        unusual = sorted(advertised - ORDINARY_METHODS)
        if not unusual:
            continue
        locations.append(
            Location(
                route=response.route,
                header="allow",
                detail=f"advertises {', '.join(sorted(advertised))}",
            )
        )
        reasons.append(
            f"{response.route} advertises {', '.join(unusual)}, which are methods an ordinary "
            "page does not need"
        )

    if not locations:
        return ControlOutcome(
            check_id="SL-C07-METHODS-01",
            canonical_control="api.http_method_exposure",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"{len(advertising)} Allow header(s), all ordinary methods",
        )

    proof = ProofResult(
        satisfied=False,
        status=EvidenceStatus.POTENTIAL,
        reasons=(
            *reasons,
            "an advertised method is inventory, not a flaw: proving support would mean "
            "invoking it, and destructive verbs are not invoked to see whether they work",
        ),
        evidence_refs=(ref,) if ref else (),
    )
    return potential(
        check_id="SL-C07-METHODS-01",
        canonical_control="api.http_method_exposure",
        category=CATEGORY,
        summary="; ".join(reasons),
        proof=proof,
        locations=tuple(locations),
        severity=Severity.INFORMATIONAL,
    )


def evaluate_api_inventory(ctx: CheckContext) -> ControlOutcome:
    """SL-C07-INVENTORY-01 — the same-origin API surface is enumerated (ADD-05).

    This control's claim is about **coverage**, not about weakness: it passes when the
    same-origin API surface was enumerated and recorded. It deliberately raises nothing, and
    its summary says so — an unevaluated API is not a secure one, and passing this control
    must not be read as one.
    """
    routes = ctx.surface.routes()
    api_routes = [
        route for route in routes if any(marker in route.lower() for marker in API_PATH_MARKERS)
    ]

    if not routes:
        return ControlOutcome(
            check_id="SL-C07-INVENTORY-01",
            canonical_control="api.same_origin_inventory",
            category=CATEGORY,
            status=Outcome.INCONCLUSIVE,
            summary="the crawl enumerated no routes, so the API surface is unknown",
        )

    if not api_routes:
        return ControlOutcome(
            check_id="SL-C07-INVENTORY-01",
            canonical_control="api.same_origin_inventory",
            category=CATEGORY,
            status=Outcome.PASS,
            summary=f"{len(routes)} route(s) enumerated; none is API-shaped",
        )

    # Recorded, not reported: the route list belongs in the host/endpoint inventory, and
    # turning discovery into a finding would be exactly the conflation Spec §10.2 warns about.
    return ControlOutcome(
        check_id="SL-C07-INVENTORY-01",
        canonical_control="api.same_origin_inventory",
        category=CATEGORY,
        status=Outcome.PASS,
        summary=(
            f"{len(api_routes)} API-shaped route(s) enumerated and recorded as inventory; "
            "no authorization claim is made for them in this profile"
        ),
    )
