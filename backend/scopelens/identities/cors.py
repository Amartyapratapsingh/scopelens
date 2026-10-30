"""Credentialed CORS proof using a real controlled foreign browser origin."""

from __future__ import annotations

from urllib.parse import urlsplit

from scopelens.domain.identity import IdentityRequest, OwnedTestObject, RoleComparison
from scopelens.identities.assessment import Capture
from scopelens.identities.browser import BrowserIdentitySessions
from scopelens.identities.probe import probe_binding, probe_binding_matches
from scopelens.identities.sessions import SessionUnavailable, pointer


def origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.hostname}:{p.port or (443 if p.scheme == 'https' else 80)}"


def check_credentialed_cors(
    target: OwnedTestObject,
    foreign_url: str,
    sessions: BrowserIdentitySessions,
    capture: Capture,
    *,
    allowed_foreign_origins: frozenset[str],
    anonymous_id: str,
    action_owner: str,
) -> RoleComparison:
    """Only cookies naturally sent by the browser establish credentialed exposure.

    The caller must register the supplied foreign origin with the broker as an operator-
    controlled callback/test origin. `allowed_foreign_origins` must come from that trusted
    policy, never from a target page or a model proposal. No authorization headers are
    inserted by the evaluated JavaScript.
    """
    refs = []
    state, reason = "blocked", "credentialed CORS prerequisites unavailable"
    baseline = False
    if origin(foreign_url) not in allowed_foreign_origins or origin(foreign_url) == origin(
        target.request.url
    ):
        return RoleComparison(
            rule_id="credentialed-cors",
            object_id=target.id,
            identity_id=target.owner_identity,
            family="cors",
            state="blocked",
            reason="controlled foreign origin grant required",
        )
    if not sessions.profiles[anonymous_id].anonymous:
        raise ValueError("CORS negative control must use anonymous identity")
    pages = []
    try:
        identity_id = target.owner_identity
        if not sessions.verify(identity_id, action_owner=action_owner):
            raise SessionUnavailable("authenticated browser session unavailable")
        status, value = sessions.request(identity_id, target.request, action_owner=action_owner)
        baseline = status == 200 and pointer(value, target.marker_pointer) == target.marker
        if not baseline:
            raise SessionUnavailable("protected synthetic record baseline unavailable")
        anon_status, anon_value = sessions.request(
            anonymous_id, IdentityRequest(url=target.request.url), action_owner=action_owner
        )
        if anon_status == 200 and pointer(anon_value, target.marker_pointer) == target.marker:
            raise SessionUnavailable("synthetic record is public; credentialed exposure unproven")
        refs.append(
            capture(
                {
                    "kind": "cors_baseline",
                    "object_id": target.id,
                    "authenticated_marker": True,
                    "anonymous_marker": False,
                }
            )
        )
        context = sessions.context(identity_id, action_owner=action_owner)
        page = context.new_page()
        pages.append(page)
        response = page.goto(foreign_url, wait_until="domcontentloaded", timeout=10_000)
        if response is None or response.status != 200 or origin(page.url) != origin(foreign_url):
            raise SessionUnavailable("controlled foreign page unavailable or redirected")
        observations = []
        for _ in range(2):
            if sessions.cancelled():
                raise SessionUnavailable("assessment cancelled")
            observation = page.evaluate(
                """async ({url, pointer, marker}) => {
                const abort = new AbortController();
                const timer = setTimeout(() => abort.abort(), 8000);
                try {
                    const response = await fetch(url, {credentials: 'include', signal: abort.signal});
                    const body = await response.json();
                    const value = pointer.slice(1).split('/').reduce((o, k) => o?.[k.replace(/~1/g, '/').replace(/~0/g, '~')], body);
                    return {readable: true, marker: response.status === 200 && value === marker};
                } catch (_) { return {readable: false, marker: false}; }
                finally { clearTimeout(timer); }
            }""",
                {
                    "url": target.request.url,
                    "pointer": target.marker_pointer,
                    "marker": target.marker,
                },
            )
            observations.append(observation)
            refs.append(
                capture(
                    {
                        "kind": "credentialed_cors_browser",
                        "object_id": target.id,
                        "foreign_origin": origin(foreign_url),
                        "readable": observation["readable"],
                        "marker_seen": observation["marker"],
                    }
                )
            )
        if not sessions.verify(identity_id, action_owner=action_owner):
            raise SessionUnavailable("browser session expired during CORS comparison")
        if not all(refs):
            raise SessionUnavailable("trusted browser evidence unavailable")
        if all(o["marker"] for o in observations):
            state, reason = (
                "confirmed",
                "controlled foreign browser read protected synthetic marker twice using ambient credentials",
            )
        else:
            state, reason = (
                "inconclusive",
                "cross-origin read did not establish protected-data exposure; browser/network restrictions may apply",
            )
    except SessionUnavailable as exc:
        state, reason = "blocked", str(exc)
    finally:
        for page in pages:
            page.close()
    return RoleComparison(
        rule_id="credentialed-cors",
        object_id=target.id,
        identity_id=target.owner_identity,
        family="cors",
        state=state,
        reason=reason,
        evidence_refs=tuple(refs),
        authorized_baseline=baseline,
        marker_observed=state == "confirmed",
    )


def cors_configuration_binding(configuration):
    """Bind only immutable CORS authority/identity inputs, not transient execution state."""
    from scopelens.domain.assessment import stable_id

    return stable_id(
        {
            "scope_version_id": str(configuration.scope_version_id),
            "identities": [p.model_dump(mode="json") for p in configuration.identities],
            "related_origins": [g.model_dump(mode="json") for g in configuration.related_origins],
            "cors_recipes": [r.model_dump(mode="json") for r in configuration.cors_recipes],
        }
    )


def collect_cors_proof(
    recipe,
    profiles,
    context_factory,
    secret_resolver,
    *,
    action_owner,
    configuration_binding,
    allowed_foreign_origins,
    cancelled=lambda: False,
    capture=None,
):
    """Capture native browser facts; target records are read only and never synthesized."""
    import uuid
    from contextlib import suppress
    from datetime import UTC, datetime

    from playwright.sync_api import Error as BrowserError

    from scopelens.discovery.catalogue import canonical_origin

    ids = {
        recipe.target.owner_identity: str(uuid.uuid4()),
        recipe.anonymous_identity_id: str(uuid.uuid4()),
    }
    proof = {
        "version": "credentialed-cors-v1",
        "recipe_id": recipe.id,
        "configuration_binding": configuration_binding,
        "owner_identity": recipe.target.owner_identity,
        "anonymous_identity": recipe.anonymous_identity_id,
        "context_ids": ids,
        "facts": [],
        "error": None,
    }
    selected = {p.id: p for p in profiles}
    page = None
    owner_id, anon_id = recipe.target.owner_identity, recipe.anonymous_identity_id
    profile = selected[owner_id]
    target_url, foreign_url = recipe.target.request.url, recipe.foreign_url

    def live():
        if cancelled() or (profile.expires_at and profile.expires_at <= datetime.now(UTC)):
            raise SessionUnavailable("cors_identity_expired_or_cancelled")

    def fresh_secret(reference):
        live()
        value = secret_resolver(reference)
        live()
        return value

    sessions = BrowserIdentitySessions(profiles, fresh_secret, context_factory, cancelled=cancelled)

    def fact(phase, identity_id, **values):
        live()
        proof["facts"].append(
            {
                "phase": phase,
                "identity_id": identity_id,
                "context_id": ids[identity_id],
                "captured_at": datetime.now(UTC).isoformat(),
                **values,
            }
        )

    def identity(phase):
        live()
        status, document = sessions.request(
            owner_id, profile.probe.request, action_owner=action_owner
        )
        observed = pointer(document, profile.probe.identity_pointer)
        fact(
            phase,
            owner_id,
            method="GET",
            url=profile.probe.request.url,
            status=status,
            observed_identity=observed if observed == profile.probe.expected_identity else None,
            probe_binding=probe_binding(profile.probe),
        )
        if status != 200 or observed != profile.probe.expected_identity:
            raise SessionUnavailable("cors_identity_not_verified")

    try:
        if canonical_origin(foreign_url) not in allowed_foreign_origins or canonical_origin(
            foreign_url
        ) == canonical_origin(target_url):
            raise SessionUnavailable("cors_foreign_origin_not_granted")
        if (
            profile.anonymous
            or profile.supplied_headers
            or profile.probe.request.secret_headers
            or not selected[anon_id].anonymous
        ):
            raise SessionUnavailable("cors_cookie_identity_required")
        live()
        if not sessions.verify(owner_id, action_owner=action_owner):
            raise SessionUnavailable("cors_identity_not_verified")
        identity("before")
        status, document = sessions.request(
            owner_id, recipe.target.request, action_owner=action_owner
        )
        value = pointer(document, recipe.target.marker_pointer)
        fact(
            "owner_baseline",
            owner_id,
            method="GET",
            url=target_url,
            status=status,
            selected_value=value if value == recipe.target.marker else None,
        )
        if status != 200 or value != recipe.target.marker:
            raise SessionUnavailable("cors_protected_baseline_missing")
        status, document = sessions.request(
            anon_id, IdentityRequest(url=target_url), action_owner=action_owner
        )
        value = pointer(document, recipe.target.marker_pointer)
        fact(
            "anonymous_baseline",
            anon_id,
            method="GET",
            url=target_url,
            status=status,
            selected_value=value if value == recipe.target.marker else None,
        )
        if status not in {401, 403, 404} or value == recipe.target.marker:
            raise SessionUnavailable("cors_anonymous_denial_not_proven")
        context = sessions.context(owner_id, action_owner=action_owner)
        network = []

        def route(request_route):
            request = request_route.request
            try:
                live()
                if (
                    request.method != "GET"
                    or request.url not in {target_url, foreign_url}
                    or request.redirected_from
                ):
                    return request_route.abort()
                headers = request.all_headers()
                if "authorization" in headers:
                    return request_route.abort()
                if request.url == target_url:
                    network.append(
                        {
                            "url": request.url,
                            "method": request.method,
                            "origin": headers.get("origin"),
                            "cookie_present": bool(headers.get("cookie")),
                            "authorization_present": False,
                        }
                    )
                return request_route.continue_()
            except (SessionUnavailable, PermissionError):
                return request_route.abort()

        context.route("**/*", route)
        page = context.new_page()
        response = page.goto(foreign_url, wait_until="domcontentloaded", timeout=10000)
        fact("foreign_page", owner_id, url=page.url, status=response.status if response else None)
        if response is None or response.status != 200 or page.url != foreign_url:
            raise SessionUnavailable("cors_foreign_page_unavailable")
        for index in range(2):
            live()
            start = len(network)
            observed = page.evaluate(
                """async ({url, pointer}) => {
                const abort = new AbortController();
                const timer = setTimeout(() => abort.abort(), 8000);
                try {
                    const response = await fetch(url, {credentials: 'include', redirect: 'error', cache: 'no-store', signal: abort.signal});
                    const body = await response.json();
                    const value = pointer.slice(1).split('/').reduce((o,k) => o?.[k.replace(/~1/g,'/').replace(/~0/g,'~')], body);
                    return {readable: true, status: response.status, url: response.url,
                            selected_value: typeof value === 'string' && value.length <= 256 ? value : null};
                } catch (_) { return {readable: false, status: null, url, selected_value: null}; }
                finally { clearTimeout(timer); }
            }""",
                {"url": target_url, "pointer": recipe.target.marker_pointer},
            )
            # Store only the declared synthetic marker, never an arbitrary response value.
            if observed.get("selected_value") != recipe.target.marker:
                observed["selected_value"] = None
            fact(
                f"read_{index + 1}",
                owner_id,
                foreign_url=page.url,
                requests=network[start:],
                **observed,
            )
        # Direct probe: never initialize/login again after the foreign read.
        identity("after")
    except (SessionUnavailable, PermissionError, KeyError, ValueError, BrowserError):
        proof["error"] = "cors_capture_incomplete"
    finally:
        if capture:
            capture(proof)
        if page:
            with suppress(Exception):
                page.close()
        with suppress(Exception):
            sessions.close()
    return proof


def evaluate_cors_proof(recipe, profiles, proof, *, configuration_binding):
    """A verdict string or boolean cannot replace exact trusted browser/identity facts."""
    from datetime import datetime
    from uuid import UUID

    from scopelens.discovery.catalogue import canonical_origin

    try:
        owner = next(p for p in profiles if p.id == recipe.target.owner_identity)
        anonymous = next(p for p in profiles if p.id == recipe.anonymous_identity_id)
        if (
            owner.anonymous
            or not anonymous.anonymous
            or owner.supplied_headers
            or owner.probe.request.secret_headers
        ):
            raise ValueError("cookie identities required")
        if (
            proof.get("version") != "credentialed-cors-v1"
            or proof.get("recipe_id") != recipe.id
            or proof.get("configuration_binding") != configuration_binding
            or proof.get("error")
            or proof.get("owner_identity") != owner.id
            or proof.get("anonymous_identity") != anonymous.id
        ):
            raise ValueError("proof binding mismatch")
        contexts = proof["context_ids"]
        if UUID(contexts[owner.id]) == UUID(contexts[anonymous.id]):
            raise ValueError("identity contexts must differ")
        facts = proof["facts"]
        if [f["phase"] for f in facts] != [
            "before",
            "owner_baseline",
            "anonymous_baseline",
            "foreign_page",
            "read_1",
            "read_2",
            "after",
        ]:
            raise ValueError("proof sequence missing")
        times = [datetime.fromisoformat(f["captured_at"]) for f in facts]
        if any(
            t.tzinfo is None or (owner.expires_at and t >= owner.expires_at) for t in times
        ) or times != sorted(times):
            raise ValueError("expired or unordered proof")
        if anonymous.expires_at and times[2] >= anonymous.expires_at:
            raise ValueError("anonymous baseline expired")
        for fact in facts:
            role = anonymous.id if fact["phase"] == "anonymous_baseline" else owner.id
            if fact.get("identity_id") != role or fact.get("context_id") != contexts[role]:
                raise ValueError("context binding mismatch")
        for fact in (facts[0], facts[-1]):
            if (
                fact.get("url") != owner.probe.request.url
                or fact.get("method") != "GET"
                or fact.get("status") != 200
                or fact.get("observed_identity") != owner.probe.expected_identity
                or not probe_binding_matches(owner.probe, fact.get("probe_binding"))
            ):
                raise ValueError("identity probe missing")
        baseline, negative = facts[1:3]
        for fact in (baseline, negative):
            if fact.get("url") != recipe.target.request.url or fact.get("method") != "GET":
                raise ValueError("protected read binding mismatch")
        if baseline.get("status") != 200 or baseline.get("selected_value") != recipe.target.marker:
            raise ValueError("protected marker missing")
        if (
            negative.get("status") not in {401, 403, 404}
            or negative.get("selected_value") is not None
        ):
            raise ValueError("anonymous denial missing")
        if facts[3].get("url") != recipe.foreign_url or facts[3].get("status") != 200:
            raise ValueError("controlled foreign page missing")
        for fact in facts[4:6]:
            if (
                fact.get("foreign_url") != recipe.foreign_url
                or fact.get("url") != recipe.target.request.url
            ):
                raise ValueError("foreign read binding mismatch")
            requests = fact.get("requests", [])
            if len(requests) != 1 or requests[0] != {
                "url": recipe.target.request.url,
                "method": "GET",
                "origin": canonical_origin(recipe.foreign_url),
                "cookie_present": True,
                "authorization_present": False,
            }:
                raise ValueError("native credentialed request missing")
        if all(
            f.get("readable") is True
            and f.get("status") == 200
            and f.get("selected_value") == recipe.target.marker
            for f in facts[4:6]
        ):
            return (
                "confirmed",
                "controlled foreign browser read protected synthetic data twice with ambient cookies",
            )
        return (
            "inconclusive",
            "cross-origin protected-data read not established; browser or network restrictions may apply",
        )
    except (KeyError, TypeError, ValueError, StopIteration, AttributeError):
        return "inconclusive", "complete bound CORS browser and identity proof unavailable"
