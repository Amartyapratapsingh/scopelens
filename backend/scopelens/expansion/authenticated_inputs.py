"""Role-bound transport for the existing reviewed generic HTTP input checks.

No client is constructed here. The worker supplies a separate broker-bound client per
identity; the broker remains authoritative for scope, request budgets and cancellation.
The per-task artifact includes before/after identity facts for independent analysis.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr

from scopelens.checks.expanded_active import ProbeStopped, run_expanded_checks
from scopelens.domain.assessment import (
    AssessmentPlanVersion,
    AssessmentTask,
    DiscoveryCatalogue,
    RequestTemplate,
)
from scopelens.domain.identity import IdentityProfile
from scopelens.identities.probe import probe_binding, probe_binding_matches, response_probe_value
from scopelens.identities.sessions import (
    IdentitySessions,
    SessionUnavailable,
    same_value,
)

IDENTITY_PROOF_VERSION = "authenticated-input-v1"
_RESERVED = {"authorization", "cookie", "proxy-authorization", "host", "x-scopelens-egress"}


def _origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise SessionUnavailable("invalid identity origin")
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def _available(profile, cancelled):
    if cancelled():
        raise ProbeStopped("cancelled")
    if profile.expires_at and profile.expires_at <= datetime.now(UTC):
        raise ProbeStopped("identity_session_expired")


class _Budget:
    def __init__(self, maximum, cancelled):
        self.maximum, self.cancelled, self.used = maximum, cancelled, 0

    def take(self):
        if self.cancelled():
            raise ProbeStopped("cancelled")
        if self.used >= self.maximum:
            raise ProbeStopped("request_budget_exhausted")
        self.used += 1


class _MeteredClient:
    def __init__(self, client, budget, guard=lambda: None):
        self.client, self.budget = client, budget
        self.guard = guard

    @property
    def cookies(self):
        return self.client.cookies

    def stream(self, *args, **kwargs):
        # Secret resolution may take time. Recheck expiry immediately before the
        # actual connection, including login and before/after identity requests.
        self.guard()
        self.budget.take()
        return self.client.stream(*args, **kwargs)

    def close(self):
        self.client.close()


class _AuthenticatedTransport:
    def __init__(self, sessions, profile, template, cancelled):
        self.sessions, self.profile, self.template = sessions, profile, template
        self.cancelled = cancelled

    def accepts(self, template):
        return template == self.template and template.role_id == self.profile.id

    def stream(self, template, **args):
        try:
            return self._stream(template, **args)
        except SessionUnavailable:
            raise ProbeStopped("authenticated_session_unavailable") from None

    def _stream(self, template, **args):
        if not self.accepts(template):
            raise ProbeStopped("authenticated_task_binding_mismatch")
        _available(self.profile, self.cancelled)
        if _origin(args["url"]) != _origin(self.profile.probe.request.url):
            raise ProbeStopped("identity_credential_origin_mismatch")
        headers = dict(args.get("headers", {}))
        reserved = _RESERVED | {name.lower() for name in self.profile.supplied_headers}
        if reserved & {name.lower() for name in headers}:
            raise ProbeStopped("template_overrides_identity_headers")
        headers.update(
            {
                name: self.sessions.secret_resolver(ref).get_secret_value()
                for name, ref in self.profile.supplied_headers.items()
            }
        )
        args.update(headers=headers, follow_redirects=False)
        return self.sessions.client(self.profile.id).stream(**args)


def evaluate_input_identity(
    profile: IdentityProfile,
    task: AssessmentTask,
    template: RequestTemplate,
    plan_id: str,
    proof: dict,
) -> tuple[bool, str]:
    """Recheck captured facts after trusted intake; worker verdicts grant no identity."""
    expected = {
        "version": IDENTITY_PROOF_VERSION,
        "plan_id": plan_id,
        "task_id": task.id,
        "template_id": template.id,
        "role_id": template.role_id,
    }
    if not isinstance(proof, dict) or any(proof.get(k) != v for k, v in expected.items()):
        return False, "authenticated_identity_proof_binding_mismatch"
    if (
        task.template_id != template.id
        or profile.id != template.role_id
        or profile.anonymous
        or profile.probe is None
    ):
        return False, "authenticated_identity_profile_required"
    try:
        if _origin(template.origin) != _origin(profile.probe.request.url):
            return False, "identity_credential_origin_mismatch"
        probes = proof.get("probes", [])
        if len(probes) != 2 or [p.get("phase") for p in probes] != ["before", "after"]:
            return False, "before_after_identity_probes_required"
        times = []
        for probe in probes:
            if (
                probe.get("identity_id") != profile.id
                or probe.get("method") != profile.probe.request.method
                or probe.get("url") != profile.probe.request.url
                or probe.get("pointer") != profile.probe.identity_pointer
                or not probe_binding_matches(profile.probe, probe.get("probe_binding"))
                or probe.get("status") != 200
                or not same_value(probe.get("observed_identity"), profile.probe.expected_identity)
            ):
                return False, "authenticated_identity_probe_failed"
            at = datetime.fromisoformat(probe["observed_at"])
            if at.tzinfo is None or (profile.expires_at and at >= profile.expires_at):
                return False, "authenticated_identity_probe_expired"
            times.append(at)
        if times[1] < times[0]:
            return False, "authenticated_identity_probe_order_invalid"
    except (KeyError, TypeError, ValueError, AttributeError, SessionUnavailable):
        return False, "authenticated_identity_proof_invalid"
    return True, "before_after_identity_probes_verified"


def run_authenticated_inputs(
    catalogue: DiscoveryCatalogue,
    plan: AssessmentPlanVersion,
    anonymous_client: httpx.Client,
    profiles: tuple[IdentityProfile, ...],
    client_factory: Callable[[str], httpx.Client],
    secret_resolver: Callable[[str], SecretStr],
    *,
    cancelled: Callable[[], bool] = lambda: False,
    max_requests: int = 200,
    max_body_bytes: int = 1048576,
) -> list[dict]:
    """Collect existing HTTP probes with explicit roles and shared per-call accounting.

    Missing/expired identities never fall back to the anonymous client. Login, identity
    probes and reviewed input requests all consume this additional local budget. Partial
    captures survive failed verification, cancellation and secret-store failures.
    """
    budget = _Budget(max_requests, cancelled)
    anonymous = _MeteredClient(anonymous_client, budget)
    templates = {t.id: t for t in catalogue.templates}
    results = []
    phase, proof, current_profile = "", None, None

    def observe(identity_id, request, response):
        if (
            proof is not None
            and current_profile is not None
            and request == current_profile.probe.request
            and identity_id == current_profile.id
        ):
            expected = current_profile.probe.expected_identity
            observed = response_probe_value(response, current_profile.probe)
            proof["probes"].append(
                {
                    "phase": phase,
                    "identity_id": identity_id,
                    "method": request.method,
                    "url": request.url,
                    "pointer": current_profile.probe.identity_pointer,
                    "probe_binding": probe_binding(current_profile.probe),
                    "status": response.status_code,
                    "observed_identity": expected if same_value(observed, expected) else None,
                    "observed_at": datetime.now(UTC).isoformat(),
                }
            )

    def make_client(role):
        client = client_factory(role)
        if client is anonymous_client or client.cookies is anonymous_client.cookies:
            raise SessionUnavailable("authenticated client reused anonymous session")
        return _MeteredClient(
            client, budget, lambda: _available(sessions.profiles[role], cancelled)
        )

    with IdentitySessions(
        profiles,
        secret_resolver,
        make_client,
        cancelled=cancelled,
        response_observer=observe,
    ) as sessions:
        for task in plan.tasks:
            one = plan.model_copy(update={"tasks": (task,), "denominator": task.coverage_weight})
            template = templates.get(task.template_id)
            before = budget.used
            # Start with the existing deterministic blocked envelope, preserving every
            # planned task even when there is no identity or executable HTTP collector.
            if template is None or template.role_id == "anonymous":
                result = run_expanded_checks(
                    catalogue,
                    one,
                    anonymous,
                    secret_resolver=lambda ref: secret_resolver(ref).get_secret_value(),
                    cancelled=cancelled,
                    max_requests=max(0, max_requests - budget.used),
                    max_body_bytes=max_body_bytes,
                )[0]
                result["data"]["requests_used"] = budget.used - before
                results.append(result)
                continue
            result = run_expanded_checks(catalogue, one, anonymous, max_requests=0)[0]
            data = result["data"]
            current_profile = sessions.profiles.get(template.role_id)
            proof = {
                "version": IDENTITY_PROOF_VERSION,
                "plan_id": plan.id,
                "task_id": task.id,
                "template_id": template.id,
                "role_id": template.role_id,
                "probes": [],
            }
            data["identity_proof"] = proof
            if data["reason"] != "authenticated_input_transport_not_integrated":
                results.append(result)
                continue
            try:
                if (
                    current_profile is None
                    or current_profile.anonymous
                    or not current_profile.probe
                ):
                    raise ProbeStopped("authenticated_identity_profile_unavailable")
                _available(current_profile, cancelled)
                if _origin(template.origin) != _origin(current_profile.probe.request.url):
                    raise ProbeStopped("identity_credential_origin_mismatch")
                reserved = _RESERVED | {n.lower() for n in current_profile.supplied_headers}
                if any(
                    i.location == "cookie"
                    or (i.location == "header" and i.name.lower() in reserved)
                    for i in template.inputs
                ):
                    raise ProbeStopped("template_overrides_identity_headers")
                phase = "before"
                if not sessions.verify(current_profile.id):
                    raise ProbeStopped("identity_before_probe_failed")
                result = run_expanded_checks(
                    catalogue,
                    one,
                    anonymous,
                    secret_resolver=lambda ref: secret_resolver(ref).get_secret_value(),
                    cancelled=cancelled,
                    max_requests=max(0, max_requests - budget.used),
                    max_body_bytes=max_body_bytes,
                    authenticated_transport=_AuthenticatedTransport(
                        sessions, current_profile, template, cancelled
                    ),
                )[0]
                data = result["data"]
                data["identity_proof"] = proof
                phase = "after"
                if not sessions.verify(current_profile.id, allow_login=False):
                    raise ProbeStopped("identity_after_probe_failed")
                valid, reason = evaluate_input_identity(
                    current_profile, task, template, plan.id, proof
                )
                if not valid:
                    raise SessionUnavailable(reason)
            except (
                ProbeStopped,
                SessionUnavailable,
                httpx.HTTPError,
                ValueError,
                OSError,
                KeyError,
                TypeError,
            ) as exc:
                # Exception strings from clients/credential stores can contain secrets.
                reason = (
                    "cancelled"
                    if cancelled()
                    else str(exc)
                    if isinstance(exc, ProbeStopped)
                    else type(exc).__name__
                )
                data.update(
                    state="inconclusive" if data["captures"] else "blocked",
                    reason=reason,
                    error=reason,
                )
            data["requests_used"] = budget.used - before
            results.append(result)
    return results
