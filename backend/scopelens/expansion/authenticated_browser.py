"""Independent identity facts for each fresh generic browser input probe.

Contexts come from the existing broker-bound factory. This module never launches a
browser or creates a client. Proof evaluation follows trusted evidence admission.
"""

from datetime import UTC, datetime
from uuid import uuid4

from scopelens.discovery.catalogue import canonical_origin
from scopelens.expansion.authenticated_inputs import IDENTITY_PROOF_VERSION, evaluate_input_identity
from scopelens.identities.browser import BrowserIdentitySessions
from scopelens.identities.probe import probe_binding
from scopelens.identities.sessions import SessionUnavailable, pointer, same_value

BROWSER_IDENTITY_VERSION = "authenticated-browser-input-v1"
PROBE_NAMES = ("baseline", "probe1", "probe2")
_RESERVED = {"authorization", "cookie", "proxy-authorization", "host", "x-scopelens-egress"}


class AuthenticatedBrowserLifecycle:
    def __init__(
        self,
        catalogue,
        plan,
        profiles,
        context_factory,
        secret_resolver,
        *,
        cancelled=lambda: False,
    ):
        self.templates = {template.id: template for template in catalogue.templates}
        self.tasks = {task.id: task for task in plan.tasks}
        self.plan_id = plan.id
        self.profiles = {profile.id: profile for profile in profiles}
        if len(self.profiles) != len(profiles):
            raise ValueError("duplicate identity ids")
        self.context_factory, self.secret_resolver = context_factory, secret_resolver
        self.cancelled = cancelled
        self._contexts = []

    def validate(self, task, template, plan_id, name):
        if (
            self.tasks.get(task.id) != task
            or self.templates.get(template.id) != template
            or task.template_id != template.id
            or plan_id != self.plan_id
            or name not in PROBE_NAMES
        ):
            raise SessionUnavailable("authenticated browser binding mismatch")
        profile = self.profiles.get(template.role_id)
        if profile is None or profile.anonymous or profile.probe is None:
            raise SessionUnavailable("authenticated browser profile required")
        origin = canonical_origin(profile.probe.request.url)
        if canonical_origin(template.origin) != origin:
            raise SessionUnavailable("authenticated browser origin mismatch")
        reserved = _RESERVED | {key.lower() for key in profile.supplied_headers}
        if any(
            i.location == "cookie" or (i.location == "header" and i.name.lower() in reserved)
            for i in template.inputs
        ):
            raise SessionUnavailable("template overrides identity headers")
        return profile, origin, reserved

    def open(self, task, template, plan_id, name, rendered_request):
        profile, origin, reserved = self.validate(task, template, plan_id, name)
        if canonical_origin(rendered_request["url"]) != origin:
            raise SessionUnavailable("authenticated browser origin mismatch")
        if reserved & {key.lower() for key in rendered_request["headers"]}:
            raise SessionUnavailable("template overrides identity headers")
        return _Probe(self, profile, task, template, name, origin)

    def fresh_context(self, role):
        context = self.context_factory(role)
        if any(context is previous for previous in self._contexts):
            raise SessionUnavailable("browser input context reused")
        # Keep references so Python object-id reuse cannot evade the freshness check.
        self._contexts.append(context)
        return context


class _AvailableRequest:
    def __init__(self, probe, request):
        self.probe, self.request = probe, request

    def fetch(self, url, **kwargs):
        # BrowserIdentitySessions resolves secrets before calling fetch. Recheck
        # expiry/cancellation here, after the control RPC and before target I/O.
        self.probe.available()
        if canonical_origin(url) != self.probe.origin:
            raise SessionUnavailable("browser credential origin mismatch")
        kwargs.update(max_redirects=0, max_retries=0)
        return self.request.fetch(url, **kwargs)


class _AvailableContext:
    def __init__(self, probe, context):
        self.context = context
        self.request = _AvailableRequest(probe, context.request)

    def __getattr__(self, name):
        return getattr(self.context, name)


class _Probe:
    def __init__(self, lifecycle, profile, task, template, name, origin):
        self.lifecycle, self.profile, self.origin = lifecycle, profile, origin
        self.context_id = uuid4().hex
        self.phase, self.verified_before, self.failed = "before", False, False
        self.proof = {
            "version": BROWSER_IDENTITY_VERSION,
            "name": name,
            "context_id": self.context_id,
            "identity_proof": {
                "version": IDENTITY_PROOF_VERSION,
                "plan_id": lifecycle.plan_id,
                "task_id": task.id,
                "template_id": template.id,
                "role_id": template.role_id,
                "browser_probe_name": name,
                "context_id": self.context_id,
                "rendered_origin": origin,
                "probes": [],
            },
        }
        self.sessions = BrowserIdentitySessions(
            (profile,),
            lifecycle.secret_resolver,
            lambda role: _AvailableContext(self, lifecycle.fresh_context(role)),
            cancelled=lifecycle.cancelled,
            response_observer=self.observe,
        )
        self.context = None

    def available(self):
        if self.lifecycle.cancelled() or (
            self.profile.expires_at and self.profile.expires_at <= datetime.now(UTC)
        ):
            raise SessionUnavailable("browser identity expired or cancelled")

    def observe(self, identity_id, request, status, document):
        probe = self.profile.probe
        if identity_id != self.profile.id or request != probe.request:
            return
        actual = pointer(document, probe.identity_pointer)
        self.proof["identity_proof"]["probes"].append(
            {
                "phase": self.phase,
                "identity_id": identity_id,
                "method": request.method,
                "url": request.url,
                "pointer": probe.identity_pointer,
                "probe_binding": probe_binding(probe),
                "status": status,
                "observed_identity": probe.expected_identity
                if same_value(actual, probe.expected_identity)
                else None,
                "observed_at": datetime.now(UTC).isoformat(),
            }
        )

    def before(self):
        self.available()
        self.context = self.sessions.context(self.profile.id, action_owner=self.context_id)
        if not self.sessions.verify(self.profile.id, action_owner=self.context_id):
            raise SessionUnavailable("browser identity probe failed")
        self.available()
        self.verified_before = True
        return self.context

    def headers(self, url, headers):
        self.available()
        if canonical_origin(url) != self.origin:
            raise SessionUnavailable("browser credential origin mismatch")
        result = dict(headers)
        for name, ref in self.profile.supplied_headers.items():
            # Case-insensitive replacement avoids a stale duplicate auth header.
            result = {key: value for key, value in result.items() if key.lower() != name.lower()}
            result[name] = self.lifecycle.secret_resolver(ref).get_secret_value()
        self.available()
        return result

    def navigate(self, route, rendered_request, body, *, supply_headers=True):
        """Fetch through the supplied context API without following redirects.

        route.continue_ propagates overridden headers into redirects. Using the
        existing guarded API preserves broker admission and renders the original
        response while keeping credential headers on this exact request.
        """
        self.available()
        if canonical_origin(rendered_request["url"]) != self.origin:
            raise SessionUnavailable("browser credential origin mismatch")
        headers = (
            self.headers(rendered_request["url"], rendered_request["headers"])
            if supply_headers
            else {}
        )
        response = self.context.request.fetch(
            rendered_request["url"],
            method=rendered_request["method"],
            headers=headers,
            data=body,
            max_redirects=0,
            max_retries=0,
            timeout=10000,
        )
        try:
            self.available()
            if 300 <= response.status < 400:
                self.proof["failure_reason"] = "authenticated_browser_redirect_not_followed"
                raise SessionUnavailable(
                    "authenticated browser redirect requires separate template"
                )
            if len(response.body()) > 1048576:
                raise SessionUnavailable("authenticated browser response exceeds evidence cap")
            route.fulfill(response=response)
        finally:
            response.dispose()

    def finish(self):
        try:
            if self.verified_before:
                self.available()
                self.phase = "after"
                # A direct independent probe cannot run the login recipe again.
                status, document = self.sessions.request(
                    self.profile.id,
                    self.profile.probe.request,
                    action_owner=self.context_id,
                )
                self.available()
                if status != 200 or not same_value(
                    pointer(document, self.profile.probe.identity_pointer),
                    self.profile.probe.expected_identity,
                ):
                    raise SessionUnavailable("browser identity probe failed")
            if self.failed:
                raise SessionUnavailable("browser authenticated request rejected")
        finally:
            self.sessions.close()


def evaluate_browser_input_identity(profile, task, template, plan_id, proofs, captures):
    """Require three independent before/after pairs bound to the frozen input task."""
    try:
        if (
            not isinstance(proofs, list)
            or len(proofs) != 3
            or not isinstance(captures, list)
            or len(captures) != 3
        ):
            return False, "browser_identity_context_proofs_required"
        context_ids = set()
        for name, proof, capture in zip(PROBE_NAMES, proofs, captures, strict=True):
            context_id = proof.get("context_id")
            inner = proof.get("identity_proof")
            if (
                proof.get("version") != BROWSER_IDENTITY_VERSION
                or proof.get("name") != name
                or capture.get("name") != name
                or not isinstance(context_id, str)
                or len(context_id) != 32
                or context_id in context_ids
                or capture.get("context_id") != context_id
                or not isinstance(inner, dict)
                or inner.get("context_id") != context_id
                or inner.get("browser_probe_name") != name
                or inner.get("rendered_origin") != canonical_origin(template.origin)
            ):
                return False, "browser_identity_context_binding_mismatch"
            context_ids.add(context_id)
            valid, reason = evaluate_input_identity(profile, task, template, plan_id, inner)
            if not valid:
                return False, reason
    except (AttributeError, TypeError, ValueError):
        return False, "browser_identity_proof_invalid"
    return True, "browser_before_after_identity_probes_verified"
