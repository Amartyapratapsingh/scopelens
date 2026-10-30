"""Bind page-ledger exemptions to frozen, bounded active tasks.

This is accounting authority, not a destination grant: ordinary scope, DNS and shared
request-budget checks still apply. Workers cannot obtain an exemption with a generic
purpose header or a discovered URL. The reference must match a frozen reviewed task.
"""

import hashlib
import json
import re
from functools import lru_cache
from urllib.parse import parse_qsl, quote, urlsplit

from scopelens.domain.assessment import AssessmentPlanVersion, RequestTemplate, stable_id
from scopelens.domain.registry import load_registry
from scopelens.scope.validator import ScopeViolation

PROBE_HEADER = "x-scopelens-reviewed-probe"
CONDITIONAL_CONTROLS = {
    "sql": "SL-C03-SQL-01",
    "xss": "SL-C03-XSS-01",
    "html": "SL-C03-HTML-01",
    "redirect": "SL-C04-REDIRECT-01",
    "cors": "SL-C04-CORS-01",
}
INPUT_CONTROLS = frozenset(
    [*CONDITIONAL_CONTROLS.values(), "SL-C03-DOMXSS-01", "SL-C04-HDRINJECT-01"]
)


def conditional_reference(entry):
    digest = hashlib.sha256(
        json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return "conditional:" + digest


def input_reference(task_id):
    return "input:" + task_id


@lru_cache(maxsize=4)
def _registry(directory):
    return load_registry(directory)


def _same_origin(origin, request):
    parts = urlsplit(origin)
    return (
        parts.scheme,
        parts.hostname,
        parts.port or (443 if parts.scheme == "https" else 80),
    ) == (
        request.scheme,
        request.host,
        request.port,
    )


def _template_matches(template, input_key, request):
    target = urlsplit(request.path)
    path = template.path
    path_inputs = [i for i in template.inputs if i.location == "path"]
    if path_inputs:
        path = re.escape(template.route_template)
        for item in path_inputs:
            pattern = (
                "[^/]+"
                if item.key == input_key
                else re.escape(quote(str(item.baseline_value), safe=""))
            )
            path = path.replace(re.escape("{" + item.name + "}"), pattern)
        if not re.fullmatch(path, target.path):
            return False
    elif target.path != path:
        return False
    query = parse_qsl(target.query, keep_blank_values=True, max_num_fields=1024)
    expected = [i for i in template.inputs if i.location == "query"]
    return len(query) == len(expected) and all(
        name == item.name
        and (
            item.key == input_key
            or item.secret_ref
            or value == ("" if item.baseline_value is None else str(item.baseline_value))
        )
        for (name, value), item in zip(query, expected, strict=True)
    )


def reviewed_request_limit(scan, scope, settings, request, *, allowed_controls=None):
    """Return the existing control request cap, or reject an invalid task reference."""
    reference = request.probe_task
    plan = scan.assessment_plan or {}
    control_id = None
    matches = False
    if request.method != "GET" or not scope.allowed_check_profile.includes_active_pack:
        raise ScopeViolation("reviewed probe accounting requires an active-profile GET task")
    if reference.startswith("conditional:"):
        for entry in plan.get("conditional_probes", []):
            if conditional_reference(entry) != reference:
                continue
            control_id = CONDITIONAL_CONTROLS.get(entry.get("kind"))
            parts = urlsplit(request.path)
            query = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=1024)
            matches = (
                _same_origin(scope.origin, request)
                and parts.path == entry.get("path")
                and (
                    not query
                    if entry.get("kind") == "cors"
                    else len(query) == 1 and query[0][0] == entry.get("parameter")
                )
            )
            break
    elif reference.startswith("input:"):
        frozen = plan.get("input_assessment_plan")
        catalogue = plan.get("request_catalogue", {})
        if frozen and scope.allowed_check_profile.expanded:
            assessment = AssessmentPlanVersion.model_validate(frozen)
            claim = plan.get("assessment_execution_claims", {}).get("task:" + reference[6:], {})
            if (
                assessment.scope_version == str(scan.scope_version_id)
                and assessment.profile == scope.allowed_check_profile.value
                and assessment.catalogue_hash == stable_id(catalogue)
                and claim.get("plan_id") == assessment.id
                and claim.get("state") == "admitted"
            ):
                task = next(
                    (t for t in assessment.tasks if input_reference(t.id) == reference), None
                )
                if task and task.state == "ready" and task.control_id in INPUT_CONTROLS:
                    raw = next(
                        (
                            t
                            for t in catalogue.get("templates", [])
                            if t.get("id") == task.template_id
                        ),
                        None,
                    )
                    if raw:
                        template = RequestTemplate.model_validate(raw)
                        mutable = task.input_key is None or any(
                            i.key == task.input_key and i.mutable for i in template.inputs
                        )
                        control_id = task.control_id
                        matches = (
                            template.authority in {"primary", "scan"}
                            and template.baseline_complete
                            and template.method == request.method
                            and mutable
                            and _same_origin(template.origin, request)
                            and _template_matches(template, task.input_key, request)
                        )
    control = _registry(settings.checks_registry_dir).get(control_id) if control_id else None
    if not matches or control is None:
        raise ScopeViolation("request does not match a frozen reviewed probe task")
    if allowed_controls is not None and control.id not in allowed_controls:
        raise ScopeViolation("reviewed control does not permit this capture")
    if (
        request.method not in control.allowed_action.methods
        or control.allowed_action.max_requests < 1
    ):
        raise ScopeViolation("reviewed control does not permit this request")
    return control.allowed_action.max_requests
