"""Typed multi-family follow-ups. Discovery proposes; frozen policy remains authority.

Follow-ups have explicit proof goals and cost bounds. Model text can choose a registered
candidate ID but cannot create an operation, change an input, or supply a proof verdict.
"""

import hashlib
import json
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from scopelens.domain.assessment import AssessmentPlanVersion, DiscoveryCatalogue, stable_id


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    family: Literal["reflection", "sql", "access", "component", "redirect", "exposure", "callback"]
    route: str
    url: str
    control: str
    signal_hash: str
    signal: str
    alternative: str
    expected_evidence: str
    stop_condition: str
    operation: Literal[
        "repeat-input-proof",
        "recheck-exposure",
        "reobserve-component",
        "browser-reflection-proof",
        "recheck-access",
        "verify-callback",
    ]
    state: Literal["ready", "blocked"] = "ready"
    reason: str = ""
    round: int = Field(default=1, ge=1, le=3)
    max_requests: int = Field(ge=0, le=26)
    priority: int = Field(ge=0, le=100)
    task_id: str | None = None
    template_id: str | None = None
    proof_id: str | None = None
    plan_id: str
    scope_version: str
    catalogue_hash: str


def semantic_signal(value):
    """Drop capture bookkeeping, not observed content, from repeat detection."""
    ignored = {
        "timestamp",
        "captured_at",
        "at",
        "run_id",
        "evidence_ref",
        "evidence_refs",
        "request_id",
        "duration_seconds",
    }
    if isinstance(value, dict):
        return {k: semantic_signal(v) for k, v in value.items() if k not in ignored}
    if isinstance(value, list):
        return [semantic_signal(v) for v in value]
    return value


def reviewed_signal(kind: str, data: dict) -> dict:
    """Only collector evidence fields can justify another follow-up round."""
    fields = {
        "response": (
            "url",
            "route",
            "status",
            "content_type",
            "headers",
            "body_excerpt",
            "truncated",
            "via_proxy",
        ),
        "expanded_active_probe": (
            "task_id",
            "plan_id",
            "template_id",
            "control_id",
            "input_key",
            "kind",
            "state",
            "captures",
        ),
        "exposure_observation": (
            "family",
            "url",
            "state",
            "status",
            "body_hash",
            "negative_control_hash",
            "bytes_read",
            "truncated",
        ),
    }
    allowed = fields.get(kind, ())
    selected = {key: data[key] for key in allowed if key in data}
    if kind == "expanded_active_probe":
        capture_fields = {
            "name",
            "group",
            "status",
            "body_hash",
            "normalized_hash",
            "truncated",
            "response_url_matches",
            "controlled_location",
            "marker_header",
            "marker_header_matches",
            "nonce",
            "ignored_noise_fields",
        }
        selected["captures"] = [
            {key: value for key, value in capture.items() if key in capture_fields}
            for capture in data.get("captures", [])
            if isinstance(capture, dict)
        ]
    return semantic_signal(selected)


def _hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def hypotheses_from(
    artifacts: list[dict],
    catalogue: DiscoveryCatalogue,
    plan: AssessmentPlanVersion,
    *,
    max_tasks: int = 12,
    ledger: list[dict] | None = None,
    configuration: dict | None = None,
    browser_available: bool = False,
    access_available: bool = False,
    callback_available: bool = False,
) -> list[Hypothesis]:
    if plan.catalogue_hash != stable_id(catalogue.model_dump(mode="json")):
        return []
    tasks = {t.id: t for t in plan.tasks}
    templates = {t.id: t for t in catalogue.templates}
    output = []
    prior = ledger or []

    def add(
        family,
        data,
        *,
        url,
        control,
        signal,
        alternative,
        expected,
        operation,
        requests,
        priority,
        task=None,
        reason="",
        signal_data=None,
        proof_id=None,
    ):
        p = urlsplit(url)
        target = urlsplit(catalogue.origin)
        if (
            (p.scheme, p.netloc) != (target.scheme, target.netloc)
            or p.username
            or p.password
            or p.fragment
        ):
            return
        digest = _hash(signal_data if signal_data is not None else semantic_signal(data))
        identity = _hash([family, operation, url, control, digest])
        history = [
            x
            for x in prior
            if x.get("family") == family and x.get("url") == url and x.get("control") == control
        ]
        if (
            any(x.get("id") == identity or x.get("signal_hash") == digest for x in history)
            or any(
                x.get("state") in {"corroborated", "contradicted", "outcome_unknown"}
                for x in history
            )
            or len(history) >= 3
        ):
            return
        output.append(
            Hypothesis(
                id=identity,
                family=family,
                route=p.path or "/",
                url=url,
                control=control,
                signal_hash=digest,
                signal=signal,
                alternative=alternative,
                expected_evidence=expected,
                stop_condition="One reviewed proof series; stop on denial, cancellation, exhausted budget or unchanged evidence",
                operation=operation,
                state="blocked" if reason else "ready",
                reason=reason,
                round=len(history) + 1,
                max_requests=requests,
                priority=priority,
                task_id=task.id if task else None,
                template_id=task.template_id if task else None,
                proof_id=proof_id,
                plan_id=plan.id,
                scope_version=plan.scope_version,
                catalogue_hash=plan.catalogue_hash,
            )
        )

    for artifact in artifacts:
        data = artifact.get("data", {})
        if not isinstance(data, dict):
            continue
        if artifact.get("kind") == "expanded_active_probe" and data.get("state") in {
            "inconclusive",
            "potential",
            "blocked",
        }:
            task = tasks.get(data.get("task_id"))
            template = templates.get(task.template_id) if task else None
            if task is None or template is None or task.state != "ready":
                continue
            if template.authority != "primary":
                continue
            family = data.get("kind")
            reason = (
                ""
                if template.method == "GET"
                and template.role_id == "anonymous"
                and not any(i.secret_ref for i in template.inputs)
                else "Follow-up requires an identity/action capability; anonymous worker cannot inherit it"
            )
            if family in {"xss", "html", "dom_xss"}:
                add(
                    "reflection",
                    data,
                    url=template.origin + template.path,
                    control=task.control_id,
                    signal="Input observation lacks independent browser execution proof",
                    alternative="Text reflection or inert escaped markup",
                    expected="Fresh controlled browser marker execution versus inert control",
                    operation="browser-reflection-proof",
                    requests=6,
                    priority=90,
                    task=task,
                    reason=reason
                    or (
                        "" if browser_available else "Controlled browser follow-up context required"
                    ),
                    signal_data=reviewed_signal("expanded_active_probe", data),
                )
            elif family in {"sql", "redirect"}:
                add(
                    family,
                    data,
                    url=template.origin + template.path,
                    control=task.control_id,
                    signal="Repeated input series was inconclusive",
                    alternative="Dynamic response noise"
                    if family == "sql"
                    else "Conditional navigation or inconsistent response",
                    expected="Fresh baseline and negative controls with repeated matching proof",
                    operation="repeat-input-proof",
                    requests=26 if family == "sql" else 5,
                    priority=85,
                    task=task,
                    reason=reason,
                    signal_data=reviewed_signal("expanded_active_probe", data),
                )
        elif artifact.get("kind") == "exposure_pack":
            for observation in data.get("observations", []):
                if observation.get("state") not in {"exposed", "candidate", "inconclusive"}:
                    continue
                from scopelens.checks.packs.exposure import CONTROL_IDS

                family = observation.get("family")
                if family not in CONTROL_IDS:
                    continue
                add(
                    "exposure",
                    observation,
                    url=observation.get("url", ""),
                    control=CONTROL_IDS[family],
                    signal="Possible exposed private configuration or diagnostic structure",
                    alternative="Fallback rewrite, masked data or transient diagnostic page",
                    expected="Fresh bounded response plus independently randomized same-directory negative control",
                    operation="recheck-exposure",
                    requests=4,
                    priority=80,
                    signal_data=reviewed_signal("exposure_observation", observation),
                )
        elif artifact.get("kind") == "response":
            from scopelens.checks.packs.exposure import identify_components

            url = data.get("url", "")
            components = identify_components(
                url, data.get("headers", {}), data.get("body_excerpt", "")
            )
            if components and not all(c.identity_corroborated for c in components):
                add(
                    "component",
                    data,
                    url=url,
                    control="SL-C06-COMPONENT-01",
                    signal="Version identity has only one passive observation form",
                    alternative="Stale banner, bundled code comment, patched build or incorrect package identity",
                    expected="Fresh component identity observation; CVE applicability remains a candidate",
                    operation="reobserve-component",
                    requests=2,
                    priority=40,
                    signal_data=reviewed_signal("response", data),
                )
        elif artifact.get("kind") in {
            "identity_observation",
            "identity_response",
            "callback_capture",
            "callback_investigation",
        }:
            config = configuration or {}
            if artifact["kind"] in {"callback_capture", "callback_investigation"}:
                # Worker callback diagnostics never supply leads or confirmation authority.
                if artifact.get("source") != "callback_broker":
                    continue
                named = next(
                    (
                        r
                        for r in config.get("callback_recipes", [])
                        if r.get("id") == data.get("recipe_id")
                    ),
                    None,
                )
                if named is None:
                    continue
                recipe = named["recipe"]
                family, url = "callback", recipe["target_url"]
                control = "SL-C07-SSRF-02" if recipe["family"] == "ssrf" else "SL-C03-XXE-02"
                ready = callback_available and bool(data.get("dispatches"))
                proof_id = named["id"]
            else:
                if data.get("proof_type") != "access":
                    continue
                matrix = config.get("permission_matrix") or {}
                rule = next(
                    (r for r in matrix.get("rules", []) if r.get("id") == data.get("proof_id")),
                    None,
                )
                target = next(
                    (
                        o
                        for o in matrix.get("objects", [])
                        if rule and o.get("id") == rule.get("object_id")
                    ),
                    None,
                )
                if rule is None or target is None:
                    continue
                family, url = "access", target["request"]["url"]
                control = "SL-C09-" + rule["family"].upper() + "-01"
                from scopelens.orchestration.followup_contexts import access_configuration

                proof_id = rule["id"]
                ready = access_available and access_configuration(config, proof_id) is not None
            add(
                family,
                data,
                url=url,
                control=control,
                signal="Comparison/correlation needs independently reviewed follow-up authority",
                alternative="Expired session or shared data"
                if family == "access"
                else "Scanner callback or unknown egress attribution",
                expected="Identity-bound marker read-back"
                if family == "access"
                else "Signed target HTTP receipts plus negative control",
                operation="recheck-access" if family == "access" else "verify-callback",
                requests=12 if family == "access" else 0,
                priority=95,
                reason=""
                if ready
                else "Identity/collector follow-up contract required; no anonymous fallback",
                proof_id=proof_id,
                signal_data=semantic_signal(
                    {
                        key: data[key]
                        for key in (
                            "proof_id",
                            "recipe_id",
                            "identity_id",
                            "method",
                            "url",
                            "status",
                            "document",
                            "probe_binding",
                            "dispatches",
                            "recipe_digest",
                            "task_id",
                        )
                        if key in data
                    }
                ),
            )

    unique = {h.id: h for h in output}
    return sorted(unique.values(), key=lambda h: (-h.priority, h.id))[:max_tasks]


def select_hypothesis(
    candidates: list[Hypothesis],
    *,
    remaining_requests: int,
    protected_baseline_requests: int = 0,
    chosen_id: str | None = None,
):
    allowed = [
        h
        for h in candidates
        if h.state == "ready"
        and h.max_requests <= max(0, remaining_requests - protected_baseline_requests)
    ]
    if not allowed:
        return None
    return next((h for h in allowed if h.id == chosen_id), allowed[0])


def verify_followup(
    hypothesis: Hypothesis, artifacts: list[dict], *, configuration=None, frozen_plan=None
) -> dict:
    """Proof result comes from registered captures, never an LLM's claimed confidence."""
    if hypothesis.operation in {"repeat-input-proof", "browser-reflection-proof"}:
        from scopelens.checks.expanded_active import evaluate_expanded

        expected_kind = {
            "SL-C03-XSS-01": "xss",
            "SL-C03-HTML-01": "html",
            "SL-C03-DOMXSS-01": "dom_xss",
        }.get(hypothesis.control, hypothesis.family)
        frozen_task = next(
            (
                task
                for task in (frozen_plan or {}).get("tasks", [])
                if task["id"] == hypothesis.task_id
            ),
            None,
        )

        rows = [
            a.get("data", {})
            for a in artifacts
            if a.get("kind") == "expanded_active_probe"
            and a.get("data", {}).get("task_id") == hypothesis.task_id
            and a.get("data", {}).get("template_id") == hypothesis.template_id
            and a.get("data", {}).get("plan_id") == hypothesis.plan_id
            and a.get("data", {}).get("control_id") == hypothesis.control
            and a.get("data", {}).get("kind") == expected_kind
            and (
                frozen_plan is None
                or (
                    frozen_task is not None
                    and a.get("data", {}).get("input_key") == frozen_task.get("input_key")
                )
            )
            and a.get("data", {}).get("reviewed") is True
        ]
        if rows:
            state, reason = evaluate_expanded(rows[0]["kind"], rows[0].get("captures", []))
            return {
                "state": "corroborated"
                if state == "confirmed"
                else "contradicted"
                if state == "pass"
                else "inconclusive",
                "reason": reason,
                "proof_state": state,
            }
    elif hypothesis.operation == "recheck-exposure":
        rows = [
            o
            for a in artifacts
            if a.get("kind") == "exposure_pack"
            for o in a.get("data", {}).get("observations", [])
            if o.get("url") == hypothesis.url
        ]
        if rows:
            state = rows[0].get("state")
            return {
                "state": "corroborated"
                if state == "exposed"
                else "contradicted"
                if state == "clear"
                else "inconclusive",
                "reason": rows[0].get("reason", "No classification"),
                "proof_state": state,
            }
    elif hypothesis.operation == "reobserve-component":
        from scopelens.checks.packs.exposure import identify_components

        for artifact in artifacts:
            data = artifact.get("data", {})
            if (
                artifact.get("kind") == "response"
                and data.get("url") == hypothesis.url
                and data.get("status") == 200
                and data.get("via_proxy")
            ):
                rows = identify_components(
                    hypothesis.url, data.get("headers", {}), data.get("body_excerpt", "")
                )
                return {
                    "state": "corroborated" if rows else "contradicted",
                    "reason": "Component identity reobserved; version match does not establish exploitability"
                    if rows
                    else "No component identity in fresh response",
                    "proof_state": "potential",
                }
    elif hypothesis.operation == "recheck-access":
        from scopelens.identities.proof import CapturedIdentityResponse, evaluate_access_proof
        from scopelens.orchestration.followup_contexts import access_configuration

        config = access_configuration(configuration, hypothesis.proof_id)
        if config is not None:
            records = []
            for row in artifacts:
                data = dict(row.get("data", {}))
                if (
                    row.get("kind") != "identity_response"
                    or data.pop("proof_type", None) != "access"
                    or data.pop("proof_id", None) != hypothesis.proof_id
                ):
                    continue
                data["evidence_ref"] = "pending-trusted-intake"
                try:
                    records.append(CapturedIdentityResponse.model_validate(data))
                except ValueError:
                    continue
            result = evaluate_access_proof(
                config.permission_matrix, config.identities, hypothesis.proof_id, tuple(records)
            )
            return {
                "state": "corroborated"
                if result.state == "confirmed"
                else "contradicted"
                if result.state == "pass"
                else "inconclusive",
                "reason": result.reason,
                "proof_state": result.state,
            }
    elif hypothesis.operation == "verify-callback":
        matching = [
            row["data"]
            for row in artifacts
            if row.get("kind") == "callback_followup_verification"
            and row.get("source") == "callback_broker"
            and row.get("data", {}).get("hypothesis_id") == hypothesis.id
        ]
        if len(matching) == 1:
            return matching[0]["verification"]
    return {
        "state": "inconclusive",
        "reason": "Required reviewed proof capture unavailable",
        "proof_state": "inconclusive",
    }


def execute_followup(
    client,
    hypothesis: Hypothesis,
    catalogue: DiscoveryCatalogue,
    plan: AssessmentPlanVersion,
    *,
    cancelled=lambda: False,
):
    if hypothesis.state != "ready":
        return [
            {"kind": "adaptive_gap", "data": {"id": hypothesis.id, "reason": hypothesis.reason}}
        ]
    if (
        hypothesis.plan_id != plan.id
        or hypothesis.scope_version != plan.scope_version
        or hypothesis.catalogue_hash != plan.catalogue_hash
        or plan.catalogue_hash != stable_id(catalogue.model_dump(mode="json"))
        or catalogue.origin
        != urlsplit(hypothesis.url).scheme + "://" + urlsplit(hypothesis.url).netloc
    ):
        return [
            {
                "kind": "adaptive_gap",
                "data": {"id": hypothesis.id, "reason": "Frozen plan or origin changed"},
            }
        ]
    if hypothesis.operation == "repeat-input-proof":
        from scopelens.checks.expanded_active import run_expanded_checks

        tasks = tuple(
            t
            for t in plan.tasks
            if t.id == hypothesis.task_id
            and t.state == "ready"
            and t.template_id == hypothesis.template_id
            and t.control_id == hypothesis.control
            and any(
                template.id == t.template_id
                and template.authority == "primary"
                and template.method == "GET"
                and template.role_id == "anonymous"
                and template.origin + template.path == hypothesis.url
                for template in catalogue.templates
            )
        )
        if not tasks:
            return [{"kind": "adaptive_gap", "data": {"reason": "Frozen task unavailable"}}]
        subset = plan.model_copy(
            update={"tasks": tasks, "denominator": sum(t.coverage_weight for t in tasks)}
        )
        return run_expanded_checks(
            catalogue, subset, client, cancelled=cancelled, max_requests=hypothesis.max_requests
        )
    if hypothesis.operation == "recheck-exposure":
        from scopelens.checks.packs.exposure import collect_exposure_pack

        result = collect_exposure_pack(
            client,
            catalogue.origin,
            technologies=("php", "apache", "spring"),
            discovered_urls=(hypothesis.url,),
            approved_urls=(hypothesis.url,),
            cancelled=cancelled,
            max_requests=hypothesis.max_requests,
        )
        return [{"kind": "exposure_pack", "data": result.model_dump(mode="json")}]
    return [
        {"kind": "adaptive_gap", "data": {"reason": "Operation uses another reviewed collector"}}
    ]


def main():
    import os
    import signal

    from scopelens.checks.crawl import Crawler, config_from_env
    from scopelens.execution.supervisor import ARTIFACT_MARKER, RESULT_MARKER

    cancelled = False

    def cancel(*_args):
        nonlocal cancelled
        cancelled = True

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    payload = json.loads(os.environ["SCOPELENS_FOLLOWUP_INPUT"])
    hypothesis = Hypothesis.model_validate(payload["hypothesis"])
    catalogue = DiscoveryCatalogue.model_validate(payload["catalogue"])
    plan = AssessmentPlanVersion.model_validate(payload["plan"])
    crawler = Crawler(config_from_env())
    with crawler._http() as client:
        artifacts = execute_followup(
            client, hypothesis, catalogue, plan, cancelled=lambda: cancelled
        )
    for artifact in artifacts:
        print(ARTIFACT_MARKER + json.dumps(artifact), flush=True)
    print(
        RESULT_MARKER
        + json.dumps({"outcome": "cancelled" if cancelled else "completed", "body_bytes": 0}),
        flush=True,
    )


if __name__ == "__main__":
    main()
