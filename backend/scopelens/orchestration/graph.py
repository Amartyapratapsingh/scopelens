"""Baseline-first LangGraph with a durable, fenced hypothesis ledger.

Postgres owns resumability. An admitted operation never replays after a lost outcome.
The graph schedules reviewed work; it does not give a model a shell or network client.
"""

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import TypedDict
from urllib.parse import urlsplit

from langgraph.graph import END, START, StateGraph
from sqlalchemy import select

from scopelens.execution.supervisor import (
    ARTIFACT_MARKER,
    SupervisorError,
    WorkerResult,
    WorkerSpec,
)
from scopelens.persistence.models import ScanRow
from scopelens.persistence.repositories import record_audit
from scopelens.persistence.session import session_scope


class State(TypedDict, total=False):
    candidates: list[dict]
    selected: dict | None
    finished: int
    stop: bool
    stop_reason: str


def _frozen_binding_matches(candidate, saved, scope, scan):
    """A proposal is valid only for the plan and scope that produced it."""
    from scopelens.domain.assessment import stable_id

    if candidate.get("operation") == "csp-recheck":
        return True
    plan = saved.get("input_assessment_plan") or {}
    catalogue = saved.get("request_catalogue") or {}
    return bool(
        candidate.get("plan_id") == plan.get("id")
        and candidate.get("scope_version") == plan.get("scope_version")
        and candidate.get("catalogue_hash") == plan.get("catalogue_hash")
        and plan.get("catalogue_hash") == stable_id(catalogue)
        and catalogue.get("origin") == scope.origin
        and str(plan.get("scope_version")) == str(scan.scope_version_id)
        and str(scope.id) == str(scan.scope_version_id)
    )


def candidates_from(artifacts, max_tasks, *, ledger=None):
    candidates = []
    seen = set()
    for artifact in reversed(artifacts):
        if artifact.get("kind") != "response":
            continue
        response = artifact.get("data", {})
        route = response.get("route", "")
        observed_url = response.get("url", "").split("#", 1)[0]
        if (
            not route.startswith("/")
            or route.startswith("//")
            or not observed_url
            or observed_url in seen
        ):
            continue
        if response.get("status") != 200 or "html" not in (response.get("content_type") or ""):
            continue
        if response.get("headers", {}).get("content-security-policy"):
            continue
        # Discovery supplies a signal, not instructions. Only the exact already-observed
        # URL is eligible for this registered read-only confirmation operation.
        seen.add(observed_url)
        signal = hashlib.sha256(
            json.dumps(
                {
                    "url": observed_url,
                    "route": route,
                    "status": response.get("status"),
                    "content_type": response.get("content_type"),
                    "csp": response.get("headers", {}).get("content-security-policy"),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        history = [
            row
            for row in (ledger or [])
            if row.get("operation") == "csp-recheck" and row.get("url") == observed_url
        ]
        if len(history) >= 3 or any(
            row.get("signal_hash") == signal
            or row.get("state") in {"corroborated", "contradicted", "outcome_unknown"}
            for row in history
        ):
            continue
        identity = hashlib.sha256(("csp-recheck|" + route + "|" + signal).encode()).hexdigest()
        candidates.append(
            {
                "id": identity,
                "route": route,
                "url": response["url"],
                "control": "SL-C04-CSP-01",
                "signal_hash": signal,
                "signal": "HTML response lacks an enforcing CSP",
                "alternative": "A cache or route variant omitted the header",
                "expected_evidence": "Fresh no-cache HTTP response on the observed route",
                "stop_condition": "One fresh response or any error",
                "round": len(history) + 1,
                "max_requests": 2,
                "operation": "csp-recheck",
            }
        )
        if len(candidates) >= max_tasks:
            break
    return candidates


def run_graph(settings, *, scan_id, scope, limits, token, run_id, supervisor, baseline):
    output = None
    pending = None

    def authorized(db, scan):
        from scopelens.broker.policy import scan_for_token
        from scopelens.execution.leases import lease_is_live

        live = scan_for_token(db, token)
        now = datetime.now(UTC)
        return bool(
            live is not None
            and live.id == scan_id
            and not scan.cancel_requested_at
            and scan.cancel_epoch == scan.egress_token_epoch
            and scope.authorization_expires_at > now
            and lease_is_live(db, scan_id, now=now)
        )

    def baseline_node(state):
        nonlocal output
        output = baseline()
        if scope.allowed_check_profile.expanded and settings.callbacks_enabled:
            from scopelens.orchestration.followup_contexts import append_callback_observations

            output = append_callback_observations(settings, output, scan_id=scan_id)
        artifacts = output.artifacts()
        observed_tasks = {
            a.get("data", {}).get("task_id")
            for a in artifacts
            if isinstance(a.get("data"), dict) and a.get("kind") == "expanded_active_probe"
        }
        with session_scope(settings) as db:
            scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
            saved = dict(scan.assessment_plan or {})
            tasks = saved.get("input_assessment_plan", {}).get("tasks", [])
            # Baseline has returned and will not be replayed. Record its outstanding
            # denominator and reservations before spending any optional request budget.
            saved["baseline_obligations"] = {
                "run_returned": True,
                "worker_succeeded": output.succeeded,
                "spent_requests": (scan.budget_spent or {}).get("requests", 0),
                "reserved_requests": (scan.budget_reserved or {}).get("requests", 0),
                "planned_task_ids": [t["id"] for t in tasks],
                "missing_capture_task_ids": [
                    t["id"] for t in tasks if t["id"] not in observed_tasks
                ],
                "blocked_task_ids": [t["id"] for t in tasks if t["state"] == "blocked"],
                "coverage_authority": "none; final proof evaluation retains every frozen task",
            }
            saved["baseline_complete_before_adaptation"] = output.succeeded
            saved["baseline_finished_before_adaptation"] = True
            scan.assessment_plan = saved
            stop = not authorized(db, scan) or output.killed or output.timed_out or not artifacts
        return {
            "finished": 0,
            "stop": stop,
            "stop_reason": "baseline_or_authority_unavailable" if stop else "",
        }

    def observe(state):
        if state.get("stop"):
            return {"candidates": []}
        with session_scope(settings) as db:
            scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
            if not authorized(db, scan):
                return {"candidates": [], "stop": True, "stop_reason": "authority_unavailable"}
            saved = dict(scan.assessment_plan or {})
            ledger = saved.get("hypotheses", [])
            if (
                scope.allowed_check_profile.expanded
                and saved.get("request_catalogue")
                and saved.get("input_assessment_plan")
            ):
                from scopelens.domain.assessment import AssessmentPlanVersion, DiscoveryCatalogue
                from scopelens.orchestration.expansion import hypotheses_from

                hypotheses = hypotheses_from(
                    output.artifacts(),
                    DiscoveryCatalogue.model_validate(saved["request_catalogue"]),
                    AssessmentPlanVersion.model_validate(saved["input_assessment_plan"]),
                    max_tasks=settings.adaptive_max_tasks * 3,
                    ledger=ledger,
                    configuration=saved.get("expansion_config"),
                    browser_available=settings.browser_enabled,
                    access_available=True,
                    callback_available=settings.callbacks_enabled,
                )
                gaps = {h["id"]: h for h in saved.get("adaptive_gaps", [])}
                gaps.update({h.id: h.model_dump() for h in hypotheses if h.state == "blocked"})
                scan.assessment_plan = {**saved, "adaptive_gaps": list(gaps.values())}
                candidates = [h.model_dump() for h in hypotheses if h.state == "ready"]
            else:
                candidates = candidates_from(
                    output.artifacts(), settings.adaptive_max_tasks, ledger=ledger
                )
            remaining = (
                limits.max_requests
                - (scan.budget_spent or {}).get("requests", 0)
                - (scan.budget_reserved or {}).get("requests", 0)
            )
            candidates = [
                c
                for c in candidates
                if c["round"] <= settings.adaptive_max_rounds and c["max_requests"] <= remaining
            ]
            return {"candidates": candidates[: settings.adaptive_max_tasks]}

    def plan(state):
        candidates = state["candidates"]
        if state.get("stop") or not candidates or state["finished"] >= settings.adaptive_max_tasks:
            reason = (
                "task_limit"
                if state["finished"] >= settings.adaptive_max_tasks
                else "no_eligible_followup"
            )
            return {
                "selected": None,
                "stop": True,
                "stop_reason": state.get("stop_reason") or reason,
            }
        chosen = candidates[0]
        from scopelens.config import REPO_ROOT
        from scopelens.orchestration.models import call_model
        from scopelens.skills import load_pack

        skill = load_pack(REPO_ROOT / "skills", "discovery")
        model = call_model(
            settings, scan_id, "planner", {"candidates": candidates, "procedure": skill}
        )
        if model.get("state") == "completed":
            wanted = model["value"]["candidate_id"]
            chosen = next((c for c in candidates if c["id"] == wanted), chosen)
        return {
            "selected": chosen,
            "candidates": [c for c in candidates if c["id"] != chosen["id"]],
        }

    def admit(state):
        selected = state["selected"]
        with session_scope(settings) as db:
            scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
            if (
                not authorized(db, scan)
                or not (scan.assessment_plan or {})
                .get("baseline_obligations", {})
                .get("run_returned")
                or (scan.budget_spent or {}).get("requests", 0)
                + (scan.budget_reserved or {}).get("requests", 0)
                + selected["max_requests"]
                > limits.max_requests
            ):
                return {"stop": True, "stop_reason": "authority_or_request_budget_unavailable"}
            ledger = list((scan.assessment_plan or {}).get("hypotheses", []))
            if not _frozen_binding_matches(selected, scan.assessment_plan or {}, scope, scan):
                return {"stop": True, "stop_reason": "frozen_binding_changed"}
            if any(x["id"] == selected["id"] for x in ledger):
                # A prior admitted outcome could be unknown. Do not replay it.
                return {"stop": True, "stop_reason": "already_admitted"}
            if selected["round"] > settings.adaptive_max_rounds:
                return {"stop": True, "stop_reason": "round_limit"}
            ledger.append(
                {
                    **selected,
                    "state": "outcome_unknown",
                    "run_id": run_id + "-adaptive-" + str(state["finished"]),
                    "cost": None,
                    "model_permissions": "proposal_only",
                }
            )
            scan.assessment_plan = {
                **(scan.assessment_plan or {}),
                "hypotheses": ledger,
            }
            if scan.assessment_plan.get("capability_measurement"):
                from scopelens.execution.capability_producer import bind_measurement

                scan.assessment_plan = bind_measurement(
                    scan.assessment_plan,
                    scan_id=scan_id,
                    scope=scope,
                    settings=settings,
                    measurement=scan.assessment_plan["capability_measurement"],
                )
            record_audit(
                db,
                actor="planner",
                action="adaptive.plan",
                subject_type="scan",
                subject_id=str(scan_id),
                outcome="admitted",
                detail={"control": selected["control"], "route": selected["route"]},
            )
        return {"stop": False}

    def execute(state):
        nonlocal pending, output
        c = state["selected"]
        pending = None
        if c is None:
            return {}
        from scopelens.execution.coordinator import _proxy_ca_pem

        endpoint = urlsplit(c["url"])
        expected = urlsplit(scope.origin)
        if (endpoint.scheme, endpoint.netloc) != (expected.scheme, expected.netloc):
            return {"stop": True, "stop_reason": "origin_mismatch"}
        with session_scope(settings) as db:
            scan = db.get(ScanRow, scan_id)
            if not authorized(db, scan) or not _frozen_binding_matches(
                c, scan.assessment_plan or {}, scope, scan
            ):
                return {"stop": True, "stop_reason": "authority_or_binding_changed"}
        child_run = run_id + "-adaptive-" + str(state["finished"])
        module = "scopelens.orchestration.recheck"
        followup_env = {}
        browser_followup = c["operation"] == "browser-reflection-proof"
        access_followup = c["operation"] == "recheck-access"
        if access_followup:
            import secrets

            module = "scopelens.orchestration.access_worker"
            with session_scope(settings) as db:
                scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
                capability = secrets.token_urlsafe(32)
                saved = dict(scan.assessment_plan or {})
                scan.assessment_plan = {
                    **saved,
                    "expansion_capability_hash": hashlib.sha256(capability.encode()).hexdigest(),
                }
            followup_env = {
                "SCOPELENS_FOLLOWUP_INPUT": json.dumps(
                    {
                        "configuration": saved.get("expansion_config"),
                        "proof_id": c["proof_id"],
                    }
                ),
                "SCOPELENS_EXPANSION_CAPABILITY": capability,
            }
        if c["operation"] in {"repeat-input-proof", "recheck-exposure"}:
            module = "scopelens.orchestration.expansion"
            with session_scope(settings) as db:
                saved = dict(db.get(ScanRow, scan_id).assessment_plan or {})
            envelope = json.dumps(
                {
                    "hypothesis": c,
                    "catalogue": saved.get("request_catalogue"),
                    "plan": saved.get("input_assessment_plan"),
                }
            )
            if len(envelope.encode()) > 100000:
                return {"stop": True}
            followup_env["SCOPELENS_FOLLOWUP_INPUT"] = envelope
        spec = WorkerSpec(
            image=settings.tool_worker_image,
            command=["python", "-m", module],
            environment={
                **followup_env,
                "SCOPELENS_TARGET_URL": c["url"],
                "SCOPELENS_EGRESS_TOKEN": token,
                "SCOPELENS_PROXY_CA_PEM": _proxy_ca_pem(settings),
                "HTTPS_PROXY": f"http://{settings.proxy_host}:{settings.proxy_http_port}",
                "HTTP_PROXY": f"http://{settings.proxy_host}:{settings.proxy_http_port}",
                "SCOPELENS_MAX_BODY_BYTES": str(limits.max_response_bytes),
                "SCOPELENS_TASK_TIMEOUT": "10",
                "SCOPELENS_ALLOWED_PREFIXES": ",".join(scope.allowed_path_prefixes),
                "SCOPELENS_EXCLUDED_PATHS": ",".join(scope.excluded_paths),
                "SCOPELENS_BROWSER_MAX_REQUESTS": str(c["max_requests"]),
                "NO_PROXY": "",
            },
            network=settings.worker_network,
            labels={"scopelens.run_id": child_run, "scopelens.scan_id": str(scan_id)},
            max_runtime_seconds=30,
        )
        try:
            if c["operation"] == "verify-callback":
                from scopelens.orchestration.followup_contexts import verify_callback_followup

                pending = verify_callback_followup(
                    settings, candidate=c, scan_id=scan_id, run_id=child_run
                )
            elif browser_followup:
                from scopelens.orchestration.followup_contexts import run_reflection_followup

                pending = run_reflection_followup(
                    settings,
                    supervisor,
                    spec,
                    candidate=c,
                    scan_id=scan_id,
                    run_id=child_run,
                    scope=scope,
                )
            else:
                pending = supervisor.run(spec, run_id=child_run)
        except SupervisorError:
            pending = WorkerResult(child_run, 1, "", "reviewed follow-up unavailable", 0)
        # Reviewed captures join the same trusted intake; summaries/stdout do not.
        additions = []
        for artifact in pending.artifacts():
            if artifact.get("kind") in {
                "response",
                "exposure_pack",
                "expanded_active_probe",
                "identity_observation",
                "identity_response",
                "session_observation",
                "adaptive_gap",
            }:
                additions.append(
                    ARTIFACT_MARKER
                    + json.dumps(
                        {
                            **artifact,
                            "source": "expansion_browser" if browser_followup else "adaptive",
                            "run_id": child_run,
                            "hypothesis_id": c["id"],
                            "plan_id": c.get("plan_id"),
                        }
                    )
                )
        output = replace(
            output,
            stdout=output.stdout + "\n" + "\n".join(additions),
            duration_seconds=output.duration_seconds + pending.duration_seconds,
        )
        return {}

    def verify(state):
        c = state["selected"]
        if c is None:
            return {"finished": state["finished"] + 1}
        captures = pending.artifacts() if pending else []
        capture_hashes = [
            hashlib.sha256(json.dumps(a, sort_keys=True).encode()).hexdigest() for a in captures
        ]
        measured_requests = [
            a["data"]["requests_used"]
            for a in captures
            if a.get("kind") == "expanded_active_probe"
            and isinstance(a.get("data"), dict)
            and isinstance(a["data"].get("requests_used"), int)
        ]
        fresh = next((a.get("data") for a in captures if a.get("kind") == "response"), None)
        outcome = "inconclusive"
        proof_detail = None
        if c["operation"] != "csp-recheck":
            from scopelens.orchestration.expansion import Hypothesis, verify_followup

            with session_scope(settings) as db:
                saved = db.get(ScanRow, scan_id).assessment_plan or {}
            proof_detail = verify_followup(
                Hypothesis.model_validate(c),
                captures,
                configuration=saved.get("expansion_config"),
                frozen_plan=saved.get("input_assessment_plan"),
            )
            outcome = proof_detail["state"]
            fresh = {"captures": captures, "verification": proof_detail}
        elif (
            fresh
            and fresh.get("url") == c["url"]
            and fresh.get("route") == c["route"]
            and fresh.get("status") == 200
            and fresh.get("via_proxy")
            and "html" in (fresh.get("content_type") or "")
        ):
            outcome = (
                "corroborated"
                if not fresh.get("headers", {}).get("content-security-policy")
                else "contradicted"
            )
        from scopelens.orchestration.models import call_model

        challenge = call_model(
            settings, scan_id, "verification", {"hypothesis": c, "outcome": outcome}
        )
        with session_scope(settings) as db:
            scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
            plan = dict(scan.assessment_plan or {})
            ledger = [dict(item) for item in plan.get("hypotheses", [])]
            for entry in ledger:
                if entry["id"] == c["id"]:
                    entry.update(
                        state=outcome,
                        evidence_hash=hashlib.sha256(
                            json.dumps(fresh, sort_keys=True).encode()
                        ).hexdigest()
                        if fresh
                        else None,
                        proof_detail=proof_detail,
                        capture_hashes=capture_hashes,
                        request_count=sum(measured_requests) if measured_requests else None,
                        worker_exit_code=pending.exit_code if pending else None,
                        challenge=challenge.get("value"),
                        cost=challenge.get("cost"),
                    )
            scan.assessment_plan = {**plan, "hypotheses": ledger}
            record_audit(
                db,
                actor="verifier",
                action="adaptive.complete",
                subject_type="scan",
                subject_id=str(scan_id),
                outcome=outcome,
                detail={"control": c["control"], "route": c["route"]},
            )
        return {"finished": state["finished"] + 1}

    graph = StateGraph(State)
    for name, node in [
        ("baseline", baseline_node),
        ("observe", observe),
        ("plan", plan),
        ("admit", admit),
        ("execute", execute),
        ("verify", verify),
    ]:
        graph.add_node(name, node)
    graph.add_edge(START, "baseline")
    graph.add_edge("baseline", "observe")
    graph.add_edge("observe", "plan")
    graph.add_conditional_edges("plan", lambda s: END if s.get("stop") else "admit")
    graph.add_conditional_edges("admit", lambda s: END if s.get("stop") else "execute")
    graph.add_edge("execute", "verify")
    graph.add_edge("verify", "observe")
    final_state = graph.compile().invoke(
        {}, {"recursion_limit": 10 + settings.adaptive_max_tasks * 6}
    )
    with session_scope(settings) as db:
        scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
        scan.assessment_plan = {
            **(scan.assessment_plan or {}),
            "adaptive_stop": {
                "reason": final_state.get("stop_reason") or "no_eligible_followup",
                "completed_followups": final_state.get("finished", 0),
            },
        }
    from scopelens.orchestration.scripts import analyze_local

    analyze_local(settings, scan_id, output.artifacts(), token=token)
    return output
