"""Scan coordinator: the body of the dispatched task (Build Plan §5.2, §5.6).

Runs in the trusted supervisor process. Three phases, each with its own transaction,
because running a worker takes minutes and holding a database transaction open for that
long would block lease renewal and the reconciler:

1. **prepare** — acquire the lease, admit the task, reserve budget, issue the egress
   capability, start the scan. One transaction.
2. **execute** — run the worker. No transaction open. The lease heartbeat renews, and
   cancellation is noticed through it.
3. **finalise** — record evidence and reconcile budget in one transaction. Optional
   report prose runs after that commit with no transaction held and the lease heartbeat
   still active. A second transaction settles the task/scan and releases the lease.

The failure vocabulary matters here and is applied deliberately. A run that was killed
after admitting a request is ``outcome_unknown``, not ``failed`` — Build Plan §5.6, because
marking it failed invites a retry that would repeat a target request whose effect is
already unknown.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.domain.budget import BudgetExceeded, BudgetLimits, BudgetUsage
from scopelens.domain.collection import TLSMeasurement
from scopelens.domain.enums import ProfileName, ScanStatus
from scopelens.domain.evidence import EvidenceOrigin
from scopelens.domain.scope import ScopeVersion
from scopelens.domain.task import TaskState
from scopelens.evidence import intake
from scopelens.evidence.store import LocalDiskEvidenceStore
from scopelens.execution import budget as budget_service
from scopelens.execution.heartbeat import (
    LeaseHeartbeat,
    holder_identity,
    new_run_id,
)
from scopelens.execution.leases import (
    Lease,
    acquire_lease,
    release_lease,
)
from scopelens.execution.ledger import (
    AdmissionRefused,
    admit_task,
    assert_execution_enabled,
    audit_budget_increases,
    budget_limits_for,
    mark_task_failed,
    mark_task_outcome_unknown,
    mark_task_running,
    mark_task_succeeded,
    transition_scan,
)
from scopelens.execution.supervisor import (
    DockerWorkerSupervisor,
    SupervisorError,
    WorkerResult,
    WorkerSpec,
    WorkerSupervisor,
)
from scopelens.persistence.models import (
    AuditEventRow,
    BrowserSessionRow,
    EvidenceRow,
    ScanRow,
    ScopeVersionRow,
    TaskRow,
)
from scopelens.persistence.repositories import record_audit, scope_row_to_domain
from scopelens.persistence.session import session_scope

#: Audit action the broker writes for every admitted request. Read back by the
#: coordinator to decide whether an uncertain outcome may have reached the target.
BROKER_ADMIT_ACTION = "broker.admit"


@dataclass
class CoordinatorResult:
    """What the coordinator did. Returned to Celery and asserted on by tests."""

    scan_id: str
    task_id: str
    task_state: TaskState
    scan_status: ScanStatus | None = None
    reason: str = ""
    evidence_ids: tuple[str, ...] = ()
    requests_admitted: int = 0
    #: False when the coordinator deliberately did nothing — a duplicate delivery, or a
    #: lease held by another coordinator. Distinguishing "did nothing" from "did the work"
    #: is what lets the recovery tests assert that duplicates cause no second run.
    acted: bool = True
    worker_succeeded: bool = False
    extra: dict[str, object] = field(default_factory=dict)


def coordinate(
    settings: Settings,
    *,
    scan_id: uuid.UUID,
    task_id: uuid.UUID,
    attempt_id: str,
    supervisor: WorkerSupervisor | None = None,
    run_id: str | None = None,
    heartbeat_interval: float | None = None,
) -> CoordinatorResult:
    """Drive one dispatched task to a settled state."""
    assert_execution_enabled(settings)
    supervisor = supervisor or DockerWorkerSupervisor(settings)
    run_id = run_id or new_run_id()

    prepared = _prepare(settings, scan_id=scan_id, task_id=task_id)
    if isinstance(prepared, CoordinatorResult):
        return prepared

    lease, scope, limits, egress_token = prepared

    heartbeat = LeaseHeartbeat(settings, lease, interval_seconds=heartbeat_interval)
    heartbeat.start()
    try:
        if isinstance(supervisor, DockerWorkerSupervisor):
            settings = _measure_capabilities(settings, supervisor, scan_id=scan_id, scope=scope)
        tls_measurement = None
        with session_scope(settings) as policy_db:
            frozen_plan = policy_db.get(ScanRow, scan_id).assessment_plan or {}
            adaptive_requested = frozen_plan.get("adaptive_requested")
            recovery_requested = bool(frozen_plan.get("cleanup_recovery"))

        def baseline():
            nonlocal tls_measurement
            if not recovery_requested and scope.lab_binding is None:
                from scopelens.discovery.control import discover_for_scan

                discover_for_scan(settings, scan_id, origin=scope.origin)
            result = _execute(
                settings,
                supervisor=supervisor,
                run_id=run_id,
                scan_id=scan_id,
                scope=scope,
                limits=limits,
                egress_token=egress_token,
            )
            if recovery_requested:
                return result
            if settings.scanner_tools_enabled:
                from scopelens.adapters.tls_client import append_testssl

                result = append_testssl(settings, scope, egress_token, result)
            tls_measurement = _measure_tls_outside_transaction(
                settings, scope=scope, egress_token=egress_token
            )
            return result

        if not recovery_requested and settings.adaptive_enabled and adaptive_requested is not False:
            from scopelens.orchestration.graph import run_graph

            worker_result = run_graph(
                settings,
                scan_id=scan_id,
                scope=scope,
                limits=limits,
                token=egress_token,
                run_id=run_id,
                supervisor=supervisor,
                baseline=baseline,
            )
        else:
            worker_result = baseline()

    except SupervisorError as exc:
        return _finalise(
            settings,
            run_id=run_id,
            lease=lease,
            attempt_id=attempt_id,
            scope=scope,
            egress_token=egress_token,
            worker_result=None,
            reason=f"supervisor error: {exc}",
            lease_lost=False,
        )
    else:
        return _finalise(
            settings,
            run_id=run_id,
            lease=lease,
            attempt_id=attempt_id,
            scope=scope,
            egress_token=egress_token,
            tls_measurement=tls_measurement,
            worker_result=worker_result,
            reason="",
            lease_lost=heartbeat.status.lost,
            heartbeat_note=heartbeat.status.lost_reason,
        )
    finally:
        heartbeat.stop()


# --- Phase 1: prepare ---------------------------------------------------------------


def _measure_capabilities(settings, supervisor, *, scan_id, scope):
    """Offline Docker measurements run without a database transaction or target access."""
    from scopelens.execution.capability_probe import collect_runtime_measurement
    from scopelens.execution.capability_producer import bind_measurement

    refs = {"tool": settings.tool_worker_image}
    if settings.scanner_tools_enabled:
        refs["kali"] = settings.kali_worker_image
    if settings.browser_enabled:
        refs["browser"] = settings.browser_worker_image
    measurement = collect_runtime_measurement(supervisor.client, image_refs=refs)
    # Bind all later launches to the measured immutable IDs, including mutable dev tags.
    fields = {
        "tool": "tool_worker_image",
        "kali": "kali_worker_image",
        "browser": "browser_worker_image",
    }
    settings = settings.model_copy(
        update={fields[row["role"]]: row["image_id"] for row in measurement["image_bindings"]}
    )
    with session_scope(settings) as session:
        scan = session.get(ScanRow, scan_id)
        session.refresh(scan, with_for_update=True)
        from scopelens.execution.leases import lease_is_live

        if (
            scan.cancel_requested_at
            or scan.cancel_epoch != scan.egress_token_epoch
            or not lease_is_live(session, scan_id)
            or scope.is_expired()
        ):
            raise SupervisorError("capability measurement authority revoked")
        if not (scan.assessment_plan or {}).get("cleanup_recovery"):
            scan.assessment_plan = bind_measurement(
                scan.assessment_plan,
                scan_id=scan_id,
                scope=scope,
                settings=settings,
                measurement=measurement,
            )
            scan.assessment_plan = {**scan.assessment_plan, "capability_measurement": measurement}
            record_audit(
                session,
                actor="coordinator",
                action="capability.measurement",
                subject_type="scan",
                subject_id=str(scan_id),
                outcome="measured",
                detail={
                    "installation_complete": measurement["installation_complete"],
                    "source_matched": bool(scan.assessment_plan.get("capability_snapshot")),
                },
            )
    return settings


def _prepare(
    settings: Settings, *, scan_id: uuid.UUID, task_id: uuid.UUID
) -> tuple[Lease, ScopeVersion, BudgetLimits, str] | CoordinatorResult:
    """Acquire authority and admit the work. Returns either the authority or a result
    explaining why nothing was done."""
    from scopelens.broker.policy import issue_egress_token

    with session_scope(settings) as session:
        scan = session.get(ScanRow, scan_id)
        task = session.get(TaskRow, task_id)

        if scan is None or task is None:
            return CoordinatorResult(
                scan_id=str(scan_id),
                task_id=str(task_id),
                task_state=TaskState.FAILED,
                reason="scan or task does not exist",
                acted=False,
            )

        current = TaskState(task.state)
        if current.is_terminal:
            # At-least-once delivery means this is expected, not exceptional.
            return CoordinatorResult(
                scan_id=str(scan_id),
                task_id=str(task_id),
                task_state=current,
                reason=f"task already {current.value}; duplicate delivery ignored",
                acted=False,
            )

        if scan.cancel_requested_at is not None:
            mark_task_failed(
                session, task=task, attempt_id=task.attempt_id, reason="scan was cancelled"
            )
            transition_scan(
                session, scan=scan, target=ScanStatus.CANCELLED, reason="cancelled before dispatch"
            )
            return CoordinatorResult(
                scan_id=str(scan_id),
                task_id=str(task_id),
                task_state=TaskState.FAILED,
                scan_status=ScanStatus.CANCELLED,
                reason="scan was cancelled before this task was admitted",
                acted=False,
            )

        scope_row = session.get(ScopeVersionRow, scan.scope_version_id)
        if scope_row is not None and scope_row_to_domain(scope_row).is_expired():
            reason = "authorization expired while queued; renew scope before starting a new scan"
            mark_task_failed(session, task=task, attempt_id=task.attempt_id, reason=reason)
            transition_scan(session, scan=scan, target=ScanStatus.FAILED, reason=reason)
            scan.reconciled_at = datetime.now(UTC)
            return CoordinatorResult(
                scan_id=str(scan_id),
                task_id=str(task_id),
                task_state=TaskState.FAILED,
                scan_status=ScanStatus.FAILED,
                reason=reason,
            )

        lease = acquire_lease(
            session,
            scan_id=scan_id,
            holder=holder_identity(),
            ttl_seconds=settings.lease_ttl_seconds,
        )
        if lease is None:
            # Another coordinator holds this scan. Doing nothing is the correct action:
            # acting would be the uncontrolled duplicate run the ledger exists to prevent.
            return CoordinatorResult(
                scan_id=str(scan_id),
                task_id=str(task_id),
                task_state=current,
                reason="another coordinator holds a live lease for this scan",
                acted=False,
            )

        scope_row = session.get(ScopeVersionRow, scan.scope_version_id)
        if scope_row is None:
            release_lease(
                session,
                scan_id=scan_id,
                holder=lease.holder,
                fencing_token=lease.fencing_token,
            )
            return CoordinatorResult(
                scan_id=str(scan_id),
                task_id=str(task_id),
                task_state=TaskState.FAILED,
                reason="scan has no scope version",
                acted=False,
            )

        limits = budget_limits_for(scope_row, settings)
        if not (scan.assessment_plan or {}).get("registry"):
            from scopelens.domain.registry import load_registry
            from scopelens.expansion.components import advisory_snapshot_for_profile

            scan.assessment_plan = {
                **(scan.assessment_plan or {}),
                "registry": load_registry(settings.checks_registry_dir).model_dump(mode="json"),
                "advisories": advisory_snapshot_for_profile(
                    ProfileName(scan.profile),
                    registry_dir=settings.checks_registry_dir,
                    legacy_path=settings.advisory_bundle_file,
                ),
                "sampling": "all discovered in-scope routes within recorded crawl limits",
            }
            record_audit(
                session,
                actor="coordinator",
                action="assessment.plan",
                subject_type="scan",
                subject_id=str(scan.id),
                outcome="frozen",
                detail={"schema_version": scan.assessment_plan["registry"]["schema_version"]},
            )
        reserved = BudgetUsage().plus_requests(1)

        try:
            budget_service.reserve(session, scan_id=scan_id, limits=limits, usage=reserved)
            admit_task(session, task=task, fencing_token=lease.fencing_token, reserved=reserved)
        except (BudgetExceeded, AdmissionRefused) as exc:
            release_lease(
                session, scan_id=scan_id, holder=lease.holder, fencing_token=lease.fencing_token
            )
            mark_task_failed(
                session, task=task, attempt_id=task.attempt_id, reason=f"admission refused: {exc}"
            )
            transition_scan(
                session,
                scan=scan,
                target=ScanStatus.COMPLETED_PARTIAL,
                reason=f"admission refused: {exc}",
            )
            scan.reconciled_at = datetime.now(UTC)
            return CoordinatorResult(
                scan_id=str(scan_id),
                task_id=str(task_id),
                task_state=TaskState.FAILED,
                scan_status=ScanStatus.COMPLETED_PARTIAL,
                reason=f"admission refused: {exc}",
            )

        egress_token = issue_egress_token(session, scan=scan)

        if scan.started_at is None:
            audit_budget_increases(
                session, scan=scan, scope_version=scope_row, settings=settings, limits=limits
            )
            scan.started_at = datetime.now(UTC)
        transition_scan(
            session, scan=scan, target=ScanStatus.TESTING, reason="executing the planned check"
        )

        mark_task_running(session, task=task, attempt_id=task.attempt_id)
        record_audit(
            session,
            actor="coordinator",
            action="task.admit",
            subject_type="task",
            subject_id=str(task.id),
            outcome="admitted",
            detail={
                "scan_id": str(scan_id),
                "fencing_token": lease.fencing_token,
                "task_type": task.task_type,
            },
        )
        scope = scope_row_to_domain(scope_row)

    return lease, scope, limits, egress_token


# --- Phase 2: execute ---------------------------------------------------------------


def _proxy_ca_pem(settings: Settings) -> str:
    """Read the proxy's CA certificate so the worker can trust the intercepting proxy.

    Passed as content rather than as a path because the worker has no host mounts: a path
    would name a file it cannot see, which is exactly how the first end-to-end run failed.
    """
    try:
        return settings.proxy_ca_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SupervisorError(
            f"cannot read the proxy CA at {settings.proxy_ca_path}: {exc}. The proxy "
            "generates it on first start, so it must have run at least once."
        ) from exc


def scope_entry_url(scope: ScopeVersion) -> str:
    """Start inside the approved path scope, including for non-root applications."""
    from scopelens.scope.paths import canonical_path

    for path in ("/", *sorted(scope.allowed_path_prefixes, key=lambda p: (len(p), p))):
        path = canonical_path(path)
        if any(path.startswith(prefix) for prefix in scope.allowed_path_prefixes) and not any(
            path.startswith(excluded) for excluded in scope.excluded_paths
        ):
            return scope.origin + path
    raise SupervisorError("scope has no permitted entry path")


def _execute(
    settings: Settings,
    *,
    supervisor: WorkerSupervisor,
    run_id: str,
    scan_id: uuid.UUID,
    scope: ScopeVersion,
    limits: BudgetLimits,
    egress_token: str,
) -> WorkerResult:
    """Run the worker. No transaction is open for the duration."""
    target_url = scope_entry_url(scope)
    with session_scope(settings) as session:
        row = session.get(ScanRow, scan_id)
        retest_routes = (row.assessment_plan or {}).get("retest_routes", []) if row else []
        reviewed_probes = (row.assessment_plan or {}).get("conditional_probes") if row else None
        recovery = (row.assessment_plan or {}).get("cleanup_recovery") if row else None
        task = session.scalar(select(TaskRow).where(TaskRow.scan_id == scan_id))
        recovery_task = task is not None and task.task_type == "cleanup_recovery_verify"
        if bool(recovery) != recovery_task:
            raise SupervisorError("recovery task and immutable plan disagree")
        if recovery_task:
            import hashlib
            import secrets

            capability = secrets.token_urlsafe(32)
            row.assessment_plan = {
                **row.assessment_plan,
                "expansion_capability_hash": hashlib.sha256(capability.encode()).hexdigest(),
            }

    from scopelens.checks.conditional import approvals

    spec = WorkerSpec(
        image=settings.kali_worker_image
        if settings.scanner_tools_enabled
        else settings.tool_worker_image,
        command=["python", "-m", "scopelens.checks.crawl"],
        environment={
            "PYTHONUNBUFFERED": "1",
            "HTTP_PROXY": f"http://{settings.proxy_host}:{settings.proxy_http_port}",
            "HTTPS_PROXY": f"http://{settings.proxy_host}:{settings.proxy_http_port}",
            "NO_PROXY": "",
            "SCOPELENS_PROXY_CA_PEM": _proxy_ca_pem(settings),
            "SCOPELENS_EGRESS_TOKEN": egress_token,
            "SCOPELENS_TARGET_URL": target_url,
            "SCOPELENS_TASK_TIMEOUT": str(int(settings.budgets.request_timeout_seconds)),
            # Crawl bounds come from the scan's own budget, so the effective limits are
            # decided in one place rather than defaulted independently inside the worker.
            "SCOPELENS_MAX_PAGES": str(limits.max_pages),
            # Reserve most of the process allowance for artifact flushing and tools.
            # The crawler must finish before the supervisor's hard process deadline.
            "SCOPELENS_CRAWL_TIMEOUT": str(
                min(limits.wall_clock_seconds, settings.worker_max_runtime_seconds) * 0.5
            ),
            "SCOPELENS_COLLECTION_TIMEOUT": str(
                min(limits.wall_clock_seconds, settings.worker_max_runtime_seconds)
            ),
            "SCOPELENS_ZAP_TIMEOUT": str(
                min(600, min(limits.wall_clock_seconds, settings.worker_max_runtime_seconds) * 0.3)
            ),
            "SCOPELENS_SCANNER_TOOLS_ENABLED": str(settings.scanner_tools_enabled).lower(),
            "SCOPELENS_MAX_DEPTH": str(
                min(
                    settings.budgets.max_crawl_depth,
                    scope.budgets_override.max_crawl_depth
                    if scope.budgets_override is not None
                    else settings.budgets.max_crawl_depth,
                )
            ),
            "SCOPELENS_MAX_BODY_BYTES": str(limits.max_response_bytes),
            "SCOPELENS_ALLOWED_PREFIXES": ",".join(scope.allowed_path_prefixes),
            "SCOPELENS_EXCLUDED_PATHS": ",".join(scope.excluded_paths),
            "SCOPELENS_TRANSPORT_HTTP_PORT": str(scope.transport_http_port or ""),
            "SCOPELENS_RETEST_ROUTES": json.dumps(retest_routes),
            "SCOPELENS_CONDITIONAL_PROBES": json.dumps(
                reviewed_probes if reviewed_probes is not None else approvals(settings, scope)
            ),
        },
        network=settings.worker_network,
        # `scopelens.scan_id` is what cancellation looks up. It has to be a container
        # label rather than in-memory state, so that a supervisor restart does not orphan
        # a running worker that cancellation can no longer find.
        # `stop_all_for_scan` filters on exactly this key.
        labels={"scopelens.run_id": run_id, "scopelens.scan_id": str(scan_id)},
        max_runtime_seconds=min(settings.worker_max_runtime_seconds, limits.wall_clock_seconds),
    )
    if recovery_task:
        from dataclasses import replace

        recovery_spec = replace(
            spec,
            image=settings.tool_worker_image,
            command=["python", "-m", "scopelens.expansion.recovery_worker"],
            environment={
                **spec.environment,
                "SCOPELENS_SCANNER_TOOLS_ENABLED": "false",
                "SCOPELENS_RECOVERY_INPUT": json.dumps(recovery),
                "SCOPELENS_EXPANSION_CAPABILITY": capability,
            },
        )
        return supervisor.run(recovery_spec, run_id=run_id)
    crawl = supervisor.run(spec, run_id=run_id)
    if (
        settings.browser_enabled
        and crawl.exit_code == 0
        and any(a.get("kind") == "surface" for a in crawl.artifacts())
    ):
        from scopelens.browser.integration import run_browser

        crawl = run_browser(settings, supervisor, spec, crawl, run_id=run_id)
    if scope.allowed_check_profile.expanded:
        from scopelens.expansion.integration import run_expansion

        crawl = run_expansion(
            settings, supervisor, spec, crawl, run_id=run_id, scan_id=scan_id, scope=scope
        )
    if settings.zap_active_lab_enabled and crawl.succeeded:
        from scopelens.execution.zap_active import append_results, dispatch

        crawl = append_results(
            crawl,
            dispatch(
                settings,
                supervisor,
                scan_id=scan_id,
                scope=scope,
                probes=reviewed_probes,
                token=egress_token,
            ),
        )
    return crawl


# --- Phase 3: finalise --------------------------------------------------------------


def _finalise(
    settings: Settings,
    *,
    run_id: str,
    lease: Lease,
    attempt_id: str,
    scope: ScopeVersion,
    egress_token: str,
    worker_result: WorkerResult | None,
    reason: str,
    lease_lost: bool,
    tls_measurement: TLSMeasurement | None = None,
    heartbeat_note: str = "",
) -> CoordinatorResult:
    store = LocalDiskEvidenceStore(
        settings.evidence_store_path,
        settings.evidence_encryption_key.get_secret_value()
        if settings.evidence_encryption_key
        else None,
    )
    evidence_ids: list[str] = []

    with session_scope(settings) as session:
        task = session.scalar(select(TaskRow).where(TaskRow.scan_id == lease.scan_id).limit(1))
        scan = session.get(ScanRow, lease.scan_id)
        if task is None or scan is None:
            return CoordinatorResult(
                scan_id=str(lease.scan_id),
                task_id="",
                task_state=TaskState.FAILED,
                reason="scan or task vanished during execution",
                acted=False,
            )

        requests_admitted = count_admitted_requests(session, scan.id)
        browser_context = session.get(BrowserSessionRow, scan.id)
        if browser_context and browser_context.owner in {
            run_id + "-browser",
            run_id + "-expansion-browser",
        }:
            browser_context.status = "closed"
            browser_context.inflight = False
            browser_context.expires_at = datetime.now(UTC)

        # --- Evidence -----------------------------------------------------------
        artifact = worker_result.declared_result() if worker_result else None

        observed_bytes = 0
        if artifact:
            try:
                observed_bytes = max(0, int(artifact.get("body_bytes") or 0))
            except (TypeError, ValueError):
                observed_bytes = 0
        spent = BudgetUsage(
            requests=requests_admitted,
            bytes=observed_bytes,
            pages=len((scan.assessment_plan or {}).get("page_request_keys", [])),
        )
        if artifact is not None:
            record = intake.record_json_evidence(
                session,
                settings=settings,
                store=store,
                scan=scan,
                origin=EvidenceOrigin.SUPERVISOR,
                producer="fetch_origin_worker",
                payload=artifact,
                task_id=task.id,
                run_id=run_id,
                summary=(
                    f"worker fetch of {scan.target_origin}: "
                    f"status={artifact.get('status_code')} reason={artifact.get('reason')}"
                ),
            )
            evidence_ids.append(record.id)

        if worker_result is not None and (worker_result.stdout or worker_result.stderr):
            record = intake.record_untrusted_observation(
                session,
                settings=settings,
                store=store,
                scan=scan,
                producer="tool_worker_stdout",
                content=(
                    worker_result.stdout + "\n--- stderr ---\n" + worker_result.stderr
                ).encode(),
                task_id=task.id,
                run_id=run_id,
                summary="worker process output, recorded as an observation only",
            )
            evidence_ids.append(record.id)

        _, pending_status, _ = _settle(
            worker_result=worker_result,
            artifact=artifact,
            requests_admitted=requests_admitted,
            lease_lost=lease_lost,
            reason=reason,
            heartbeat_note=heartbeat_note,
            cancelled=scan.cancel_requested_at is not None,
        )
        # --- Analysis ------------------------------------------------------------
        # Runs after the evidence is stored, because the controls read artifacts by evidence
        # reference. A crawl with no surface artifact cannot be analysed: the scan is settled
        # without findings and says so, rather than reporting an empty surface as clean.
        analysis = None
        recovery_requested = bool((scan.assessment_plan or {}).get("cleanup_recovery"))
        if recovery_requested:
            _finalise_recovery_capture(
                session,
                settings=settings,
                scan=scan,
                task=task,
                lease=lease,
                run_id=run_id,
                worker_result=worker_result,
                store=store,
            )
        elif artifact is not None or worker_result is not None:
            analysis = _analyse(
                settings=settings,
                session=session,
                scan=scan,
                scope=scope,
                egress_token=egress_token,
                tls_measurement=tls_measurement,
                worker_result=worker_result,
                evidence_ids=evidence_ids,
                store=store,
                scan_interrupted=pending_status != ScanStatus.COMPLETED,
                task_id=task.id,
                run_id=run_id,
            )

        scanner_gaps = [
            a["data"].get("tool", "scanner")
            for a in (worker_result.artifacts() if worker_result else [])
            if a.get("kind") == "scanner_result"
            and a["data"].get("state") in {"error", "timeout", "cancelled", "partial"}
        ]
        # --- Budget reconciliation ---------------------------------------------
        # Runs on every path, including the abnormal ones, so a reservation cannot be
        # stranded by an exit route nobody thought to test.
        #
        # `settle` rather than `reconcile`: two different reservations can be outstanding
        # here — this coordinator's own, taken at admission, and the broker's per-request
        # ones, taken to stop concurrent admissions oversubscribing. Releasing only the
        # first leaves the second stranded, permanently shrinking a completed scan's budget.
        budget_service.settle(session, scan_id=scan.id, spent=spent)

        write_prose = (
            not recovery_requested
            and settings.report_writer_model.configured
            and pending_status in {ScanStatus.COMPLETED, ScanStatus.COMPLETED_PARTIAL}
            and not lease_lost
            and scan.cancel_requested_at is None
        )
        if write_prose:
            transition_scan(
                session,
                scan=scan,
                target=ScanStatus.REPORTING,
                reason="Building report explanations",
            )
            # All target work has ended. Report generation grants no further egress.
            scan.egress_token_epoch = -1

    if write_prose:
        from scopelens.writer.enrich import enrich

        enrich(settings, lease.scan_id)

    with session_scope(settings) as session:
        scan = session.scalar(select(ScanRow).where(ScanRow.id == lease.scan_id).with_for_update())
        task = session.scalar(select(TaskRow).where(TaskRow.scan_id == lease.scan_id).limit(1))
        # --- Settle --------------------------------------------------------------
        task_state, scan_status, settle_reason = _settle(
            worker_result=worker_result,
            artifact=artifact,
            requests_admitted=requests_admitted,
            lease_lost=lease_lost,
            reason=reason,
            heartbeat_note=heartbeat_note,
            cancelled=scan.cancel_requested_at is not None,
        )

        if task_state is TaskState.SUCCEEDED:
            mark_task_succeeded(
                session, task=task, attempt_id=attempt_id, reason=settle_reason, spent=spent
            )
        elif task_state is TaskState.OUTCOME_UNKNOWN:
            mark_task_outcome_unknown(
                session, task=task, attempt_id=attempt_id, reason=settle_reason
            )
        else:
            mark_task_failed(
                session, task=task, attempt_id=attempt_id, reason=settle_reason, spent=spent
            )

        if scanner_gaps and scan_status is ScanStatus.COMPLETED:
            scan_status = ScanStatus.COMPLETED_PARTIAL
            settle_reason += "; incomplete tool coverage: " + ", ".join(scanner_gaps)
        if recovery_requested and scan_status is ScanStatus.COMPLETED:
            recovery_result = (scan.assessment_plan or {}).get("cleanup_recovery_result", {})
            if not recovery_result.get("verified"):
                scan_status = ScanStatus.COMPLETED_PARTIAL
                settle_reason = "Recovery verification incomplete; original resource remains fenced"
        if scan.cancel_requested_at is not None and scan_status is not ScanStatus.CANCELLED:
            scan_status = ScanStatus.CANCELLED
        transition_scan(session, scan=scan, target=scan_status, reason=settle_reason)
        scan.reconciled_at = datetime.now(UTC)

        record_audit(
            session,
            actor="coordinator",
            action="task.settle",
            subject_type="task",
            subject_id=str(task.id),
            outcome=task_state.value,
            detail={
                "scan_id": str(scan.id),
                "scan_status": scan_status.value,
                "requests_admitted": requests_admitted,
                "lease_lost": lease_lost,
                "reason": settle_reason,
            },
        )

        release_lease(
            session,
            scan_id=scan.id,
            holder=lease.holder,
            fencing_token=lease.fencing_token,
        )

        evidence_rows = session.scalars(
            select(EvidenceRow.id).where(EvidenceRow.scan_id == scan.id)
        ).all()
        evidence_ids = [str(row) for row in evidence_rows]

    return CoordinatorResult(
        scan_id=str(lease.scan_id),
        task_id=str(task.id),
        task_state=task_state,
        scan_status=scan_status,
        reason=settle_reason,
        evidence_ids=tuple(evidence_ids),
        requests_admitted=requests_admitted,
        worker_succeeded=bool(worker_result and worker_result.succeeded),
        extra={
            "lease_lost": lease_lost,
            "findings": len(analysis.findings) if analysis else 0,
            "verdict": analysis.snapshot.verdict if analysis else None,
            "coverage_percent": round(analysis.snapshot.coverage_percent, 1) if analysis else None,
            "analysis_errors": list(analysis.errors) if analysis else [],
        },
    )


def _finalise_recovery_capture(
    session,
    *,
    settings,
    scan,
    task,
    lease,
    run_id,
    worker_result,
    store,
):
    """Only reviewed read-only recovery captures can release an existing resource fence."""
    from hashlib import sha256
    from pathlib import Path

    from scopelens.execution.leases import LeaseLost
    from scopelens.expansion.recovery import (
        RECOVERY_PRODUCER,
        RecoveryRefused,
        RecoverySpec,
        finalize_recovery,
    )

    captures = [
        a
        for a in (worker_result.artifacts() if worker_result else [])
        if a.get("kind") == "cleanup_recovery_capture"
    ]
    spec = RecoverySpec.model_validate(scan.assessment_plan["cleanup_recovery"])
    record = None
    if len(captures) == 1:
        source = Path(__file__).parents[1] / "expansion"
        record = intake.record_json_evidence(
            session,
            settings=settings,
            store=store,
            scan=scan,
            origin=EvidenceOrigin.SUPERVISOR,
            producer=RECOVERY_PRODUCER,
            producer_hash=sha256(
                (source / "recovery_worker.py").read_bytes() + (source / "recovery.py").read_bytes()
            ).hexdigest(),
            tool_version=settings.tool_worker_image,
            role=spec.identity.id,
            payload=captures[0],
            task_id=task.id,
            run_id=run_id,
            summary="Fresh authenticated read-only recovery verification",
        )
    try:
        if record is None:
            raise RecoveryRefused("one_recovery_capture_required")
        finalize_recovery(
            session,
            scan,
            lease=lease,
            run_id=run_id,
            evidence_id=record.id,
            store=store,
        )
    except (RecoveryRefused, LeaseLost) as exc:
        scan.assessment_plan = {
            **scan.assessment_plan,
            "cleanup_recovery_result": {
                "verified": False,
                "reason": str(exc),
                "evidence_ref": record.id if record else None,
            },
        }


def _analyse(
    *,
    settings: Settings,
    session: Session,
    scan: ScanRow,
    scope: ScopeVersion,
    egress_token: str,
    worker_result: WorkerResult | None,
    evidence_ids: list[str],
    store: Any,
    tls_measurement: TLSMeasurement | None = None,
    scan_interrupted: bool = False,
    task_id: uuid.UUID | None = None,
    run_id: str | None = None,
):  # type: ignore[no-untyped-def]
    """Run the deterministic checks over the collected artifacts, then score.



    The TLS measurement is taken here, through the constrained lane, because it must not come
    from the intercepted assessment lane. A lane that cannot be reached leaves the measurement
    as None, which makes the TLS control inconclusive rather than clean.
    """
    from scopelens.checks.analyze import analyze

    artifacts = worker_result.artifacts() if worker_result else []
    # Callback evidence comes from private broker/collector records. A worker may
    # describe its attempt, but cannot supply a capture or its trusted timestamp.
    artifacts = [a for a in artifacts if not str(a.get("kind", "")).startswith("callback_")]
    if not any(a.get("kind") == "surface" for a in artifacts):
        return None

    frozen_configuration = (scan.assessment_plan or {}).get("expansion_config")
    if frozen_configuration:
        from scopelens.callbacks.deployment import runtime_from_settings
        from scopelens.callbacks.integration import capture_callback_artifacts
        from scopelens.domain.expansion import AssessmentConfiguration
        from scopelens.persistence.session import build_session_factory

        configuration = AssessmentConfiguration.model_validate(frozen_configuration)
        if configuration.callback_recipes:
            runtime = runtime_from_settings(
                settings, session_factory=build_session_factory(session.get_bind())
            )
            artifacts.extend(
                capture_callback_artifacts(
                    runtime, configuration, owner_id=scan.operator_id, scan_id=scan.id
                )
            )

    from hashlib import sha256
    from pathlib import Path

    from scopelens.checks.controls.cookies import parse_set_cookie

    refs = {"crawl": evidence_ids[0] if evidence_ids else ""}
    if tls_measurement is not None:
        record = intake.record_json_evidence(
            session,
            settings=settings,
            store=store,
            scan=scan,
            origin=EvidenceOrigin.TLS_LANE,
            producer="tls_lane",
            payload=tls_measurement.model_dump(),
            task_id=task_id,
            run_id=run_id,
            summary=(
                f"TLS lane measurement of {tls_measurement.host}:{tls_measurement.port}: "
                f"{tls_measurement.protocol_version}, self_signed={tls_measurement.self_signed}"
            ),
        )
        refs["tls"] = record.id

    # Store the actual structured capture, not just the worker's summary, before proof
    # rules reference it. Each response is independently capped and redacted by intake.
    for captured in artifacts:
        if captured.get("kind") not in {
            "surface",
            "response",
            "cleartext",
            "unreachable",
            "browser_state",
            "browser_summary",
            "browser_request_template",
            "expanded_browser_summary",
            "scanner_result",
            "active_probe",
            "expanded_active_probe",
            "exposure_pack",
            "expansion_gap",
            "identity_observation",
            "identity_response",
            "session_observation",
            "workflow_capture",
            "callback_capture",
        }:
            continue
        # Preserve attribute facts while raw Set-Cookie values are fully redacted.
        fields = []
        for header in captured.get("data", {}).get("set_cookie", []):
            fact = parse_set_cookie(header)
            if fact is not None:
                fields.append({"name": fact.name, "attributes": fact.attributes})
        stored_capture = {**captured, "response_attributes": fields}
        browser_capture = captured.get("source") in {"browser", "expansion_browser"}
        producer = "reviewed_browser_capture" if browser_capture else "reviewed_crawler_capture"
        source_file = "browser/worker.py" if browser_capture else "checks/crawl.py"
        if captured.get("source") == "adaptive":
            producer = "reviewed_adaptive_capture"
            source_file = "orchestration/recheck.py"
        if captured["kind"] == "scanner_result":
            producer = "reviewed_scanner_adapter"
            source_file = (
                "execution/zap_active.py"
                if captured.get("source") == "zap_task_supervisor"
                else "broker/tls_tool.py"
                if captured.get("source") == "tls_lane"
                else "adapters/runner.py"
            )
        if captured["kind"] == "active_probe":
            producer = "reviewed_active_capture"
            source_file = "browser/active.py" if browser_capture else "checks/active.py"
        if captured.get("source") == "expansion":
            producer = "reviewed_expansion_capture"
            source_file = "expansion/worker.py"
        if captured.get("source") == "expansion_browser":
            producer = "reviewed_expansion_browser_capture"
            source_file = "expansion/browser_worker.py"
        if captured.get("kind") == "callback_capture":
            producer = "reviewed_callback_broker_capture"
            source_file = "broker/mitm_addon.py"
        producer_hash = sha256((Path(__file__).parents[1] / source_file).read_bytes()).hexdigest()
        record = intake.record_json_evidence(
            session,
            settings=settings,
            store=store,
            scan=scan,
            origin=EvidenceOrigin.TLS_LANE
            if captured.get("source") == "tls_lane"
            else EvidenceOrigin.SUPERVISOR,
            producer=producer,
            payload=stored_capture,
            producer_hash=producer_hash,
            tool_version=settings.browser_worker_image
            if browser_capture
            else (
                settings.kali_worker_image
                if settings.scanner_tools_enabled
                else settings.tool_worker_image
            ),
            task_id=task_id,
            run_id=captured.get("run_id", run_id),
            summary=f"Captured {captured['kind']} artifact",
        )
        refs[f"artifact:{record.id}"] = record.id
        captured["evidence_ref"] = record.id
        if captured["kind"] == "surface":
            refs["crawl"] = record.id
        elif captured["kind"] == "cleartext":
            refs["cleartext"] = record.id
    scope_record = intake.record_json_evidence(
        session,
        settings=settings,
        store=store,
        scan=scan,
        origin=EvidenceOrigin.SUPERVISOR,
        producer="scope_record",
        payload=scope.model_dump(mode="json"),
        task_id=task_id,
        run_id=run_id,
        summary="Immutable scope authorization",
    )
    refs["scope"] = scope_record.id
    if (scan.assessment_plan or {}).get("advisories"):
        advisory_record = intake.record_json_evidence(
            session,
            settings=settings,
            store=store,
            scan=scan,
            origin=EvidenceOrigin.SUPERVISOR,
            producer="advisory_snapshot",
            payload=scan.assessment_plan["advisories"],
            task_id=task_id,
            run_id=run_id,
            summary="Versioned advisory source and content hash",
        )
        refs["advisories"] = advisory_record.id

    bundle = intake.record_json_evidence(
        session,
        settings=settings,
        store=store,
        scan=scan,
        origin=EvidenceOrigin.SUPERVISOR,
        producer="capture_manifest",
        payload={"artifacts": dict(refs), "run_id": run_id},
        task_id=task_id,
        run_id=run_id,
        summary="Capture manifest linking every response and inventory artifact",
    )
    refs["crawl"] = bundle.id
    return analyze(
        settings=settings,
        session=session,
        scan=scan,
        artifacts=artifacts,
        evidence_refs=refs,
        tls_measurement=tls_measurement,
        scan_interrupted=scan_interrupted,
    )


def _measure_tls_outside_transaction(
    settings: Settings, *, scope: ScopeVersion, egress_token: str
) -> TLSMeasurement | None:
    """Ask the constrained TLS lane for a measurement of the real upstream.

    **Must be called with no database transaction open.** The lane authorizes by querying the
    database, so calling it from inside a transaction that holds the rows it needs deadlocks
    until the client times out.

    Returns None when the lane refuses or is unreachable, which makes the TLS control
    inconclusive rather than clean — the correct outcome for a transport nobody looked at.

    The lane authorizes the request itself, with the same egress token and the same scope
    rules as the HTTP lane, so this is not a way to reach a destination the broker would
    otherwise refuse.
    """
    if scope.scheme != "https" or not egress_token:
        return None

    from scopelens.broker.tls_lane_service import TLSLaneClient

    facts = TLSLaneClient(settings.tls_lane_url).measure(
        egress_token=egress_token, host=scope.host, port=scope.port
    )
    if facts is None:
        return None
    # ``TLSFacts`` is a dataclass, not a pydantic model, so ``asdict`` — not ``model_dump``.
    return TLSMeasurement(**asdict(facts))


def _settle(
    *,
    worker_result: WorkerResult | None,
    artifact: dict | None,
    requests_admitted: int,
    lease_lost: bool,
    reason: str,
    heartbeat_note: str,
    cancelled: bool,
) -> tuple[TaskState, ScanStatus, str]:
    """Decide the task and scan outcome.

    Kept as one explicit function because this is the vocabulary the whole product's
    honesty rests on: a check that did not run is never recorded as having passed.
    """
    if cancelled:
        # A request may already have reached the target before cancellation landed.
        if requests_admitted > 0:
            return (
                TaskState.OUTCOME_UNKNOWN,
                ScanStatus.CANCELLED,
                f"cancelled after {requests_admitted} request(s) were admitted; partial "
                "evidence retained",
            )
        return TaskState.FAILED, ScanStatus.CANCELLED, "cancelled before any request was admitted"

    if lease_lost:
        return (
            TaskState.OUTCOME_UNKNOWN,
            ScanStatus.COMPLETED_PARTIAL,
            f"coordinator lost its lease during the run ({heartbeat_note}); a replacement "
            "must reconcile before this work is retried",
        )

    if worker_result is None:
        return TaskState.FAILED, ScanStatus.FAILED, reason or "worker did not run"

    if worker_result.timed_out or worker_result.killed:
        # The worker was stopped mid-flight. Whether its request reached the target is
        # exactly what cannot be known, so it is not recorded as a failure to be retried.
        return (
            TaskState.OUTCOME_UNKNOWN,
            ScanStatus.COMPLETED_PARTIAL,
            f"worker did not finish within {worker_result.duration_seconds:.0f}s and was "
            "stopped; outcome unknown",
        )

    if artifact is None:
        return (
            TaskState.FAILED,
            ScanStatus.FAILED,
            f"worker produced no result artifact (exit={worker_result.exit_code})",
        )

    status_code = artifact.get("status_code")
    if artifact.get("ok"):
        summary = (
            "HTTP crawl completed; captured endpoints, responses and discovery gaps"
            if artifact.get("url") is None
            else f"fetched {artifact.get('url')} -> HTTP {status_code}"
        )
        return (
            TaskState.SUCCEEDED,
            ScanStatus.COMPLETED,
            summary,
        )

    # The broker refusing a request is a legitimate, expected outcome: it means scope or
    # budget stopped the work. Recorded as partial, never as a pass.
    if requests_admitted == 0:
        return (
            TaskState.FAILED,
            ScanStatus.COMPLETED_PARTIAL,
            f"no request was admitted by the broker ({artifact.get('reason')}); nothing was tested",
        )

    if artifact.get("crawl_ok") is True and artifact.get("browser_ok") is False:
        return (
            TaskState.FAILED,
            ScanStatus.COMPLETED_PARTIAL,
            "HTTP crawl results were saved; browser exploration did not finish: "
            + str(artifact.get("error") or "no browser failure detail was recorded"),
        )
    return (
        TaskState.FAILED,
        ScanStatus.COMPLETED_PARTIAL,
        f"fetch failed: {artifact.get('reason')} ({artifact.get('error') or 'no detail'})",
    )


def count_admitted_requests(session: Session, scan_id: uuid.UUID) -> int:
    """How many requests the broker actually admitted for this scan.

    Read from the broker's audit trail rather than from the worker's own report: the
    worker's claim about what it did is not the record of what was authorized.
    """
    return int(
        session.scalar(
            select(func.count())
            .select_from(AuditEventRow)
            .where(
                AuditEventRow.action == BROKER_ADMIT_ACTION,
                AuditEventRow.subject_id == str(scan_id),
                AuditEventRow.outcome == "allowed",
            )
        )
        or 0
    )


__all__ = [
    "BROKER_ADMIT_ACTION",
    "CoordinatorResult",
    "coordinate",
    "count_admitted_requests",
]
