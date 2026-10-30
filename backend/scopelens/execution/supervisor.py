"""Worker supervisor (Build Plan §5.4).

The supervisor is the **trusted** component. It owns run identity, starts and stops the
worker container, and collects the artifact the worker produced. It is the only thing
that talks to both the Docker daemon and PostgreSQL.

The isolation guarantees live in :meth:`DockerWorkerSupervisor._container_kwargs`, which
is the single place a worker container is configured. Everything it deliberately omits
is as important as what it sets:

* **no Docker socket** — a worker cannot start, stop or inspect containers
* **no host mounts** — a worker cannot read or write the host filesystem
* **no control-plane network** — the worker cannot reach PostgreSQL, Redis or the API
* **no database or Redis credentials** — they are not in its environment at all
* **read-only root filesystem, all capabilities dropped, no privilege escalation**
* **CPU, memory and PID limits**
* **one per-scan scratch directory**, discarded with the container

Target traffic is not blocked here — it is blocked by the network topology. The worker
sits on an `internal: true` network whose only route out is the forward proxy, so a
worker attempting a direct connection fails at the network layer rather than being asked
politely not to.

`docs/OPEN_QUESTIONS.md` Q-10 records what this does **not** achieve: the supervisor
holds the Docker socket, which is a host-level privilege, and §5.4 requires a stronger
boundary (a dedicated worker VM) before any generated code runs in M4.
"""

from __future__ import annotations

import contextlib
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Protocol

from scopelens.config import Settings

#: The worker prints exactly one line beginning with this marker; that line is its
#: declared result. Everything else it writes is recorded as an untrusted observation.
#:
#: A stdout channel rather than a shared scratch file because a bind mount resolves on
#: the *host*, so a directory the supervisor creates inside its own container is not the
#: directory a sibling container would mount. A shared named volume would work but adds a
#: path-mapping problem for no gain: the result is a few kilobytes of JSON.
RESULT_MARKER = "SCOPELENS_RESULT "

#: A worker may emit any number of these. The declared result is a single summary; artifacts
#: are the bulk material the checks run on — a crawl produces one surface map and one entry
#: per response, which does not fit in a summary and should not be squeezed into one.
ARTIFACT_MARKER = "SCOPELENS_ARTIFACT "


@dataclass(frozen=True)
class WorkerSpec:
    """Everything a worker run needs. Contains no credentials by construction."""

    image: str
    command: list[str]
    environment: dict[str, str]
    network: str
    labels: dict[str, str] = field(default_factory=dict)
    max_runtime_seconds: int = 300
    browser: bool = False


@dataclass(frozen=True)
class WorkerResult:
    """The outcome of one worker run, as the supervisor observed it."""

    run_id: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    killed: bool = False

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out and not self.killed

    @property
    def observation(self) -> str:
        """A short, redaction-safe description for the audit trail."""
        return (
            f"exit={self.exit_code} timed_out={self.timed_out} killed={self.killed} "
            f"duration={self.duration_seconds:.2f}s"
        )

    def artifacts(self) -> list[dict]:
        """Every artifact line the worker emitted, in order.

        A malformed line is skipped rather than aborting the batch: one unparseable artifact
        should cost that artifact, not the whole run. The count of skipped lines is not
        silently dropped — a caller can compare against what it expected.
        """
        import json

        collected: list[dict] = []
        for line in self.stdout.splitlines():
            if not line.startswith(ARTIFACT_MARKER):
                continue
            try:
                parsed = json.loads(line[len(ARTIFACT_MARKER) :])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                collected.append(parsed)
        return collected

    def declared_result(self) -> dict | None:
        """Parse the worker's declared result line, if it produced one.

        Returns None when the worker printed no marker, which is the honest answer for a
        worker that crashed: a missing result is not an empty one.
        """
        import json

        for line in reversed(self.stdout.splitlines()):
            if line.startswith(RESULT_MARKER):
                try:
                    parsed = json.loads(line[len(RESULT_MARKER) :])
                except json.JSONDecodeError:
                    return None
                return parsed if isinstance(parsed, dict) else None
        return None


class SupervisorError(RuntimeError):
    """The supervisor could not carry out the run."""


class WorkerSupervisor(Protocol):
    def run(self, spec: WorkerSpec, *, run_id: str) -> WorkerResult: ...

    def stop(self, run_id: str, *, timeout_seconds: float = 30.0) -> bool: ...


class DockerWorkerSupervisor:
    """Runs each task in its own ephemeral container."""

    #: The only environment variables a worker ever receives. Anything not listed here
    #: is absent, which is stronger than being blanked — an absent variable cannot be
    #: un-set by an accidental later edit.
    ALLOWED_ENV_KEYS = frozenset(
        {
            "PATH",
            "PYTHONUNBUFFERED",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            # The proxy CA arrives as PEM *content*, not a path: the worker has no
            # host mounts, so a path would point at a file it cannot see.
            "SCOPELENS_PROXY_CA_PEM",
            "SCOPELENS_EGRESS_TOKEN",
            "SCOPELENS_TARGET_URL",
            "SCOPELENS_TASK_TIMEOUT",
            # Crawl bounds (Build Plan §5.3, §5.7). Passed in rather than defaulted in the
            # worker, so the effective limits are decided by the coordinator from the scan's
            # own budget and are visible in one place.
            "SCOPELENS_MAX_PAGES",
            "SCOPELENS_CRAWL_TIMEOUT",
            "SCOPELENS_COLLECTION_TIMEOUT",
            "SCOPELENS_ZAP_TIMEOUT",
            "SCOPELENS_BROWSER_OWNER",
            "SCOPELENS_SCANNER_TOOLS_ENABLED",
            "SCOPELENS_CONDITIONAL_PROBES",
            "SCOPELENS_EXPANSION_INPUT",
            "SCOPELENS_FOLLOWUP_INPUT",
            "SCOPELENS_RECOVERY_INPUT",
            "SCOPELENS_EXPANSION_CAPABILITY",
            "SCOPELENS_BROWSER_MAX_ACTIONS",
            "SCOPELENS_BROWSER_MAX_ACTIVE_ACTIONS",
            "SCOPELENS_BROWSER_MAX_REQUESTS",
            "SCOPELENS_BROWSER_MAX_STATES",
            "SCOPELENS_TRANSPORT_HTTP_PORT",
            "SCOPELENS_RETEST_ROUTES",
            "SCOPELENS_MAX_DEPTH",
            "SCOPELENS_MAX_BODY_BYTES",
            "SCOPELENS_USER_AGENT",
            "SCOPELENS_ALLOWED_PREFIXES",
            "SCOPELENS_EXCLUDED_PATHS",
            "SCOPELENS_ARTIFACT_MARKER",
            "SCOPELENS_SCRATCH_DIR",
        }
    )

    def __init__(self, settings: Settings, *, client=None) -> None:  # type: ignore[no-untyped-def]
        self._settings = settings
        self._client = client
        self._running: dict[str, str] = {}

    @property
    def client(self):  # type: ignore[no-untyped-def]
        if self._client is None:
            import docker

            try:
                self._client = docker.from_env()
            except docker.errors.DockerException as exc:
                raise SupervisorError("configured worker Docker daemon unavailable") from exc
        return self._client

    def _container_kwargs(self, spec: WorkerSpec) -> dict:
        """The worker container's configuration. See the module docstring."""
        env = {k: v for k, v in spec.environment.items() if k in self.ALLOWED_ENV_KEYS}
        rejected = sorted(set(spec.environment) - self.ALLOWED_ENV_KEYS)
        if rejected:
            # Loud rather than silent: a caller passing a credential to a worker is a
            # bug worth failing on, not one to quietly drop.
            raise SupervisorError(
                f"refusing to pass unexpected environment variable(s) to a worker: {rejected}. "
                "Workers receive no credentials, by design (Build Plan §5.4)."
            )

        config = {
            "image": spec.image,
            "command": spec.command,
            "environment": env,
            "network": spec.network,
            # No host mounts of any kind. The worker's scratch is a per-run tmpfs, so it
            # is isolated by construction rather than by path discipline.
            "labels": {**spec.labels, "scopelens.managed": "worker"},
            "read_only": True,
            "tmpfs": {"/tmp": "rw,noexec,nosuid,size=64m"},
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "privileged": False,
            "mem_limit": f"{self._settings.worker_memory_limit_mb}m",
            "nano_cpus": int(self._settings.worker_cpu_limit * 1e9),
            "pids_limit": self._settings.worker_pids_limit,
            "detach": True,
            # The worker must not outlive its scan. `auto_remove` keeps a crashed run
            # from leaving a container behind for the reconciler to find.
            "auto_remove": False,
            "working_dir": "/tmp",
        }

        if spec.environment.get("SCOPELENS_SCANNER_TOOLS_ENABLED") == "true":
            config.update(
                mem_limit=f"{self._settings.scanner_worker_memory_limit_mb}m", pids_limit=512
            )
            config["tmpfs"] = {"/tmp": "rw,noexec,nosuid,size=256m"}
        if spec.browser:
            config.update(init=True, shm_size="256m", mem_limit="1024m", pids_limit=512)
            config["tmpfs"] = {"/tmp": "rw,nosuid,size=512m"}
            # Docker accepts the seccomp JSON itself. No host-mounted path is needed.
            config["security_opt"].append(
                "seccomp=" + self._settings.browser_seccomp_path.read_text()
            )
        return config

    def run(self, spec: WorkerSpec, *, run_id: str) -> WorkerResult:
        started = time.monotonic()
        token = spec.environment.get("SCOPELENS_EGRESS_TOKEN")
        if token and not self._authority_live(token):
            raise SupervisorError("worker admission revoked before start")
        container = self.client.containers.run(**self._container_kwargs(spec))
        self._running[run_id] = container.id

        stopped = threading.Event()
        revoked = threading.Event()

        def watch():
            while not stopped.wait(0.5):
                if token and not self._authority_live(token):
                    revoked.set()
                    self._terminate(container, 10)
                    return

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        timed_out = False
        try:
            try:
                status = container.wait(timeout=spec.max_runtime_seconds)
                exit_code = int(status.get("StatusCode", -1))
            except Exception:  # noqa: BLE001 - any wait failure means "did not finish in time"
                timed_out = True
                exit_code = None
                self._kill(container)

            stdout = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
            stderr = container.logs(stdout=False, stderr=True).decode("utf-8", "replace")
        finally:
            stopped.set()
            watcher.join(timeout=6)
            self._running.pop(run_id, None)
            # Cleanup must not mask the run's outcome.
            with contextlib.suppress(Exception):
                container.remove(force=True)

        return WorkerResult(
            run_id=run_id,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=time.monotonic() - started,
            timed_out=timed_out,
            killed=revoked.is_set(),
        )

    def _authority_live(self, token):
        from datetime import UTC, datetime

        from scopelens.broker.policy import scan_for_token
        from scopelens.execution.leases import lease_is_live
        from scopelens.persistence.session import session_scope

        try:
            with session_scope(self._settings) as db:
                scan = scan_for_token(db, token)
                return bool(
                    scan
                    and not scan.cancel_requested_at
                    and scan.egress_token_epoch == scan.cancel_epoch
                    and lease_is_live(db, scan.id)
                    and scan.scope_version.authorization_expires_at > datetime.now(UTC)
                )
        except Exception:  # noqa: BLE001 - authority cannot be maintained
            return False

    def stop(self, run_id: str, *, timeout_seconds: float = 30.0) -> bool:
        """Stop a running worker's process group (§5.6).

        SIGTERM first so the worker can flush partial evidence, then SIGKILL. Returns
        False when there was nothing to stop, which is not an error — the run may simply
        have finished.
        """
        container_id = self._running.get(run_id)
        if container_id is None:
            return False
        container = self.client.containers.get(container_id)
        self._terminate(container, timeout_seconds)
        return True

    def _terminate(self, container, timeout_seconds: float) -> None:  # type: ignore[no-untyped-def]
        """SIGTERM, wait briefly, then SIGKILL.

        The grace period is capped at ``worker_stop_grace_seconds`` rather than set to the
        caller's ``timeout_seconds``. Passing the whole deadline as the grace period means
        a worker that ignores SIGTERM consumes the entire budget and the deadline is missed
        every time — which is what the first measurement showed.
        """
        grace = min(self._settings.worker_stop_grace_seconds, int(timeout_seconds))
        try:
            container.stop(timeout=grace)
        except Exception:  # noqa: BLE001 - fall through to the hard kill
            self._kill(container)

    @staticmethod
    def _kill(container) -> None:  # type: ignore[no-untyped-def]
        # Already-dead is the expected case, not a failure.
        with contextlib.suppress(Exception):
            container.kill()

    def stop_all_for_scan(self, scan_id: uuid.UUID, *, timeout_seconds: float = 30.0) -> int:
        """Stop every worker belonging to a scan, whatever run id it was started under.

        Used by cancellation. Keyed off the container label rather than the in-memory
        map, so a supervisor restart does not orphan a running worker.
        """
        containers = self.client.containers.list(
            filters={"label": [f"scopelens.scan_id={scan_id}", "scopelens.managed=worker"]}
        )
        stopped = 0
        for container in containers:
            self._terminate(container, timeout_seconds)
            stopped += 1
        return stopped


class RecordingSupervisor:
    """In-memory supervisor for tests. Records specs without running anything.

    Deliberately not a stub that pretends to succeed: the caller decides the result it
    wants, and the default is a *failure*, so a test that forgets to set one fails
    loudly instead of passing on a fabricated success.
    """

    def __init__(self, result: WorkerResult | None = None) -> None:
        self.specs: list[WorkerSpec] = []
        self.run_ids: list[str] = []
        self.stopped: list[str] = []
        self._result = result

    def run(self, spec: WorkerSpec, *, run_id: str) -> WorkerResult:
        self.specs.append(spec)
        self.run_ids.append(run_id)
        if self._result is not None:
            return self._result
        return WorkerResult(
            run_id=run_id,
            exit_code=1,
            stdout="",
            stderr="no result configured for this fake supervisor",
            duration_seconds=0.0,
        )

    def stop(self, run_id: str, *, timeout_seconds: float = 30.0) -> bool:
        self.stopped.append(run_id)
        return True

    def stop_all_for_scan(self, scan_id: uuid.UUID, *, timeout_seconds: float = 30.0) -> int:
        self.stopped.append(str(scan_id))
        return 1
