"""Containment: the worker boundary (Build Plan §5.3, §5.4; test suite §8 "Containment/scope").

M0 asserted that no dispatch code existed. That assertion is now false by design, so this
suite asserts the inverse and harder claim: that the code which *does* exist is fenced.

The most important test in this file is
``test_worker_container_has_no_socket_no_mounts_and_no_control_network``. It inspects the
exact kwargs the supervisor passes to Docker, so a later edit that adds a mount or changes
the network fails here rather than silently widening the boundary.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from scopelens.config import REPO_ROOT, Settings
from scopelens.execution.supervisor import DockerWorkerSupervisor, WorkerSpec

PACKAGE_ROOT = REPO_ROOT / "backend" / "scopelens"

#: The policy-broker addon runs in the proxy image, which has its own dependency set
#: (docs/OPEN_QUESTIONS.md Q-9). If it ever imports from the backend, the proxy container
#: fails to start with a confusing ImportError.
PROXY_ADDON = PACKAGE_ROOT / "broker" / "mitm_addon.py"

#: Modules that may open a connection to a target, and why each one is allowed.
#:
#: This is an allowlist with a stated reason per entry. Adding to it is a decision about
#: the scope boundary, so it has to be made deliberately here rather than discovered later.
EGRESS_CAPABLE = {
    "execution/zap_active.py": "Trusted supervisor channel; mandatory proxy only, signed exact task requests, scanner has no network",
    "adapters/zap_active_worker.py": "Network-none worker; HTTP clients bind loopback native API only, target requests use Docker file IPC",
    "discovery/passive.py": "Control-plane only; fixed crt.sh and dns.google providers, never HTTP to discovered hosts",
    "expansion/recovery.py": "httpx error types only; target traffic uses injected broker-bound identity clients with exact read-only recovery requests",
    "callbacks/runtime.py": "httpx.URL normalization only; database-backed broker dispatch proof, no HTTP client construction",
    "expansion/client.py": "Proxy-local assessment RPC only; target credentials resolved through fixed capability",
    "expansion/authenticated_inputs.py": "Injected broker-bound per-role clients only; exact origin and identity probes",
    "adapters/expansion_runner.py": "Pinned fixed Nuclei templates and binary through mandatory Bridge proxy; no community bundle",
    "callbacks/probes.py": "Injected broker client only; callback receipt service is separately constrained",
    "checks/expanded_active.py": "Injected broker client; frozen request plan and per-call limits",
    "checks/packs/exposure.py": "Injected broker client; bounded scoped GETs and no redirect following",
    "identities/assessment.py": "IdentitySessions transport only; httpx imported for error types",
    "identities/lifecycle.py": "IdentitySessions transport only; httpx cookies and error types",
    "identities/sessions.py": "Separate caller-supplied broker client per identity; no client constructor",
    "identities/readiness.py": "One read-only IdentitySessions probe through caller-supplied broker clients; httpx used for fixed error categories",
    "workflows/assessment.py": "IdentitySessions transport only; explicit recipes and cleanup journal",
    "expansion/browser_worker.py": "Isolated browser worker; mandatory Bridge proxy and fixed control client, scoped recipe guards",
    "adapters/roles.py": "Approved provider gateway only, no target traffic",
    "orchestration/models.py": "Fixed internal model gateway, no target traffic",
    "orchestration/scripts.py": "Fixed authenticated dedicated-VM gateway",
    "execution/sandbox.py": "Generated RPC uses the mandatory token-bound proxy only",
    "browser/bridge.py": "fixed broker upstream only; loopback listener inside isolated worker",
    "browser/worker.py": "Chromium and action client inside isolated worker, both through broker",
    "adapters/model.py": "approved configured provider only, redirect following disabled",
    "adapters/model_service.py": "authenticated internal provider gateway, no worker access",
    "adapters/tls_client.py": "supervisor to fixed authenticated TLS lane only",
    "broker/tls_tool.py": "trusted fixed testssl command, each socket through revalidating loopback gate",
    "scope/dns.py": "resolves names for validation; never connects",
    "broker/tls_lane.py": "the constrained TLS measurement lane; handshake only",
    "broker/tls_lane_service.py": "calls the lane, over the control network",
    "checks/fetch_origin.py": "runs inside the worker and goes through the proxy",
    "checks/crawl.py": "runs inside the worker and goes through the proxy",
    "broker/mitm_addon.py": (
        "the enforcement point itself; it runs in the proxy and calls the policy service"
    ),
}

#: HTTP client libraries. Importing one means this module can speak HTTP to something.
HTTP_CLIENT_ROOTS = {"httpx", "requests", "aiohttp", "urllib3"}

#: Source constructs that actually open a connection to a *target*.
#:
#: Deliberately narrow in two directions. `socket.gethostname()` is not egress, and a
#: detector that flagged it would force a meaningless allowlist entry — which makes the
#: whole list less trustworthy. A bare `.connect(` is not specific either: SQLAlchemy uses
#: it for database connections, so flagging it would light up the migration environment.
CONNECTING_CONSTRUCTS = (
    "socket.create_connection",
    "socket.socket(",
    "urlopen(",
)

STDLIB_ROOTS = {
    "__future__",
    "asyncio",
    "base64",
    "json",
    "os",
    "sys",
    "urllib",
    "typing",
    "dataclasses",
    "enum",
    "time",
    "hashlib",
    "secrets",
    "uuid",
    "pathlib",
    "contextlib",
    "logging",
    "socket",
    "ssl",
}


def can_reach_a_target(path: Path) -> bool:
    """Whether a module can open a connection, by import or by construct."""
    names = imported_names(path)
    roots = {n.split(".")[0] for n in names}
    if roots & HTTP_CLIENT_ROOTS or "http.client" in names:
        return True
    source = path.read_text(encoding="utf-8")
    return any(construct in source for construct in CONNECTING_CONSTRUCTS)


def iter_python_files() -> list[Path]:
    return sorted(p for p in PACKAGE_ROOT.rglob("*.py") if "__pycache__" not in p.parts)


def imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


@pytest.fixture
def supervisor(settings: Settings) -> DockerWorkerSupervisor:
    return DockerWorkerSupervisor(settings, client=object())


def sample_spec(**overrides: object) -> WorkerSpec:
    base = {
        "image": "scopelens/tool-worker:dev",
        "command": ["python", "-m", "scopelens.checks.fetch_origin"],
        "environment": {"PATH": "/usr/bin", "PYTHONUNBUFFERED": "1"},
        "network": "scopelens_worker_net",
        "labels": {"scopelens.run_id": "run-1"},
    }
    base.update(overrides)
    return WorkerSpec(**base)  # type: ignore[arg-type]


@pytest.mark.db
class TestWorkerContainerBoundary:
    def test_worker_container_has_no_socket_no_mounts_and_no_control_network(
        self, supervisor: DockerWorkerSupervisor
    ) -> None:
        """The single most important containment assertion in the suite."""
        kwargs = supervisor._container_kwargs(sample_spec())

        # No host filesystem, and that includes the Docker socket.
        assert "volumes" not in kwargs or kwargs["volumes"] == {}
        assert not any("docker.sock" in str(v) for v in kwargs.get("volumes", {}).values())

        # No control-plane network: the worker cannot reach postgres, redis or the api.
        assert kwargs["network"] == "scopelens_worker_net"
        assert kwargs["network"] != "control"

        # No privilege escalation and no capabilities to escalate with.
        assert kwargs["cap_drop"] == ["ALL"]
        assert kwargs["security_opt"] == ["no-new-privileges:true"]
        assert kwargs["privileged"] is False

        # Read-only root, with a single bounded writable tmpfs.
        assert kwargs["read_only"] is True
        assert kwargs["tmpfs"] == {"/tmp": "rw,noexec,nosuid,size=64m"}

        # Resource ceilings.
        assert kwargs["pids_limit"] > 0
        assert kwargs["mem_limit"]
        assert kwargs["nano_cpus"] > 0

    def test_worker_receives_no_credentials(self, supervisor: DockerWorkerSupervisor) -> None:
        """A credential passed to a worker is a bug, and the supervisor refuses it."""
        for key in (
            "SCOPELENS_DATABASE_URL",
            "SCOPELENS_REDIS_URL",
            "SCOPELENS_SESSION_SECRET",
            "SCOPELENS_OPERATOR_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
        ):
            with pytest.raises(Exception, match="refusing to pass"):
                supervisor._container_kwargs(
                    sample_spec(environment={"PATH": "/usr/bin", key: "value"})
                )

    def test_allowed_environment_is_exactly_the_allowlist(
        self, supervisor: DockerWorkerSupervisor
    ) -> None:
        kwargs = supervisor._container_kwargs(
            sample_spec(environment={"PATH": "/usr/bin", "SCOPELENS_EGRESS_TOKEN": "t"})
        )
        assert set(kwargs["environment"]) <= DockerWorkerSupervisor.ALLOWED_ENV_KEYS
        assert "SCOPELENS_EGRESS_TOKEN" in kwargs["environment"]

    def test_workers_are_labelled_as_managed(self, supervisor: DockerWorkerSupervisor) -> None:
        """The label is how cancellation finds a worker whose supervisor restarted."""
        kwargs = supervisor._container_kwargs(sample_spec())
        assert kwargs["labels"]["scopelens.managed"] == "worker"

    def test_cancellation_and_the_coordinator_agree_on_the_scan_label(self) -> None:
        """`stop_all_for_scan` filters on a label the coordinator must actually set.

        These live in different modules, so a rename on one side would silently make
        cancellation unable to find any worker — the failure mode is a scan that keeps
        running after being cancelled.
        """
        import inspect

        from scopelens.execution import coordinator, supervisor

        coordinator_source = inspect.getsource(coordinator._execute)
        assert "scopelens.scan_id" in coordinator_source
        assert "scopelens.scan_id" in inspect.getsource(
            supervisor.DockerWorkerSupervisor.stop_all_for_scan
        )


def literal_from_source(path: Path, name: str) -> str:
    """Read a module-level string constant without importing the module.

    The proxy addon cannot be imported here — it needs `mitmproxy`, which the backend
    deliberately does not depend on (docs/OPEN_QUESTIONS.md Q-9). Parsing the source is
    the only way to compare the constants the two environments must agree on.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and target.id == name
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    return node.value.value
    raise AssertionError(f"{name} not found as a string constant in {path.name}")


class TestProxyHooksArePresent:
    """Static guards for the CONNECT bypass found in review.

    The dynamic proof is `tests/containment/proxy_bypass.py`, run by `make test-proxy`,
    because it needs a real mitmproxy. These are the cheap guards that run in the normal
    suite: if someone removes a hook or drops an option, the fast tests say so before the
    expensive one has to.
    """

    def test_the_addon_hooks_connect_and_raw_transports(self) -> None:
        source = PROXY_ADDON.read_text(encoding="utf-8")
        for hook in ("def http_connect(", "def tcp_start(", "def udp_start(", "def request("):
            assert hook in source, f"broker/mitm_addon.py no longer defines {hook}"

    def test_connect_requires_a_token(self) -> None:
        """A CONNECT that is not identified must be refused before any tunnel opens."""
        source = PROXY_ADDON.read_text(encoding="utf-8")
        connect_body = source[
            source.index("def http_connect(") : source.index("def _block_connect(")
        ]
        assert "extract_token" in connect_body
        assert "missing_egress_token" in connect_body

    def test_proxy_disables_raw_tcp_and_eager_connections(self) -> None:
        """Both options are load-bearing; the bypass returns if either is removed."""
        import yaml

        compose = yaml.safe_load(
            (REPO_ROOT / "deploy" / "docker-compose.dev.yml").read_text(encoding="utf-8")
        )
        command = compose["services"]["proxy"]["entrypoint"]
        assert "connection_strategy=lazy" in command, (
            "eager connection strategy opens the upstream socket before the CONNECT "
            "decision, making that decision too late"
        )
        assert "rawtcp=false" in command, (
            "rawtcp enabled lets a non-TLS tunnel be relayed as raw TCP, bypassing every HTTP hook"
        )

    def test_the_policy_service_is_not_published(self) -> None:
        """The broker's decision endpoint must not be reachable from the host."""
        import yaml

        compose = yaml.safe_load(
            (REPO_ROOT / "deploy" / "docker-compose.dev.yml").read_text(encoding="utf-8")
        )
        policy = compose["services"]["policy"]
        assert "ports" not in policy, "the policy service publishes a port to the host"
        assert set(policy["networks"]) == {"control"}

    def test_the_operator_api_does_not_serve_the_broker_route(self) -> None:
        """It used to, on a published port, while a docstring said otherwise."""
        source = (PACKAGE_ROOT / "main.py").read_text(encoding="utf-8")
        assert "internal.router" not in source.replace("internal_app", "")

    def test_redis_requires_a_password(self) -> None:
        import yaml

        compose = yaml.safe_load(
            (REPO_ROOT / "deploy" / "docker-compose.dev.yml").read_text(encoding="utf-8")
        )
        command = " ".join(compose["services"]["redis"]["command"])
        assert "--requirepass" in command


class TestBrokerContractAgreement:
    """Constants duplicated across two dependency-isolated images, asserted equal.

    The worker image and the proxy image cannot import from each other, so each carries
    its own copy. A drift between them produces a 403 that looks like a policy decision
    rather than a version mismatch — which is exactly how the first end-to-end run failed.
    """

    def test_the_worker_and_the_proxy_agree_on_the_token_header(self) -> None:
        worker = literal_from_source(
            PACKAGE_ROOT / "checks" / "fetch_origin.py", "EGRESS_TOKEN_HEADER"
        )
        proxy = literal_from_source(PROXY_ADDON, "TOKEN_HEADER")
        assert worker == proxy

    def test_the_worker_marker_matches_the_supervisor_parser(self) -> None:
        worker = literal_from_source(PACKAGE_ROOT / "checks" / "fetch_origin.py", "RESULT_MARKER")
        supervisor = literal_from_source(
            PACKAGE_ROOT / "execution" / "supervisor.py", "RESULT_MARKER"
        )
        assert worker == supervisor


class TestProxyAddonIsolation:
    def test_addon_imports_nothing_from_scopelens(self) -> None:
        """It runs in the proxy image, which does not have the backend package."""
        offenders = sorted(
            name for name in imported_names(PROXY_ADDON) if name.split(".")[0] == "scopelens"
        )
        assert not offenders, (
            f"broker/mitm_addon.py must not import from scopelens (it runs in the proxy "
            f"image): {offenders}"
        )

    def test_addon_imports_only_stdlib_and_mitmproxy(self) -> None:
        allowed_third_party = {"mitmproxy"}
        offenders = []
        for name in imported_names(PROXY_ADDON):
            root = name.split(".")[0]
            if root in allowed_third_party or root in STDLIB_ROOTS:
                continue
            offenders.append(name)
        assert not offenders, f"unexpected imports in the proxy addon: {offenders}"

    def test_addon_fails_closed(self) -> None:
        """Every failure path in the policy client returns a denial, never an allow."""
        source = PROXY_ADDON.read_text(encoding="utf-8")
        assert 'return _deny("policy_unavailable"' in source
        assert 'return _deny("policy_malformed"' in source
        assert "allowed" in source


class TestEgressCapableModulesAreDeclared:
    def test_every_module_that_can_reach_a_target_is_declared(self) -> None:
        """An undeclared egress-capable module is a gap in the boundary's map.

        This does not prove a module *does* reach out — it proves nobody added an HTTP
        client or a connecting call without recording the reason here.
        """
        undeclared: list[str] = []
        for path in iter_python_files():
            relative = path.relative_to(PACKAGE_ROOT).as_posix()
            if relative in EGRESS_CAPABLE:
                continue
            if can_reach_a_target(path):
                undeclared.append(relative)

        assert not undeclared, (
            "these modules can open a connection but are not declared in EGRESS_CAPABLE "
            f"with a reason: {undeclared}"
        )

    def test_workers_live_only_on_the_worker_network(self) -> None:
        """The worker network is internal, so a worker's only route out is the proxy."""
        import yaml

        compose = yaml.safe_load(
            (REPO_ROOT / "deploy" / "docker-compose.dev.yml").read_text(encoding="utf-8")
        )
        worker_net = compose["networks"]["worker_net"]
        assert worker_net["name"] == "scopelens_worker_net"
        assert worker_net["internal"] is True

    def test_only_proxy_and_tls_lane_join_an_egress_capable_network(self) -> None:
        import yaml

        compose = yaml.safe_load(
            (REPO_ROOT / "deploy" / "docker-compose.dev.yml").read_text(encoding="utf-8")
        )
        for name, service in compose["services"].items():
            networks = set(service.get("networks") or {})
            if name == "callback-receiver":
                # Explicit opt-in receiver accepts isolated fixture callbacks. It
                # has no worker/egress network or published operator interface.
                assert networks == {"control", "labs"}
                assert service["profiles"] == ["callbacks"]
                assert not service.get("ports")
                assert "--no-access-log" in service["command"]
                continue
            if "egress" in networks or "labs" in networks:
                assert name in {"proxy", "tls-lane", "model-gateway"}, (
                    f"{name} is attached to a network with a route out; only the proxy and "
                    "the TLS lane may be"
                )

    def test_the_api_has_no_route_to_the_labs_or_the_internet(self) -> None:
        import yaml

        compose = yaml.safe_load(
            (REPO_ROOT / "deploy" / "docker-compose.dev.yml").read_text(encoding="utf-8")
        )
        api_networks = set(compose["services"]["api"]["networks"])
        assert api_networks == {"control"}


@pytest.mark.parametrize(
    "relative",
    [
        "callbacks/probes.py",
        "checks/expanded_active.py",
        "checks/packs/exposure.py",
        "identities/assessment.py",
        "identities/lifecycle.py",
        "identities/sessions.py",
        "workflows/assessment.py",
    ],
)
def test_expansion_collectors_cannot_construct_unbound_http_clients(relative):
    """New collectors must keep using injected transport, including import aliases."""
    tree = ast.parse((PACKAGE_ROOT / relative).read_text())
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update({a.asname or a.name: a.name for a in node.names})
        elif isinstance(node, ast.ImportFrom) and node.module:
            aliases.update({a.asname or a.name: f"{node.module}.{a.name}" for a in node.names})

    def name(node):
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return name(node.value) + "." + node.attr
        return ""

    forbidden = {
        "Client",
        "AsyncClient",
        "Session",
        "ClientSession",
        "PoolManager",
        "request",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "stream",
    }
    calls = [name(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)]
    assert not [
        n for n in calls if n.split(".")[0] in HTTP_CLIENT_ROOTS and n.split(".")[-1] in forbidden
    ], relative


def test_scanner_memory_is_configurable_without_widening_filesystem_or_network():
    settings = Settings(_env_file=None, scanner_worker_memory_limit_mb=2048)
    supervisor = DockerWorkerSupervisor(settings, client=object())
    spec = sample_spec(environment={"SCOPELENS_SCANNER_TOOLS_ENABLED": "true"})
    kwargs = supervisor._container_kwargs(spec)
    assert kwargs["mem_limit"] == "2048m"
    assert kwargs["tmpfs"] == {"/tmp": "rw,noexec,nosuid,size=256m"}
    assert kwargs["read_only"] and kwargs["cap_drop"] == ["ALL"]
    assert "volumes" not in kwargs and kwargs["network"] == spec.network
