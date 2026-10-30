"""Central configuration for ScopeLens.

Every setting is environment-driven with the ``SCOPELENS_`` prefix. No secret is ever
defaulted to a usable value: the session secret and operator password hash have no
defaults, so a misconfigured deployment fails closed at startup instead of running
with a guessable key (Build Plan §0.7).
"""

from __future__ import annotations

import enum
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Environment(enum.StrEnum):
    DEV = "dev"
    TEST = "test"
    PRODUCTION = "production"


class Budgets(BaseModel):
    """Execution budgets.

    Starting values are the conservative pilot defaults from Project Specification §12.
    Explicit operator-approved scope overrides may raise concurrency and request rate
    up to the separate Settings ceilings. Other overrides only lower these defaults.
    Scope creation is versioned and audited (Spec §12).
    """

    requests_per_second: float = 2.0
    max_in_flight: int = 2
    max_pages: int = 300
    max_crawl_depth: int = 4
    max_total_requests: int = 5000
    wall_clock_seconds: int = 45 * 60
    request_timeout_seconds: float = 10.0
    max_body_bytes: int = 1024 * 1024
    max_redirects_per_fetch: int = 5
    stop_after_consecutive_errors: int = 10

    @model_validator(mode="after")
    def _sane(self) -> Budgets:
        if self.max_in_flight < 1:
            raise ValueError("max_in_flight must be >= 1")
        if self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        return self


class ModelRoleSettings(BaseModel):
    """Provider configuration for one logical role (Build Plan §5.18).

    No model name is hardcoded in a node (Build Plan §0.5). A role with no ``model``
    configured is simply unavailable; nothing falls back to a built-in default.
    M0 only carries these placeholders — the adapter itself is M4.
    """

    base_url: str | None = Field(default=None, repr=False)
    api_key: SecretStr | None = None
    model: str | None = None
    timeout_seconds: float = Field(default=60.0, gt=0, le=120)
    max_output_tokens: int | None = None
    token_limit_parameter: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    response_format: Literal["json_object", "json_schema"] = "json_object"
    reasoning_effort: Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"] | None = (
        None
    )
    vision: bool = False
    json_mode: bool = False

    tools: bool = False
    streaming: bool = False
    context_tokens: int = Field(default=16000, ge=1024)
    input_price_per_million: float | None = Field(default=None, ge=0)
    output_price_per_million: float | None = Field(default=None, ge=0)
    fallbacks: list[ModelRoleSettings] = Field(default_factory=list)

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.model)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SCOPELENS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # Nested settings are addressed with a double underscore, e.g.
        # SCOPELENS_REPORT_WRITER__MODEL=...
        env_nested_delimiter="__",
    )

    environment: Environment = Environment.DEV
    # Endpoints may contain basic-auth userinfo or query credentials. Keep their string
    # values usable by clients, while omitting them from repr/str diagnostics.
    database_url: str = Field(
        default="postgresql+psycopg://scopelens:scopelens@localhost:5433/scopelens", repr=False
    )

    # --- Operator authentication (Build Plan §5.1) -------------------------------
    operator_username: str = "operator"
    # bcrypt hash. No default: the account cannot be seeded without it.
    operator_password_hash: SecretStr | None = None
    # Plaintext alternative for first-run seeding only. Ignored when a hash is set.
    operator_password: SecretStr | None = None

    session_secret: SecretStr | None = None
    session_cookie_name: str = "scopelens_session"
    session_max_age_seconds: int = 12 * 60 * 60
    session_https_only: bool | None = None

    # --- M1 execution -----------------------------------------------------------
    # Scanner execution is real from M1 onwards. `execution/gate.py` was deleted: the
    # flag now genuinely enables execution, and the fences around it are the lease,
    # the budget reservation, the policy broker and the cancellation epoch — not the
    # absence of a code path.
    scanner_execution_enabled: bool = True

    # Staged supervisor-mediated ZAP grants; no ordinary worker receives this key.
    zap_active_lab_enabled: bool = False
    zap_active_signing_key: SecretStr | None = Field(default=None, repr=False)
    zap_active_allowlist_file: Path = REPO_ROOT / "checks_registry/tooling/zap-active.json"

    # Dispatch. Redis/Celery deliver notifications only; PostgreSQL owns scan truth.
    redis_url: str = Field(default="redis://redis:6379/0", repr=False)
    outbox_poll_interval_seconds: float = 1.0
    outbox_batch_size: int = 20

    # Coordinator leases (Build Plan §5.2). One renewable lease per scan. The TTL must
    # exceed the renew interval by enough that a slow renewal is not mistaken for a
    # lost lease, and be short enough that a dead coordinator is replaced promptly.
    lease_ttl_seconds: int = 30
    lease_renew_interval_seconds: float = 10.0

    # Supervisor / worker lifecycle (Build Plan §5.4).
    docker_host: str = Field(default="unix:///var/run/docker.sock", repr=False)
    worker_network: str = "scopelens_worker_net"
    tool_worker_image: str = "scopelens/tool-worker:dev"
    browser_worker_image: str = "scopelens/browser-worker:dev"
    model_gateway_url: str = Field(default="http://model-gateway:8080", repr=False)
    approved_model_base_urls: list[str] = Field(default_factory=list, repr=False)
    browser_model_max_calls: int = Field(default=3, ge=1, le=10)
    adaptive_enabled: bool = False
    adaptive_max_tasks: int = Field(default=6, ge=1, le=30)
    adaptive_max_rounds: int = Field(default=3, ge=1, le=3)
    model_max_calls: int = Field(default=30, ge=1, le=100)
    model_cost_ceiling: float = Field(default=5.0, gt=0)
    sandbox_gateway_url: str = Field(default="http://host.docker.internal:8097", repr=False)
    generated_scripts_enabled: bool = False
    scanner_tools_enabled: bool = False
    kali_worker_image: str = "scopelens/kali-tool:dev"
    browser_enabled: bool = False
    # Triage metadata only. These roots do not grant worker/broker scan authority.
    discovery_owned_domains: tuple[str, ...] = ()
    passive_discovery_enabled: bool = True
    browser_max_actions: int = Field(default=24, ge=1, le=100)
    browser_max_active_actions: int = Field(default=500, ge=1)
    browser_max_states: int = Field(default=12, ge=1, le=100)
    browser_seccomp_path: Path = REPO_ROOT / "deploy" / "browser" / "seccomp.json"
    worker_cpu_limit: float = 1.0
    worker_memory_limit_mb: int = 512
    scanner_worker_memory_limit_mb: int = Field(default=2048, ge=512, le=8192)
    worker_pids_limit: int = 256
    # SIGTERM grace before SIGKILL. Deliberately far below the 30 s cancellation target
    # (Build Plan §5.6): using the whole deadline as the grace period makes the deadline
    # unreachable by construction, which measurement caught rather than inspection.
    worker_stop_grace_seconds: int = 5
    # A worker that outlives its task is killed. Generous relative to a single bounded
    # HTTP check, but bounded: an unbounded worker is a leak, not a policy.
    worker_max_runtime_seconds: int = Field(default=1800, ge=60, le=21600)

    # Policy broker (Build Plan §5.3).
    policy_service_url: str = Field(default="http://127.0.0.1:8000", repr=False)
    proxy_host: str = Field(default="proxy", repr=False)
    proxy_http_port: int = 8080
    proxy_max_in_flight: int = Field(default=8, ge=1)
    # Hard per-scan ceilings, separate from the conservative 2/2 budget defaults.
    scope_max_in_flight: int = Field(default=8, ge=1)
    scope_max_requests_per_second: float = Field(default=10.0, gt=0, allow_inf_nan=False)
    # The CA mitmproxy generates. Workers trust it explicitly rather than the system
    # store, so only the proxy's intercepting identity is trusted, not arbitrary roots.
    proxy_ca_path: Path = Path("/var/lib/scopelens/proxy/mitmproxy-ca-cert.pem")
    tls_lane_url: str = Field(default="http://tls-lane:8080", repr=False)
    tls_lab_ca_file: Path | None = None
    advisory_bundle_file: Path | None = None

    # Evidence (Build Plan §5.5).
    callback_collector_origins: tuple[str, ...] = ()
    callback_signing_key: SecretStr | None = Field(default=None, repr=False)
    identity_encryption_key: SecretStr | None = None
    identity_store_path: Path = REPO_ROOT / "runs" / "identity_secrets"
    evidence_retention_days: int = Field(default=30, ge=1, le=3650)
    evidence_encryption_key: SecretStr | None = None
    evidence_store_path: Path = REPO_ROOT / "runs" / "evidence"

    # --- Paths ------------------------------------------------------------------
    checks_registry_dir: Path = REPO_ROOT / "checks_registry"
    lab_services_file: Path = REPO_ROOT / "deploy" / "lab_services.yaml"
    evaluation_dir: Path = REPO_ROOT / "evaluation"
    release_manifest_path: Path = REPO_ROOT / "release_manifest.json"

    # --- Profiles / versions (Build Plan §5.15, §5.19) --------------------------
    default_profile: str = "external-configuration"
    score_version: str = "score-v1.0"
    registry_schema_version: str = "check-registry-v1"

    budgets: Budgets = Field(default_factory=Budgets)

    # --- Model roles (placeholders; adapter is M4) ------------------------------
    planner_model: ModelRoleSettings = Field(default_factory=ModelRoleSettings)
    browser_model: ModelRoleSettings = Field(default_factory=ModelRoleSettings)
    verification_model: ModelRoleSettings = Field(default_factory=ModelRoleSettings)
    report_writer_model: ModelRoleSettings = Field(default_factory=ModelRoleSettings)

    @model_validator(mode="after")
    def _validate_secrets(self) -> Settings:
        if (
            self.zap_active_signing_key
            and len(self.zap_active_signing_key.get_secret_value().encode()) < 32
        ):
            raise ValueError("ZAP task signing key requires at least 32 bytes")
        if self.zap_active_lab_enabled and not self.zap_active_signing_key:
            raise ValueError("lab ZAP task grants require a supervisor signing key")
        if self.environment is Environment.PRODUCTION:
            missing = [
                name
                for name, value in (
                    ("SCOPELENS_SESSION_SECRET", self.session_secret),
                    ("SCOPELENS_OPERATOR_PASSWORD_HASH", self.operator_password_hash),
                )
                if value is None
            ]
            if missing:
                raise ValueError(f"required in production but unset: {', '.join(missing)}")
        return self

    @model_validator(mode="after")
    def _validate_callbacks(self):
        for origin in self.callback_collector_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("callback collector must be an exact HTTP origin")
            _ = parsed.port
        if (
            self.callback_signing_key
            and len(self.callback_signing_key.get_secret_value().encode()) < 32
        ):
            raise ValueError("callback signing key requires at least 32 bytes")
        return self

    @property
    def callbacks_enabled(self):
        return bool(self.callback_collector_origins and self.callback_signing_key)

    @property
    def cookie_secure(self) -> bool:
        """``Secure`` on the session cookie outside development."""
        if self.session_https_only is not None:
            return self.session_https_only
        return self.environment is Environment.PRODUCTION


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
