"""Exact native-ZAP task contracts and potential-only report normalization.

Shape validation never authorizes a launch. The trusted supervisor and signed broker
channel enforce actual requests. The shipped operator approval manifest is empty.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import date
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from scopelens.adapters.scanners import ScannerObservation
from scopelens.domain.enums import AuthorityDomain, ProfileName

MAX_REPORT_BYTES = 1_048_576
REVIEWED_RULES: dict[str, ActiveRulePin] = {}


def _sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _request_parts(url: str) -> tuple[str, str, str, tuple[tuple[str, str], ...]]:
    part = urlsplit(url)
    if (
        part.scheme not in {"http", "https"}
        or not part.hostname
        or part.username
        or part.password
        or part.fragment
        or not part.path.startswith("/")
        or "\\" in part.path
        or "%" in part.path
        or ";" in part.query
    ):
        raise ValueError("ambiguous or non-HTTP request destination")
    try:
        port = part.port or (443 if part.scheme == "https" else 80)
        pairs = parse_qsl(part.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise ValueError("ambiguous request destination") from exc
    if not 0 < port < 65536 or len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate query key or invalid port")
    return part.scheme, f"{part.hostname.lower()}:{port}", part.path, tuple(pairs)


class ActiveRulePin(BaseModel):
    """Operator-reviewed *exact* rule/config and finite harmless input values."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    rule_id: str
    control_id: str
    engine_version: str
    engine_sha256: str
    rule_config_sha256: str
    allowed_values: tuple[str, ...]
    max_requests: int = Field(ge=1, le=24)
    deadline_seconds: int = Field(ge=1, le=60)
    addon_filename: str | None = None
    addon_sha256: str | None = None

    @model_validator(mode="after")
    def valid_pin(self):
        if (
            not self.rule_id.isdecimal()
            or not self.control_id.startswith("SL-")
            or not self.engine_version
            or not _sha256(self.engine_sha256)
            or not _sha256(self.rule_config_sha256)
            or not self.allowed_values
            or len(set(self.allowed_values)) != len(self.allowed_values)
            or len(self.allowed_values) > self.max_requests
            or any(not value or len(value) > 128 for value in self.allowed_values)
            or (self.addon_sha256 is not None and not _sha256(self.addon_sha256))
            or (
                self.addon_filename is not None
                and (
                    Path(self.addon_filename).name != self.addon_filename
                    or not self.addon_filename.startswith("ascanrules-release-")
                    or not self.addon_filename.endswith(".zap")
                )
            )
        ):
            raise ValueError("incomplete reviewed rule pin")
        return self


class ApprovedOrigin(BaseModel):
    """An exact origin, never a wildcard, redirect destination or subdomain grant."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    scheme: Literal["http", "https"]
    host: str
    port: int = Field(strict=True, ge=1, le=65535)

    @model_validator(mode="after")
    def exact_host(self):
        try:
            valid = str(ipaddress.ip_address(self.host)) == self.host
        except ValueError:
            valid = (
                bool(
                    re.fullmatch(
                        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*",
                        self.host,
                    )
                )
                and len(self.host) <= 253
            )
        if not valid:
            raise ValueError("approval host must be a canonical exact hostname or IP")
        return self

    def matches(self, url: str) -> bool:
        try:
            scheme, authority, _, _ = _request_parts(url)
            return scheme == self.scheme and authority == f"{self.host}:{self.port}"
        except ValueError:
            return False


class OperatorApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    operator: str = Field(min_length=1, max_length=200)
    date: date
    decision: str = Field(min_length=1, max_length=4000)

    @model_validator(mode="after")
    def explicit_record(self):
        if not self.operator.strip() or not self.decision.strip():
            raise ValueError("operator and decision must be explicit")
        return self


class OriginScopedRulePin(ActiveRulePin):
    approved_origins: tuple[ApprovedOrigin, ...] = Field(min_length=1, max_length=16)
    approval: OperatorApproval

    @model_validator(mode="after")
    def unique_origins(self):
        if self.rule_id != "40012" or len(set(self.approved_origins)) != len(self.approved_origins):
            raise ValueError("only 40012 with distinct exact origins is supported")
        return self


def rule_authorized_for_scope(pin, scope, *, profile=None, url=None) -> bool:
    """Independent dispatch/broker origin guard; v1 confers lab authority only."""
    if pin is None or (profile is not None and profile != scope.allowed_check_profile.value):
        return False
    if scope.authority_domain == AuthorityDomain.LAB:
        binding = getattr(scope, "lab_binding", None)
        eligible = (
            scope.allowed_check_profile == ProfileName.EXTERNAL_ACTIVE_V2
            and binding is not None
            and binding.service in {"labs-good", "labs-bad"}
        )
    else:
        eligible = (
            scope.authority_domain == AuthorityDomain.PRODUCTION
            and scope.allowed_check_profile == ProfileName.EXTERNAL_DAST
            and isinstance(pin, OriginScopedRulePin)
        )
    if not eligible:
        return False
    if isinstance(pin, OriginScopedRulePin):
        destination = url or scope.origin + "/"
        return any(origin.matches(destination) for origin in pin.approved_origins) and any(
            origin.matches(scope.origin + "/") for origin in pin.approved_origins
        )
    return scope.authority_domain == AuthorityDomain.LAB


def reviewed_rule(rule_id: str, settings=None) -> ActiveRulePin | None:
    """An empty shipped approval manifest is inert; proposals confer no authority.

    The in-memory registry is retained for isolated contract fixtures. Deployments use
    only a committed operator-reviewed manifest in the immutable control-plane image.
    Invalid/missing manifests fail closed, never falling back to a proposed rule.
    """
    if rule_id in REVIEWED_RULES:
        return REVIEWED_RULES[rule_id]
    if settings is None:
        return None
    try:
        data = json.loads(settings.zap_active_allowlist_file.read_bytes())
        if set(data) != {"version", "approved_rules"} or data["version"] not in {
            "zap-active-allowlist-v1",
            "zap-active-allowlist-v2",
        }:
            return None
        model = (
            OriginScopedRulePin if data["version"] == "zap-active-allowlist-v2" else ActiveRulePin
        )
        pins = [model.model_validate(row) for row in data["approved_rules"]]
        if len(pins) > 4 or len({pin.rule_id for pin in pins}) != len(pins):
            return None
        return next((pin for pin in pins if pin.rule_id == rule_id), None)
    except (OSError, ValueError, TypeError, KeyError):
        return None


class ActiveRuleTask(BaseModel):
    """A frozen GET input identity; exact URLs are checked again for every request."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    scan_id: str
    task_id: str
    input_id: str
    rule_id: str
    url: str
    method: Literal["GET"] = "GET"
    input_name: str
    rule_config_sha256: str
    max_requests: int = Field(ge=1, le=24)
    deadline_seconds: int = Field(ge=1, le=60)

    @model_validator(mode="after")
    def valid_task(self):
        if not all(
            (self.scan_id, self.task_id, self.input_id, self.rule_id, self.input_name)
        ) or not _sha256(self.rule_config_sha256):
            raise ValueError("incomplete active task identity")
        *_, pairs = _request_parts(self.url)
        if sum(name == self.input_name for name, _ in pairs) != 1:
            raise ValueError("exactly one named query input required")
        return self

    def accepts(self, method: str, url: str, body: bytes, pin: ActiveRulePin) -> bool:
        """Finite request guard; never itself an admission grant."""
        if method != "GET" or body or pin.rule_id != self.rule_id:
            return False
        try:
            base, offered = _request_parts(self.url), _request_parts(url)
        except ValueError:
            return False
        if base[:3] != offered[:3]:
            return False
        old, new = dict(base[3]), dict(offered[3])
        return (
            old.keys() == new.keys()
            and all(old[key] == value for key, value in new.items() if key != self.input_name)
            and new[self.input_name] in pin.allowed_values
        )


class ActiveAdmission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    state: Literal["blocked"] = "blocked"
    reason: str
    task_sha256: str | None = None
    rule_config_sha256: str | None = None


def active_admission(task: ActiveRuleTask) -> ActiveAdmission:
    """Legacy shape-only admission remains blocked; grants need trusted supervision.

    Callers cannot use this helper to authorize native execution. The launcher issues
    a separate database-backed grant after creating the exact network-none container.
    """
    pin = REVIEWED_RULES.get(task.rule_id)
    if pin is None:
        return ActiveAdmission(reason="rule has no reviewed executable pin")
    if (
        task.rule_config_sha256 != pin.rule_config_sha256
        or task.max_requests > pin.max_requests
        or task.deadline_seconds > pin.deadline_seconds
    ):
        return ActiveAdmission(reason="task differs from reviewed rule limits")
    return ActiveAdmission(
        reason="shape-only admission cannot authorize broker-bound native launch; lab gate pending",
        task_sha256=hashlib.sha256(task.model_dump_json().encode()).hexdigest(),
        rule_config_sha256=pin.rule_config_sha256,
    )


class ActiveCandidateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: Literal["completed", "partial", "error", "timeout", "cancelled"]
    task_id: str
    input_id: str
    rule_id: str
    rule_config_sha256: str
    output_sha256: str
    observations: list[ScannerObservation] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


def normalize_active_report(
    task: ActiveRuleTask,
    pin: ActiveRulePin,
    raw: bytes,
    *,
    exit_code: int | None = 0,
    truncated: bool = False,
    timed_out: bool = False,
    cancelled: bool = False,
) -> ActiveCandidateResult:
    """Normalize only bound alerts. Never confer coverage or confirmation."""
    digest = hashlib.sha256(raw).hexdigest()
    errors: list[str] = []
    observations: list[ScannerObservation] = []
    if task.rule_id != pin.rule_id or task.rule_config_sha256 != pin.rule_config_sha256:
        errors.append("report has no matching reviewed task pin")
    elif len(raw) > MAX_REPORT_BYTES:
        errors.append("tool report exceeds retained output limit")
    else:
        try:
            document = json.loads(raw)
            if not isinstance(document, dict) or not isinstance(document.get("site"), list):
                raise ValueError("invalid report root")
            seen: set[tuple[str, str]] = set()
            for site in document["site"]:
                if not isinstance(site, dict) or not isinstance(site.get("alerts", []), list):
                    raise ValueError("invalid site")
                for alert in site.get("alerts", []):
                    if not isinstance(alert, dict) or str(alert.get("pluginid")) != pin.rule_id:
                        errors.append("unknown or missing rule in tool report")
                        continue
                    instances = alert.get("instances")
                    if not isinstance(instances, list) or not instances:
                        errors.append("rule alert has no bound instance")
                        continue
                    for instance in instances:
                        url = instance.get("uri") if isinstance(instance, dict) else None
                        if not isinstance(url, str) or not task.accepts("GET", url, b"", pin):
                            errors.append("tool observation outside task request binding")
                            continue
                        identity = (pin.rule_id, url)
                        if identity in seen:
                            continue
                        seen.add(identity)
                        if len(seen) > task.max_requests:
                            errors.append("tool observations exceed task request ceiling")
                            continue
                        observations.append(
                            ScannerObservation(
                                tool="zap",
                                tool_version=pin.engine_version,
                                rule_id=pin.rule_id,
                                title="Reviewed ZAP rule candidate",
                                reported_severity=str(alert.get("riskcode", "unknown")),
                                locations=[url],
                                evidence="Bound tool candidate; independent proof required",
                                mapped_control=pin.control_id,
                                output_hash=digest,
                            )
                        )
        except (ValueError, TypeError, AttributeError):
            errors.append("malformed ZAP active report")
            observations.clear()
    if truncated:
        errors.append("output truncated")
    if exit_code:
        errors.append(f"process exit {exit_code}")
    state = (
        "cancelled"
        if cancelled
        else "timeout"
        if timed_out
        else "partial"
        if errors and observations
        else "error"
        if errors
        else "completed"
    )
    return ActiveCandidateResult(
        state=state,
        task_id=task.task_id,
        input_id=task.input_id,
        rule_id=task.rule_id,
        rule_config_sha256=pin.rule_config_sha256,
        output_sha256=digest,
        observations=observations,
        errors=errors,
    )
