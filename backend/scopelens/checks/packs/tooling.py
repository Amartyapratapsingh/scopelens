"""Pinned reviewed tool bundles and exact request bindings for future active adapters.

Only templates listed in the local manifest are returned. A tool match is a candidate;
exposure.py provides the independent proof. ZAP active admission requires an enforced
transport capability, not merely a context/includePaths regular expression.
"""

import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class TemplatePin(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    file: str
    sha256: str
    control_id: str
    canonical_control: str
    technologies: list[str]
    method: str
    path: str
    max_requests: int
    proof: str
    review_state: str


def reviewed_templates(folder: Path, technologies=()) -> list[TemplatePin]:
    manifest = json.loads((folder / "manifest.json").read_text())
    if manifest["nuclei_version"] != "3.11.1":
        raise ValueError("unreviewed Nuclei engine version")
    technology = {t.lower() for t in technologies}
    selected = []
    for raw in manifest["templates"]:
        pin = TemplatePin.model_validate(raw)
        path = (folder / pin.file).resolve()
        if path.parent != folder.resolve():
            raise ValueError("template escapes pinned bundle")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != pin.sha256:
            raise ValueError("template integrity failure")
        template = yaml.safe_load(data)
        if set(template) != {"id", "info", "http"} or template["id"] != pin.id:
            raise ValueError("unreviewed template structure")
        requests = template["http"]
        if (
            len(requests) != 1
            or requests[0].get("method") != "GET"
            or requests[0].get("redirects") is not False
            or requests[0].get("path") != ["{{RootURL}}" + pin.path]
        ):
            raise ValueError("template differs from reviewed request binding")
        if not pin.technologies or technology.intersection(pin.technologies):
            selected.append(pin)
    return selected


class ActiveRuleBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    rule_id: int = 40012  # ZAP reflected-XSS signal, confirmation belongs to browser proof.
    url: str
    method: str = "GET"
    parameter: str
    max_requests: int = Field(default=12, ge=1, le=24)
    deadline_seconds: int = Field(default=30, ge=1, le=60)

    @model_validator(mode="after")
    def reviewed_only(self):
        p = urlsplit(self.url)
        pairs = parse_qsl(p.query, keep_blank_values=True)
        if (
            self.rule_id != 40012
            or self.method != "GET"
            or p.scheme not in {"http", "https"}
            or not p.hostname
            or p.username
            or p.password
            or p.fragment
        ):
            raise ValueError("unreviewed active rule/request")
        if len([k for k, _ in pairs if k == self.parameter]) != 1:
            raise ValueError("one reviewed query input required")
        return self

    def accepts(self, method: str, url: str, body: bytes = b"") -> bool:
        """Used by a transport gate on every request; unrelated query values stay fixed."""
        base, current = urlsplit(self.url), urlsplit(url)
        if (
            method != self.method
            or body
            or (current.scheme, current.netloc, current.path)
            != (base.scheme, base.netloc, base.path)
            or current.fragment
            or current.username
            or current.password
        ):
            return False
        original, proposed = (
            parse_qsl(base.query, keep_blank_values=True),
            parse_qsl(current.query, keep_blank_values=True),
        )
        return sorted(k for k, _ in original) == sorted(k for k, _ in proposed) and sorted(
            (k, v) for k, v in original if k != self.parameter
        ) == sorted((k, v) for k, v in proposed if k != self.parameter)


def zap_active_admission(binding: ActiveRuleBinding, *, transport_capability: dict | None):
    """No caller boolean can claim enforcement; require matching broker-issued binding digest.

    The trusted runner validates capability identity/expiry in its broker. This helper
    checks its shape and binding. It does not execute ZAP or authenticate a capability.
    """
    digest = hashlib.sha256(binding.model_dump_json().encode()).hexdigest()
    if (
        not transport_capability
        or transport_capability.get("binding_sha256") != digest
        or not transport_capability.get("capability_id")
        or transport_capability.get("enforced_fields")
        != [
            "method",
            "origin",
            "path",
            "query_keys",
            "fixed_query_values",
            "body",
            "requests",
            "deadline",
        ]
    ):
        return {
            "state": "blocked",
            "reason": "Exact broker-bound active-rule capability unavailable",
        }
    return {
        "state": "admitted",
        "binding_sha256": digest,
        "rule_id": binding.rule_id,
        "requires_runner_capability_verification": True,
    }
