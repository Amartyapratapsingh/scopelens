"""Release manifest (Build Plan §5.19, Implementation Plan §17.3).

Pins the application revision, database schema, every tool/template/browser/skill
version, the profile and score versions, and model-compatibility results.

THE ONE RULE HERE: a value that has not been measured is ``None`` or an explicit
status string, never a plausible-looking placeholder. A manifest that reports a
pinned scanner version the project has never run is worse than one that reports
``not_implemented``, because it makes the release look validated. Build Plan §0.3
forbids fabricated results; this file applies that rule to metadata as well.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from scopelens.config import REPO_ROOT, Settings
from scopelens.domain.registry import CheckRegistry, RegistryError, load_registry

MANIFEST_VERSION = "release-manifest-v1"


def model_compatibility(settings: Settings) -> list[dict]:
    """Publish measured smoke results only for the exact adapter and configured roles."""
    path = REPO_ROOT / "checks_registry/model_qualification.json"
    try:
        evidence = json.loads(path.read_text())
        adapter = REPO_ROOT / "backend/scopelens/adapters/roles.py"
        if evidence["adapter_sha256"] != hashlib.sha256(adapter.read_bytes()).hexdigest():
            return []
        results = []
        for record in evidence["results"]:
            name = record["role"]
            if name not in {"planner", "verification", "report_writer", "script", "browser"}:
                continue
            role = getattr(settings, ("planner" if name == "script" else name) + "_model")
            if (
                record.get("smoke_passed") is not True
                or role.model != record["model"]
                or role.base_url != record["provider"]
                or not record.get("configuration")
                or any(getattr(role, k, None) != v for k, v in record["configuration"].items())
            ):
                continue
            results.append(
                {
                    "role": name,
                    "model": role.model,
                    "provider": role.base_url,
                    "status": "synthetic_smoke_passed",
                    "recorded_at": evidence["recorded_at"],
                    "evidence_file": "checks_registry/model_qualification.json",
                    "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "limitations": evidence["limitations"],
                }
            )
        return results
    except (OSError, ValueError, KeyError, TypeError):
        return []


def git_revision() -> dict[str, Any]:
    """Current revision, or an explicit unknown. Never guesses."""
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError, FileNotFoundError):
        return {"commit": None, "dirty": None, "status": "unavailable"}

    try:
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            ).stdout.strip()
        )
    except (subprocess.SubprocessError, OSError):
        dirty = None

    return {"commit": revision, "dirty": dirty, "status": "ok"}


def pinned_images() -> dict[str, Any]:
    """Image references pinned in the compose files, by service.

    Reads the files rather than restating them, so the manifest cannot drift from the
    stack that actually runs.
    """
    images: dict[str, dict[str, str | None]] = {}
    for path in (
        REPO_ROOT / "deploy" / "docker-compose.dev.yml",
        REPO_ROOT / "labs" / "docker-compose.yml",
    ):
        if not path.exists():
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        for service, definition in (data.get("services") or {}).items():
            if not isinstance(definition, dict) or "image" not in definition:
                continue
            reference = str(definition["image"])
            repository, _, digest = reference.partition("@")
            images[service] = {
                "reference": reference,
                "repository": repository,
                "digest": digest or None,
                "source_file": str(path.relative_to(REPO_ROOT)),
            }
    return images


def _installed_version(distribution: str) -> str | None:
    """Version of a Python distribution, or None when it is not installed here.

    Read from package metadata rather than restated, so the manifest cannot claim a
    version the environment does not actually have.
    """
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version(distribution)
    except PackageNotFoundError:
        return None


def _tool_status() -> dict[str, Any]:
    """Scanner, dispatch and browser tooling.

    A tool that is not installed reports ``version: None`` rather than a plausible-looking
    number, so nothing downstream can mistake an absent tool for a pinned one. The ZAP,
    Nuclei and Playwright payloads arrive in M3, when the adapters that use them are built.
    """
    tools: dict[str, Any] = {
        # Present and used by M1.
        "celery": {"status": "in_use", "version": _installed_version("celery"), "milestone": "M2"},
        "redis": {"status": "in_use", "version": _installed_version("redis"), "milestone": "M2"},
        # Runs as its own image, not as a backend dependency (docs/OPEN_QUESTIONS.md Q-9).
        "mitmproxy": {
            "status": "in_use_separate_image",
            "version": "12.1.2",
            "milestone": "M2",
            "note": "pinned in deploy/proxy.Dockerfile; deliberately not a backend dependency",
        },
        # Not built yet.
        "zap": {"status": "not_implemented", "version": None, "milestone": "M3"},
        "nuclei": {"status": "not_implemented", "version": None, "milestone": "M3"},
        "testssl.sh": {"status": "not_implemented", "version": None, "milestone": "M3"},
        "playwright": {"status": "not_implemented", "version": None, "milestone": "M3"},
        "chromium": {"status": "not_implemented", "version": None, "milestone": "M3"},
        "langgraph": {
            "status": "in_use",
            "version": _installed_version("langgraph"),
            "milestone": "M4",
        },
    }
    runtime = _runtime_bundle()
    for name, version in runtime.get("versions", {}).items():
        tools[name] = {"status": "in_use_isolated_runtime", "version": version, "milestone": "M3"}
    return tools


def _runtime_bundle():
    path = REPO_ROOT / "checks_registry/tooling/runtime.json"
    return json.loads(path.read_text()) if path.exists() else {}


def _registry_summary(registry: CheckRegistry | None, error: str | None) -> dict[str, Any]:
    if registry is None:
        return {"status": "unavailable", "error": error, "controls": []}

    return {
        "status": "ok",
        "schema_version": registry.schema_version,
        "control_count": len(registry.entries),
        # Only `enabled` controls count as supported (Build Plan §5.19). Populated by
        # reading the registry, never by counting entries.
        "supported_control_ids": [e.id for e in registry.entries if e.is_supported],
        "experimental_control_ids": [
            e.id for e in registry.entries if e.review_state.value == "experimental"
        ],
        "controls": [
            {
                "id": e.id,
                "category": e.category.value,
                "review_state": e.review_state.value,
                "phase": e.availability.phase,
                "stance": e.availability.stance,
                "mandatory": e.mandatory,
                "coverage_weight": e.coverage_weight,
                "fixtures_verified": e.fixtures.verified,
            }
            for e in registry.entries
        ],
    }


def _schema_revision(session: Session | None) -> str | None:
    if session is None:
        return None
    from scopelens.persistence.repositories import database_revision

    return database_revision(session)


def build_manifest(settings: Settings, session: Session | None = None) -> dict[str, Any]:
    try:
        registry: CheckRegistry | None = load_registry(settings.checks_registry_dir)
        registry_error: str | None = None
    except RegistryError as exc:
        registry = None
        registry_error = str(exc)

    return {
        "manifest_version": MANIFEST_VERSION,
        "generated_at": datetime.now(UTC).isoformat(),
        "milestone": "M4/M5 backend candidate",
        "application": {
            **git_revision(),
            "name": "scopelens",
            "python_requires": "==3.12.*",
        },
        "database": {
            "engine": "postgresql",
            "schema_revision": _schema_revision(session),
        },
        "profiles": {
            "default": settings.default_profile,
            "score_version": settings.score_version,
            "check_registry_schema_version": settings.registry_schema_version,
        },
        "checks_registry": _registry_summary(registry, registry_error),
        # What M1 actually executes. Named explicitly so "a scan runs" cannot be read as
        # "the catalogue runs": this is the plumbing proof, not a security control.
        "execution": {
            "task_types": ["crawl", "cleanup_recovery_verify"],
            "m3_stages": [
                "zap_passive_har",
                "reviewed_nuclei",
                "conditional_config",
                "browser",
                "testssl_protocols",
            ],
            "note": (
                "Scoped HTTP crawl and separate TLS measurements, deterministic controls, "
                "evidence verification, coverage, scoring, retests and HTML/JSON reports. "
                "Component coverage requires an operator-configured advisory snapshot."
            ),
        },
        "tools": _tool_status(),
        "images": pinned_images(),
        "m3_runtime": _runtime_bundle(),
        "model_compatibility": model_compatibility(settings),
        # Capabilities this milestone deliberately does not contain. Listed so an
        # absent subsystem is visible in the manifest rather than inferred from silence.
        "unimplemented": [
            "reviewed_zap_active_task_capabilities",
            "adaptive_browser_identity_callback_dispatch",
            "expansion_qualification_harness",
        ],
        "expansion": {
            "status": "integration_pending",
            "configuration_schema": "immutable-assessment-configuration-v1",
            "discovery_imports": "bounded_offline_intake_and_frozen_configuration_connected_source",
            "browser_request_discovery": "normalized_request_intentions_captured_without_authorizing_blocked_actions",
            "assessment_revisions": "coordinator_history_and_write_ahead_no_replay_claims_connected_source",
            "browser_workflows": "dispatch_lease_intake_and_report_proof_connected_experimental",
            "http_identity_workflow_proofs": "connected_in_source_local_fixture_tests_passed",
            "authenticated_http_inputs": "role_isolated_transport_and_report_identity_proof_connected_source",
            "authenticated_browser_inputs": "three_context_identity_proof_deployed_lab_pair_passed_experimental",
            "credentialed_cors": "native_browser_cookie_proof_connected_source_experimental_deployed_gate_pending",
            "callback_assessments": "broker_dispatch_and_signed_receipt_proof_deployed_four_case_gate_passed_experimental",
            "cleanup_recovery": "fresh_authority_read_only_verification_deployed_synthetic_pending_intent_gate_passed",
            "expanded_scanner_runner": "five_pinned_templates_proxy_fixture_tested_runtime_connected_source",
            "expanded_scoring": "versioned_pilot_rubrics_locally_tested_not_qualified",
            "report_reach": "frozen_plan_instance_completion_and_unknown_capability_totals_connected_source",
            "runtime_capability_measurement": "supervisor_offline_image_and_source_binding_connected_source_deployment_gate_pending",
            "adaptive_contexts": "anonymous_browser_supplied_sessions_stored_callback_verification_connected_source_deployment_gates_pending",
            "expanded_components": "pinned_12_package_194_record_corpus_connected_in_source",
            "qualified_new_families": [],
            "note": "Source registry inventory does not attest to deployment of current worker images.",
        },
        "release_qualification": {
            "status": "not_qualified",
            "required": [
                "independent held-out benchmark",
                "configured provider qualification",
                "authorized owned-site pilot",
                "final production worker-boundary validation",
            ],
            "note": "Implemented backend paths are distinct from independently validated release claims.",
        },
        "m4": {
            "graph": "baseline-observe-plan-admit-execute-verify",
            "prompt_version": "roles-v1",
            "sandbox": "dedicated-lima-vz-systemd-v1",
            "model_adapter": "bounded non-streaming JSON proposals; all roles share reservations",
            "mcp": "disabled; no remote MCP servers configured",
            "skills_manifest_sha256": __import__("hashlib")
            .sha256((REPO_ROOT / "skills/manifest.json").read_bytes())
            .hexdigest(),
        },
    }


def write_manifest(settings: Settings, session: Session | None = None) -> Path:
    """Write the manifest to disk. Returns the path written."""
    import json

    manifest = build_manifest(settings, session)
    path = Path(settings.release_manifest_path)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path
