"""Trusted coordinator binding of offline image measurements to executable plans."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from scopelens.domain.capabilities import runtime_control_decisions
from scopelens.domain.enums import ProfileName
from scopelens.domain.registry import CheckRegistry
from scopelens.execution.capability_probe import ProbeFailure, build_capability_snapshot


def source_digest(root: Path | None = None) -> str:
    """Same source tree digest as the fixed offline probe, excluding bytecode."""
    root = root or Path(__file__).resolve().parents[2]
    rows = [
        str(path.relative_to(root)) + ":" + hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*.py"))
        if "__pycache__" not in path.parts
    ]
    if not rows:
        raise ProbeFailure("candidate source unavailable")
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()


def bind_measurement(plan: dict, *, scan_id, scope, settings, measurement: dict) -> dict:
    """Freeze complete decisions, including unavailable controls, before dispatch.

    This is capability inventory, not broker authorization or assessment completion.
    Each actual request still needs the live broker lease, scope and budget checks.
    Callers must already hold current execution authority.
    """
    updated = {**plan}
    updated.pop("capability_snapshot", None)
    candidate = measurement.get("source_sha256")
    if candidate != source_digest() or not measurement.get("image_bindings"):
        return updated
    registry = CheckRegistry.model_validate(plan["registry"])
    profile = scope.allowed_check_profile.value
    enabled = registry.supported_for_profile(ProfileName(profile))
    admitted, ready = [], []
    live = scope.authorization_expires_at > datetime.now(UTC)
    from scopelens.execution.coordinator import scope_entry_url

    try:
        scope_entry_url(scope)
        has_entry = True
    except Exception:  # noqa: BLE001 - missing authority must never imply readiness.
        has_entry = False
    for entry in enabled:
        # Enabled legacy implementations are passive evaluations of GET captures.
        # Unknown/new action shapes require an explicit producer implementation.
        passive = entry.allowed_action.max_requests == 0 and entry.availability.stance in {
            "OBSERVE",
            "FLAG",
        }
        can_get = "GET" in scope.allowed_methods and has_entry
        if live and passive and can_get:
            admitted.append(entry.id)
        prerequisites = passive and entry.prerequisites.credentials == "none"
        if entry.id in {"SL-C01-TLS-01", "SL-C01-HSTS-01", "SL-C01-MIXED-01"}:
            prerequisites = prerequisites and scope.scheme == "https"
        if entry.id == "SL-C01-TLS-01":
            prerequisites = prerequisites and bool(settings.tls_lane_url)
        if entry.id == "SL-C01-REDIR-01":
            prerequisites = prerequisites and bool(scope.transport_http_port)
        if entry.id == "SL-C06-COMPONENT-01":
            prerequisites = prerequisites and bool(
                plan.get("advisories", {}).get("bundle", {}).get("records")
            )
        if prerequisites:
            ready.append(entry.id)
    updated.update(
        capability_candidate_fingerprint=candidate,
        capability_expected_images=measurement["image_bindings"],
        capability_execution_plan={
            "version": "coordinator-capability-v1",
            "admitted_control_ids": sorted(admitted),
            "prerequisites_satisfied_ids": sorted(ready),
            "browser_enabled": settings.browser_enabled,
            "scanner_tools_enabled": settings.scanner_tools_enabled,
            "adaptive_claim_ids": sorted(row["id"] for row in plan.get("hypotheses", [])),
        },
    )
    updated["capability_snapshot"] = build_capability_snapshot(
        updated,
        scan_id=str(scan_id),
        scope_version_id=str(scope.id),
        profile=profile,
        measurement=measurement,
        runtime_controls=runtime_control_decisions(updated, profile=profile),
    )
    return updated
