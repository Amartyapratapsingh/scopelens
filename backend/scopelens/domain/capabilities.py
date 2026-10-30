"""Distinct installation, executable-control and qualification counts.

Only trusted coordinator state may carry a capability snapshot. This module computes
bindings from the actual frozen plan and never reads a release manifest as evidence.
"""

import hashlib
import json
from typing import Any


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def plan_bindings(
    plan: dict, *, scan_id: str, scope_version_id: str, profile: str
) -> dict[str, str]:
    """Recompute stable inputs; execution results and live revisions are excluded.

    A trusted coordinator must freeze the final execution plan before measuring.
    Missing candidate/image context intentionally prevents a published total.
    """
    frozen = {
        key: plan.get(key)
        for key in (
            "registry",
            "expansion_config",
            "configuration_id",
            "configuration_hash",
            "request_catalogue",
            "input_assessment_plan",
            "adaptive_requested",
            "capability_execution_plan",
        )
    }
    return {
        "scan_id": str(scan_id),
        "scope_version_id": str(scope_version_id),
        "profile": profile,
        "candidate_fingerprint": plan.get("capability_candidate_fingerprint", ""),
        "registry_sha256": canonical_sha256(plan.get("registry")),
        "configuration_sha256": canonical_sha256(
            {
                key: plan.get(key)
                for key in ("expansion_config", "configuration_id", "configuration_hash")
            }
        ),
        "plan_sha256": canonical_sha256(frozen),
    }


def snapshot_matches(
    snapshot: dict, plan: dict, *, scan_id: str, scope_version_id: str, profile: str
) -> bool:
    expected = plan_bindings(
        plan, scan_id=scan_id, scope_version_id=scope_version_id, profile=profile
    )
    if not expected["candidate_fingerprint"] or not plan.get("capability_expected_images"):
        return False
    if any(snapshot.get(key) != value for key, value in expected.items()):
        return False
    images = plan["capability_expected_images"]
    image_ids = {item.get("image_id") for item in images if isinstance(item, dict)}
    tools = snapshot.get("installed_tools", [])
    controls = snapshot.get("runtime_controls", [])
    return (
        isinstance(images, list)
        and snapshot.get("image_bindings") == images
        and len({item.get("role") for item in images if isinstance(item, dict)}) == len(images)
        and all(item.get("image_id") in image_ids for item in tools)
        and len({item.get("control_id") for item in controls}) == len(controls)
        and snapshot.get("source_sha256") == expected["candidate_fingerprint"]
    )


def runtime_control_decisions(plan: dict, *, profile: str) -> list[dict]:
    """Join actual registered Python implementations to frozen admission decisions.

    The coordinator must write admission and prerequisite ID lists after its own policy
    checks. Missing lists produce false decisions, never implicit authorization.
    """
    import inspect

    from scopelens.checks.controls import CONTROLS
    from scopelens.domain.enums import ProfileName
    from scopelens.domain.registry import CheckRegistry

    registry = CheckRegistry.model_validate(plan["registry"])
    frozen = plan.get("capability_execution_plan") or {}
    admitted = set(frozen.get("admitted_control_ids") or ())
    ready = set(frozen.get("prerequisites_satisfied_ids") or ())
    implemented = {control.check_id: control.evaluate for control in CONTROLS}
    result = []
    for entry in registry.supported_for_profile(ProfileName(profile)):
        function = implemented.get(entry.id)
        try:
            source_sha = hashlib.sha256(inspect.getsource(function).encode()).hexdigest()
        except (OSError, TypeError):
            source_sha = "unavailable"
        result.append(
            {
                "control_id": entry.id,
                "runtime_supported": function is not None and source_sha != "unavailable",
                "prerequisites_satisfied": entry.id in ready,
                "authority_admitted": entry.id in admitted,
                "verification_ref": f"implementation:{source_sha}:plan:{canonical_sha256(frozen)}",
            }
        )
    return result


def capability_inventory(
    *, installed_tools: list[dict], executable_control_ids: list[str], qualification: dict
) -> dict:
    """Inventory claims require distinct evidence: installation, execution, qualification."""
    tools = sorted(
        {
            str(t["name"])
            for t in installed_tools
            if t.get("measured_version") and t.get("verification_ref")
        }
    )
    controls = sorted(set(executable_control_ids))
    qualified = sorted(
        f
        for f, result in qualification.get("families", {}).items()
        if result.get("qualified") is True
    )
    return {
        "installed_tools": {"count": len(tools), "names": tools},
        "executable_checks": {"count": len(controls), "control_ids": controls},
        "independently_qualified_families": {"count": len(qualified), "families": qualified},
        "note": "These counts measure different things; none estimates the percentage of all website vulnerabilities detected.",
    }
