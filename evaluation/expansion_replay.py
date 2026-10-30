"""Offline proof replay for the reviewed expanded HTTP/browser input collectors.

Callback, authorization workflow and generated-script summaries receive no automatic
proof credit. This module has no network client, session store or label input.
"""

import hashlib
import json
from dataclasses import dataclass

from evaluation.expansion_bundle import InputBinding, TargetBinding
from scopelens.checks.expanded_active import CONTROL_KINDS, evaluate_expanded
from scopelens.domain.assessment import AssessmentTask, RequestTemplate
from scopelens.domain.identity import IdentityProfile, IdentityRequest, SessionProbe
from scopelens.expansion.authenticated_browser import evaluate_browser_input_identity
from scopelens.expansion.authenticated_inputs import evaluate_input_identity


@dataclass(frozen=True)
class Replay:
    state: str
    reason: str
    evidence_refs: tuple[str, ...] = ()


def verified_payload(artifact: dict) -> dict | None:
    """Validate bytes and intake metadata before interpreting any captured claims."""
    metadata = artifact.get("metadata", {})
    raw = artifact.get("raw_utf8")
    if (
        metadata.get("trusted") is not True
        or metadata.get("truncated") is not False
        or metadata.get("redaction_state") not in {"redacted", "clean"}
        or metadata.get("origin") != "supervisor"
        or not metadata.get("producer_hash")
        or not isinstance(raw, str)
        or hashlib.sha256(raw.encode()).hexdigest() != metadata.get("content_hash")
        or len(raw.encode()) != metadata.get("content_bytes")
    ):
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(value, dict) or value.get("run_id") != metadata.get("run_id"):
        return None
    return value


def replay_input(
    target: TargetBinding, binding: InputBinding, artifacts: dict[str, dict]
) -> Replay:
    kind = CONTROL_KINDS.get(binding.control_id)
    if kind is None:
        return Replay("inconclusive", "unsupported_replay_family")
    browser = kind in {"xss", "html", "dom_xss"}
    source = "expansion_browser" if browser else "expansion"
    producer = "reviewed_expansion_browser_capture" if browser else "reviewed_expansion_capture"
    matches = []
    for ref, artifact in artifacts.items():
        payload = verified_payload(artifact)
        if payload is None or payload.get("kind") != "expanded_active_probe":
            continue
        data = payload.get("data")
        if not isinstance(data, dict) or data.get("task_id") != binding.task_id:
            continue
        if data.get("state") == "blocked":
            continue
        matches.append((ref, artifact, payload, data))
    if len(matches) != 1:
        return Replay("inconclusive", "missing_or_ambiguous_trusted_capture")
    ref, artifact, payload, data = matches[0]
    expected = {
        "control_id": binding.control_id,
        "task_id": binding.task_id,
        "template_id": binding.template_id,
        "plan_id": binding.plan_id,
        "method": binding.method,
        "route": binding.route,
        "role_id": binding.role_id,
        "input_key": binding.input_key,
        "kind": kind,
    }
    if (
        payload.get("source") != source
        or artifact["metadata"].get("producer") != producer
        or any(data.get(key) != value for key, value in expected.items())
        or data.get("reviewed") is not True
    ):
        return Replay("inconclusive", "capture_binding_or_producer_mismatch")
    try:
        if binding.role_id != "anonymous":
            identity = binding.identity
            profile = IdentityProfile(
                id=identity.id,
                role=identity.role,
                expires_at=identity.expires_at,
                probe=SessionProbe(
                    request=IdentityRequest(method=identity.method, url=identity.url),
                    identity_pointer=identity.identity_pointer,
                    expected_identity=identity.expected_identity,
                ),
            )
            task = AssessmentTask(
                id=binding.task_id,
                template_id=binding.template_id,
                control_id=binding.control_id,
                input_key=binding.input_key,
                state="ready",
                reason="frozen evaluator binding",
            )
            template = RequestTemplate(
                id=binding.template_id,
                origin=target.origin,
                path=binding.route,
                route_template=binding.route,
                method=binding.method,
                role_id=binding.role_id,
            )
            args = (profile, task, template, binding.plan_id)
            valid, _ = (
                evaluate_browser_input_identity(
                    *args, data.get("browser_identity_proofs"), data.get("captures")
                )
                if browser
                else evaluate_input_identity(*args, data.get("identity_proof"))
            )
            if not valid:
                return Replay("inconclusive", "identity_proof_replay_failed")
        state, _ = evaluate_expanded(kind, data.get("captures", []), error=data.get("error"))
    except (ValueError, TypeError, KeyError, AttributeError):
        return Replay("inconclusive", "malformed_proof_capture")
    return Replay(
        state, "registered_input_proof_replayed", (ref,) if state in {"confirmed", "pass"} else ()
    )
