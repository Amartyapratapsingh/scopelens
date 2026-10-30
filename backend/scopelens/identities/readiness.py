"""Read-only identity observations, independent of access or lifecycle controls."""

from __future__ import annotations

from datetime import UTC, datetime

import httpx

from scopelens.domain.capabilities import canonical_sha256
from scopelens.identities.probe import probe_binding, response_probe_value
from scopelens.identities.sessions import (
    IdentitySessions,
    IdentityTransportError,
    SessionUnavailable,
    same_value,
    transport_category,
    transport_phase,
)

READINESS_VERSION = "identity-readiness-v1"


def identity_digest(value) -> str:
    return "sha256:" + canonical_sha256(value)


def evaluate_identity_readiness(profile, record, *, configuration_binding, now=None):
    """Recompute a readiness observation only after trusted evidence admission.

    This establishes an identity observation, never a control pass or vulnerability.
    Missing transport/probe facts cannot be repaired by the worker's state or reason.
    """
    probe = profile.probe
    if (
        profile.anonymous
        or probe is None
        or probe.request.method not in {"GET", "HEAD"}
        or probe.request.json_body
        or probe.request.secret_fields
        or not (profile.supplied_headers or probe.request.secret_headers)
        or not isinstance(record, dict)
    ):
        return False
    try:
        observed_at = datetime.fromisoformat(record["observed_at"])
        return (
            record.get("version") == READINESS_VERSION
            and record.get("kind") == "identity_readiness"
            and record.get("proof_type") == "readiness"
            and record.get("proof_id") == profile.id
            and record.get("identity_id") == profile.id
            and record.get("configuration_binding") == configuration_binding
            and record.get("probe_binding") == probe_binding(probe)
            and record.get("method") == probe.request.method
            and record.get("url") == probe.request.url
            and record.get("status") == 200
            and record.get("observed_digest") == identity_digest(probe.expected_identity)
            and observed_at.tzinfo is not None
            and (now is None or observed_at <= now)
            and (profile.expires_at is None or observed_at < profile.expires_at)
        )
    except (KeyError, TypeError, ValueError):
        return False


def collect_identity_readiness(
    configuration, secret_resolver, client_factory, emit, *, cancelled, configuration_binding=None
):
    """At most one admitted request per identity, at most twenty identities.

    No login, redirects, mutations or anonymous fallback. Credential references are
    resolved immediately before the probe through the existing assessment control.
    Response bodies remain bounded by IdentitySessions and only a digest is emitted.
    """
    binding = configuration_binding or canonical_sha256(configuration.model_dump(mode="json"))
    current_profile = None

    def available():
        if cancelled():
            raise SessionUnavailable("identity_readiness_cancelled")
        if current_profile.expires_at and current_profile.expires_at <= datetime.now(UTC):
            raise SessionUnavailable("identity_supplied_session_expired")

    def secret(reference):
        available()
        value = secret_resolver(reference)
        available()
        if not value.get_secret_value():
            raise PermissionError("identity_credentials_unavailable")
        return value

    with IdentitySessions(
        configuration.identities, secret, client_factory, cancelled=cancelled
    ) as sessions:
        for profile in configuration.identities:
            if profile.anonymous:
                continue
            current_profile = profile
            probe = profile.probe
            # Authenticated profiles require this contract at configuration admission.
            assert probe is not None
            record = {
                "version": READINESS_VERSION,
                "kind": "identity_readiness",
                "proof_type": "readiness",
                "proof_id": profile.id,
                "identity_id": profile.id,
                "configuration_binding": binding,
                "probe_binding": probe_binding(probe),
                "method": probe.request.method,
                "url": probe.request.url,
                "status": None,
                "observed_digest": None,
                "state": "blocked",
                "reason": "identity_probe_not_observed",
            }
            try:
                available()
                if (
                    probe.request.method not in {"GET", "HEAD"}
                    or probe.request.json_body
                    or probe.request.secret_fields
                ):
                    record["reason"] = "identity_readiness_requires_read_only_probe"
                elif not profile.supplied_headers and not probe.request.secret_headers:
                    record["reason"] = "identity_supplied_credentials_required"
                else:
                    response = sessions.request(profile.id, probe.request)
                    available()
                    record["status"] = response.status_code
                    actual = response_probe_value(response, probe)
                    if response.status_code == 200 and same_value(actual, probe.expected_identity):
                        record.update(
                            state="verified",
                            reason="identity_probe_verified",
                            observed_digest=identity_digest(actual),
                        )
                    elif response.status_code in {401, 403}:
                        record["reason"] = "identity_probe_unauthenticated"
                    elif 300 <= response.status_code < 400:
                        record["reason"] = "identity_probe_redirect_not_followed"
                    else:
                        record["reason"] = "identity_probe_invalid_or_mismatched"
            except PermissionError:
                record["reason"] = "identity_credentials_unavailable_or_expired"
            except SessionUnavailable as exc:
                record["reason"] = (
                    str(exc)
                    if str(exc)
                    in {"identity_readiness_cancelled", "identity_supplied_session_expired"}
                    else "identity_probe_transport_or_response_unavailable"
                )
            except httpx.HTTPError as exc:
                record["reason"] = "identity_probe_transport_unavailable"
                # Fixed categories explain failures without storing exception messages,
                # which may contain credentials, response data or request headers.
                record["transport_error"] = transport_category(exc)
                record["transport_phase"] = transport_phase(exc)
                if isinstance(exc, IdentityTransportError):
                    record["response_status"] = exc.response_status
            except (OSError, KeyError, ValueError):
                record["reason"] = "identity_probe_or_credentials_unavailable"
            record["observed_at"] = datetime.now(UTC).isoformat()
            emit("identity_observation", record)
