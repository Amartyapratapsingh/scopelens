"""Session rotation and revocation against explicit policy, with replayable proof fields."""

from __future__ import annotations

import hashlib
import math
import re
import time
from copy import deepcopy

import httpx

from scopelens.domain.identity import IdentityProfile, RoleComparison, SessionPolicy
from scopelens.identities.assessment import Capture
from scopelens.identities.probe import probe_binding, probe_binding_matches, response_probe_value
from scopelens.identities.sessions import (
    IdentitySessions,
    SessionUnavailable,
    response_value,
    same_value,
)

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def clone_cookies(cookies: httpx.Cookies) -> httpx.Cookies:
    result = httpx.Cookies()
    for cookie in cookies.jar:
        result.jar.set_cookie(deepcopy(cookie))
    return result


def evaluate_session_proof(
    policy: SessionPolicy, profile: IdentityProfile, record: dict
) -> tuple[str, str]:
    """Recompute only from fixed-collector records accepted by trusted intake."""
    probe = profile.probe
    if (
        probe is None
        or not probe_binding_matches(probe, record.get("probe_binding"))
        or profile.id != policy.identity_id
        or record.get("identity_id") != policy.identity_id
    ):
        return "inconclusive", "identity/probe binding absent"
    if (
        record.get("initial_probe_status") != 200
        or record.get("initial_identity") != probe.expected_identity
    ):
        return "inconclusive", "initial session was not independently authenticated"
    kind = record.get("check")
    old, new = record.get("old_cookie_hash"), record.get("new_cookie_hash")
    replayed = record.get("replayed_cookie_hash")
    if any(not isinstance(value, str) or not _SHA256_HEX.fullmatch(value) for value in (old, new)):
        return "inconclusive", "valid cookie fingerprints absent"
    if "replayed_cookie_hash" in record and (
        not isinstance(replayed, str) or not _SHA256_HEX.fullmatch(replayed)
    ):
        return "inconclusive", "valid replay fingerprint absent"
    if kind == "rotation":
        if (
            not policy.login_rotates
            or not profile.login
            or record.get("login_status") not in profile.login.success_statuses
            or record.get("new_probe_status") != 200
            or record.get("new_identity") != probe.expected_identity
        ):
            return "inconclusive", "new login/session proof absent"
        return (
            ("confirmed", "declared rotation absent after verified login")
            if old == new
            else ("pass", "cookie rotation observed after verified login")
        )
    if (
        not profile.login
        or record.get("login_status") not in profile.login.success_statuses
        or record.get("new_probe_status") != 200
        or record.get("new_identity") != probe.expected_identity
    ):
        return "inconclusive", "replacement session could not be independently verified"
    if kind == "expiry":
        return _evaluate_expiry(policy, profile, record)
    if kind not in {"old_session", "logout"}:
        return "inconclusive", "unknown lifecycle proof"
    if kind == "old_session" and not policy.old_session_revoked_on_login:
        return "inconclusive", "old-session revocation was not declared"
    if kind == "logout" and (
        not policy.logout
        or not policy.logout_revokes
        or record.get("logout_status") not in {200, 204}
    ):
        return "inconclusive", "declared logout did not complete"
    expected_hash = (
        record.get("old_cookie_hash") if kind == "old_session" else record.get("new_cookie_hash")
    )
    if not replayed or replayed != expected_hash:
        return "inconclusive", "session replay fingerprint absent or wrong session"
    if (
        record.get("replay_probe_status") == 200
        and record.get("replay_identity") == probe.expected_identity
    ):
        return "confirmed", "old cookie still authenticates after declared revocation"
    if (
        probe.unauthenticated_pointer
        and record.get("replay_denial_observed") is True
        and record.get("replay_probe_status") in probe.unauthenticated_statuses
        and record.get("replay_denial") == probe.unauthenticated_value
    ):
        return "pass", "replayed cookie received the declared unauthenticated response"
    return "inconclusive", "replay did not establish authenticated access or declared denial"


def _evaluate_expiry(policy, profile, record):
    interval = policy.expiry_after_seconds
    declared = record.get("expiry_after_seconds")
    if interval is None or type(declared) is not int or declared != interval:
        return "inconclusive", "matching server expiry interval was not declared"

    def elapsed(value):
        if type(value) not in {int, float}:
            return False
        try:
            return math.isfinite(value) and value >= interval
        except OverflowError:
            return False

    waited = record.get("expiry_waited_seconds")
    replays = record.get("expiry_replays")
    if (
        record.get("replayed_cookie_hash") != record["new_cookie_hash"]
        or not elapsed(waited)
        or not isinstance(replays, list)
        or len(replays) != 2
    ):
        return "inconclusive", "complete measured expiry wait and two replays required"
    previous = waited
    probe = profile.probe
    authenticated = []
    denied = []
    for replay in replays:
        if not isinstance(replay, dict):
            return "inconclusive", "expiry replay capture absent"
        measured = replay.get("elapsed_seconds")
        if not elapsed(measured) or measured < previous:
            return "inconclusive", "expiry replay fingerprint or measured timing invalid"
        previous = measured
        authenticated.append(
            replay.get("replay_probe_status") == 200
            and replay.get("replay_identity") == probe.expected_identity
        )
        denied.append(
            bool(probe.unauthenticated_pointer)
            and replay.get("replay_denial_observed") is True
            and replay.get("replay_probe_status") in probe.unauthenticated_statuses
            and same_value(replay.get("replay_denial"), probe.unauthenticated_value)
        )
    if all(authenticated):
        return "confirmed", "session still authenticates twice after declared server expiry"
    if all(denied):
        return "pass", "expired session twice received the declared unauthenticated response"
    return "inconclusive", "expiry replays did not repeat authenticated access or declared denial"


def _wait_for_expiry(started, interval, cancelled):
    """Wait on elapsed time, checking cancellation throughout the bounded interval."""
    while True:
        if cancelled():
            raise SessionUnavailable("assessment cancelled during expiry wait")
        elapsed = time.monotonic() - started
        if elapsed >= interval:
            return elapsed
        time.sleep(min(0.1, interval - elapsed))


def check_session_policy(
    policy: SessionPolicy, sessions: IdentitySessions, capture: Capture
) -> tuple[RoleComparison, ...]:
    """No cookie values enter evidence; exact session probe values and hashes do.

    Explicit login/logout mutations still require caller broker grants. Cancellation may
    interrupt them; there is no automatic replay or bypass of revoked egress.
    """
    results = []
    identity = policy.identity_id
    profile = sessions.profiles[identity]
    if profile.anonymous or profile.login is None or profile.probe is None:
        return (
            RoleComparison(
                rule_id=f"session:{identity}",
                object_id="session",
                identity_id=identity,
                family="session",
                state="blocked",
                reason="declared login recipe required",
            ),
        )
    probe = profile.probe

    def hash_cookie(value):
        return hashlib.sha256(value.encode()).hexdigest() if value else None

    def probe_fields(prefix):
        response = sessions.request(identity, probe.request)
        actual = response_probe_value(response, probe)
        denied = (
            response_value(response, probe.unauthenticated_pointer)
            if probe.unauthenticated_pointer
            else None
        )
        return {
            f"{prefix}_probe_status": response.status_code,
            f"{prefix}_identity": actual if actual == probe.expected_identity else None,
            f"{prefix}_denial": denied if same_value(denied, probe.unauthenticated_value) else None,
            f"{prefix}_denial_observed": bool(
                probe.unauthenticated_pointer and same_value(denied, probe.unauthenticated_value)
            ),
        }

    def record(check, fields):
        item = {
            "kind": "session_policy",
            "identity_id": identity,
            "check": check,
            "probe_binding": probe_binding(probe),
            **fields,
        }
        state, reason = evaluate_session_proof(policy, profile, item)
        ref = capture(item)
        results.append(
            RoleComparison(
                rule_id=f"session:{identity}:{check}",
                object_id="session",
                identity_id=identity,
                family="session",
                state=state if ref else "blocked",
                reason=reason if ref else "trusted evidence unavailable",
                evidence_refs=(ref,) if ref else (),
            )
        )

    try:
        if not sessions.verify(identity):
            raise SessionUnavailable("initial session verification failed")
        initial = probe_fields("initial")
        client = sessions.client(identity)
        old = clone_cookies(client.cookies)
        old_value = client.cookies.get(policy.cookie_name)
        if not old_value:
            raise SessionUnavailable("declared session cookie absent")
        login = sessions.request(identity, profile.login.request)
        if login.status_code not in profile.login.success_statuses or not sessions.verify(
            identity, allow_login=False
        ):
            raise SessionUnavailable("fresh login could not be verified")
        new_probe = probe_fields("new")
        fresh = clone_cookies(client.cookies)
        new_value = client.cookies.get(policy.cookie_name)
        if not new_value:
            raise SessionUnavailable("fresh session cookie absent")
        fields = {
            **initial,
            **new_probe,
            "old_cookie_hash": hash_cookie(old_value),
            "new_cookie_hash": hash_cookie(new_value),
            "login_status": login.status_code,
        }
        if policy.login_rotates:
            record("rotation", fields)
        if policy.old_session_revoked_on_login:
            client.cookies = clone_cookies(old)
            try:
                replay = probe_fields("replay")
            finally:
                client.cookies = clone_cookies(fresh)
            record(
                "old_session", {**fields, **replay, "replayed_cookie_hash": hash_cookie(old_value)}
            )
        if policy.logout and policy.logout_revokes:
            response = sessions.request(identity, policy.logout)
            client.cookies = clone_cookies(fresh)
            replay = probe_fields("replay")
            record(
                "logout",
                {
                    **fields,
                    **replay,
                    "logout_status": response.status_code,
                    "replayed_cookie_hash": hash_cookie(new_value),
                },
            )
            client.cookies.clear()
        if policy.expiry_after_seconds is not None:
            # Logout or earlier replays must not supply an already revoked expiry subject.
            expiry_login = sessions.request(identity, profile.login.request)
            if (
                expiry_login.status_code not in profile.login.success_statuses
                or not sessions.verify(identity, allow_login=False)
            ):
                raise SessionUnavailable("expiry login could not be verified")
            expiry_new_probe = probe_fields("new")
            expiry_cookies = clone_cookies(client.cookies)
            expiry_value = client.cookies.get(policy.cookie_name)
            if not expiry_value:
                raise SessionUnavailable("expiry session cookie absent")
            for cookie in expiry_cookies.jar:
                if cookie.name == policy.cookie_name:
                    # A client-side Max-Age must not suppress the server-side replay.
                    cookie.expires = None
                    cookie.discard = True
            started = time.monotonic()
            waited = _wait_for_expiry(started, policy.expiry_after_seconds, sessions.cancelled)
            replays = []
            try:
                for _ in range(2):
                    # Cookie deletion/renewal in the first response cannot alter the replay subject.
                    client.cookies = clone_cookies(expiry_cookies)
                    measured = time.monotonic() - started
                    replays.append(
                        {
                            **probe_fields("replay"),
                            "elapsed_seconds": measured,
                        }
                    )
            finally:
                client.cookies.clear()
            record(
                "expiry",
                {
                    **fields,
                    **expiry_new_probe,
                    "new_cookie_hash": hash_cookie(expiry_value),
                    "replayed_cookie_hash": hash_cookie(expiry_value),
                    "login_status": expiry_login.status_code,
                    "expiry_after_seconds": policy.expiry_after_seconds,
                    "expiry_waited_seconds": waited,
                    "expiry_replays": replays,
                },
            )
    except (SessionUnavailable, httpx.HTTPError, PermissionError, ValueError):
        results.append(
            RoleComparison(
                rule_id=f"session:{identity}:workflow",
                object_id="session",
                identity_id=identity,
                family="session",
                state="blocked",
                reason="session lifecycle workflow could not complete",
            )
        )
    return tuple(results)
