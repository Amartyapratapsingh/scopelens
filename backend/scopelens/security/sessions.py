"""Signed session cookies (Build Plan §5.1).

A stateless signed cookie is sufficient for the single seeded operator, and it keeps
M0 free of Redis (which is M1 dispatch infrastructure, not an auth dependency).

The token carries only the operator id and username. It never carries a role, a
scope, or anything a client could tamper with to gain authority — the server
re-reads the operator on every request.
"""

from __future__ import annotations

from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

DEFAULT_SALT = "scopelens.session.v1"


class SessionError(Exception):
    """Raised when a session token is missing, tampered with or expired."""


class SessionSigner:
    def __init__(self, secret: str, *, max_age_seconds: int, salt: str = DEFAULT_SALT) -> None:
        if not secret:
            raise SessionError("a session secret is required; refusing to sign with an empty key")
        self._serializer = URLSafeTimedSerializer(secret_key=secret, salt=salt)
        self._max_age = max_age_seconds

    @property
    def max_age_seconds(self) -> int:
        return self._max_age

    def sign(self, payload: dict[str, Any]) -> str:
        return self._serializer.dumps(payload)

    def verify(self, token: str) -> dict[str, Any]:
        try:
            payload = self._serializer.loads(token, max_age=self._max_age)
        except SignatureExpired as exc:
            raise SessionError("session expired") from exc
        except BadSignature as exc:
            raise SessionError("session token is invalid") from exc

        if not isinstance(payload, dict) or "sub" not in payload:
            raise SessionError("session token is malformed")
        return payload
