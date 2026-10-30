"""Redaction (Build Plan §6.1).

Cookie values, tokens, secrets and PII are replaced with ``[redacted]`` before storage,
before any model call and before any report render.

Two layers, because evidence arrives in two shapes:

* :func:`redact` walks **structured** data and redacts by key name, which is exact.
* :func:`redact_text` scrubs **unstructured** text — an HTTP response body, a header
  block, a tool's stdout — by finding sensitive key/value pairs and credential-shaped
  substrings wherever they appear.

The second layer is not optional. Evidence is mostly text, and a redactor that only
understood dictionaries would store a response body containing an API key verbatim while
reporting ``redaction_state: redacted``. That is worse than not redacting, because it
claims a scrub that did not happen.

A deliberate limitation, stated so it is not mistaken for completeness: this is pattern
matching, not a classifier. It will miss a secret with no recognizable shape under a key
name it does not know. It is a reduction in exposure, not a guarantee.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[redacted]"

#: Key names whose values never survive into storage or a model prompt.
SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|auth|credential|cookie|session|"
    r"private[_-]?key|bearer|signature|otp|pin)",
    re.IGNORECASE,
)

#: ``key: value`` / ``key=value`` pairs in free text, with optional quoting.
#:
#: Only the first four characters of the *value* are consumed for the decision; the whole
#: value is replaced. Deliberately stops at whitespace and common delimiters so it does
#: not swallow the rest of a log line.
_KEY_VALUE_PATTERN = re.compile(
    r"(?P<key>\b[a-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|authorization|"
    r"set-cookie|cookie|session[_-]?id|private[_-]?key|signature|otp|pin)[a-z0-9_.-]*\b)"
    r"(?P<sep>\s*[:=]\s*)"
    r'(?P<quote>["\']?)'
    r"(?P<value>[^\s\"',;}\]]+)"
    r"(?P=quote)",
    re.IGNORECASE,
)

#: Credential shapes, matched **anywhere** in a string rather than anchored to it.
#:
#: Unanchored on purpose: a token inside a response body, a log line or a header block is
#: exactly the case that matters, and an anchored pattern silently skips all of them.
_CREDENTIAL_SHAPES = (
    # Callback nonce URLs are short-lived bearer capabilities too. Proxied target
    # queries contain their percent-encoded form; neither form belongs in reports.
    re.compile(r"(?:/|%2f)callback(?:/|%2f)[A-Za-z0-9_-]{20,128}", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{16,}"),  # OpenAI-style keys
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"),  # GitHub tokens
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),  # bcrypt hash
    re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"),
)

#: Substrings that are structurally sensitive but must survive redaction to stay readable.
#: Currently empty; the hook exists so a future exception is a deliberate line here rather
#: than a loosened pattern.
_NEVER_REDACT: frozenset[str] = frozenset()

_MAX_DEPTH = 12


def contains_credential_shape(text: str) -> bool:
    """Whether any credential-shaped substring appears in ``text``."""
    return any(pattern.search(text) for pattern in _CREDENTIAL_SHAPES)


def looks_sensitive(value: str) -> bool:
    """Whether a standalone value looks like a credential."""
    if value in _NEVER_REDACT:
        return False
    return contains_credential_shape(value)


def redact_text(text: str) -> str:
    """Scrub complete credentials before key/value matching can split them."""
    for pattern in _CREDENTIAL_SHAPES:
        text = pattern.sub(REDACTED, text)
    return _KEY_VALUE_PATTERN.sub(
        lambda m: f"{m.group('key')}{m.group('sep')}{m.group('quote')}{REDACTED}{m.group('quote')}",
        text,
    )


def redact(value: Any, *, key: str | None = None, _depth: int = 0) -> Any:
    """Return a redacted copy of structured ``value``.

    Mappings and sequences are walked; strings are additionally passed through
    :func:`redact_text`, so a secret embedded in a string value is caught even when the
    enclosing key gives no hint.
    """
    if _depth > _MAX_DEPTH:
        return "[redacted: nesting too deep]"

    # Exact presence facts contain no credential material. Never exempt strings,
    # numbers, containers or similarly named keys.
    if key in {"cookie_present", "authorization_present"} and type(value) is bool:
        return value

    if key is not None and SENSITIVE_KEY_PATTERN.search(key):
        return REDACTED

    if isinstance(value, dict):
        return {str(k): redact(v, key=str(k), _depth=_depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple | set):
        return [redact(item, _depth=_depth + 1) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
