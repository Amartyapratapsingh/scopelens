"""Domain error base.

All operator-fixable input problems derive from :class:`DomainError`, and the API
translates exactly that type into a 400. A bare ``ValueError`` raised by a bug keeps
its 500, so an internal fault is never disguised as a client mistake.
"""

from __future__ import annotations


class DomainError(ValueError):
    """An input or configuration problem the operator can act on."""
