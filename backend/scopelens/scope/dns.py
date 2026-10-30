"""The only module permitted to import ``socket``.

Scope registration must know whether a host resolves exclusively to public addresses
(Build Plan §5.1). That requires DNS. Resolving is *validation*, not a target action:
no connection is opened and no HTTP request is made anywhere in M0.

Confining ``socket`` here means the import-boundary test can assert that no other
module in the package is even capable of opening a socket to a target. M1 replaces
this with the broker's re-resolve-and-pin path; the protocol stays the same.
"""

from __future__ import annotations

import socket
from typing import Protocol


class ResolverError(RuntimeError):
    """Raised when a host cannot be resolved at all."""


class Resolver(Protocol):
    def resolve(self, host: str) -> list[str]:
        """Return every address the host resolves to (IPv4 and IPv6)."""
        ...


class SystemResolver:
    """Real DNS via ``getaddrinfo``.

    Returns *all* addresses rather than the first: a host that resolves to one public
    and one private address must be rejected, not accepted on the strength of
    whichever address happened to be returned first.
    """

    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self._timeout = timeout_seconds

    def resolve(self, host: str) -> list[str]:
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self._timeout)
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise ResolverError(f"cannot resolve {host!r}: {exc}") from exc
        finally:
            socket.setdefaulttimeout(previous)

        addresses: list[str] = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise ResolverError(f"cannot resolve {host!r}: no addresses returned")
        return addresses


class StaticResolver:
    """Test/dev resolver backed by an explicit map.

    A host absent from the map raises, so an unlisted host can never be silently
    treated as public.
    """

    def __init__(self, mapping: dict[str, list[str]]) -> None:
        self._mapping = {host.lower(): list(addresses) for host, addresses in mapping.items()}

    def resolve(self, host: str) -> list[str]:
        try:
            return list(self._mapping[host.lower()])
        except KeyError as exc:
            raise ResolverError(f"cannot resolve {host!r}: not in static map") from exc
