"""Destination validation — the scope boundary's decision function (Build Plan §5.1, §5.3).

Pure functions over already-resolved addresses. No I/O happens here, so the rules are
exhaustively testable without a network.

In M0 this runs once at scope registration. The same function is the per-connection
check M1's broker must call for every request, redirect and browser subrequest — that
reuse is deliberate, so the registration rule and the enforcement rule cannot drift
apart.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

from scopelens.domain.enums import AuthorityDomain
from scopelens.domain.errors import DomainError
from scopelens.domain.lab import LabBinding, LabBindingError, LabServiceAllowlist
from scopelens.domain.scope import default_port, normalize_host

# Cloud metadata endpoints. 169.254.169.254 is link-local and would already be
# rejected, but naming them makes the intent explicit and survives a future refactor
# of the address rules.
METADATA_ADDRESSES = frozenset(
    {
        "169.254.169.254",  # AWS / Azure / GCP IMDS
        "169.254.170.2",  # ECS task metadata
        "fd00:ec2::254",  # AWS IMDS over IPv6
        "100.100.100.200",  # Alibaba Cloud
    }
)

# Characters that make host parsing ambiguous. A host containing these is rejected
# outright rather than normalised, because "normalise then check" is where
# authority-confusion bugs live.
_FORBIDDEN_HOST_CHARS = frozenset(" \t\r\n/@\\?#[]{}|\"'<>^`")


class ScopeViolation(DomainError):
    """Raised when a destination is outside the authorized scope."""


def address_rejection_reason(address: str) -> str | None:
    """Return why an address is unusable, or ``None`` if it is a public destination."""
    if address in METADATA_ADDRESSES:
        return "cloud metadata endpoint"

    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return f"not a valid IP address ({address!r})"

    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) must be judged as its IPv4 self,
    # otherwise the loopback/private checks are bypassed by the v6 wrapper.
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return address_rejection_reason(str(parsed.ipv4_mapped))

    if parsed.is_loopback:
        return "loopback address"
    if parsed.is_link_local:
        return "link-local address"
    if parsed.is_private:
        return "private address"
    if parsed.is_multicast:
        return "multicast address"
    if parsed.is_unspecified:
        return "unspecified address"
    if parsed.is_reserved:
        return "reserved address"
    if not parsed.is_global:
        return "not globally routable"
    return None


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def validate_host_syntax(host: str) -> str:
    """Reject hosts that cannot be safely interpreted as a single authority."""
    if not host:
        raise ScopeViolation("host is empty")
    if offending := sorted(set(host) & _FORBIDDEN_HOST_CHARS):
        raise ScopeViolation(f"host contains forbidden character(s): {offending}")
    if host != normalize_host(host):
        raise ScopeViolation(f"host must already be normalized; got {host!r}")
    return host


@dataclass(frozen=True)
class DestinationDecision:
    """The outcome of validating one destination. Kept for the audit trail."""

    allowed: bool
    authority_domain: AuthorityDomain
    host: str
    port: int
    addresses: tuple[str, ...]
    reason: str
    lab_service: str | None = None

    def require_allowed(self) -> DestinationDecision:
        if not self.allowed:
            raise ScopeViolation(self.reason)
        return self


def validate_destination(
    *,
    host: str,
    port: int,
    resolved_addresses: list[str],
    authority_domain: AuthorityDomain,
    lab_binding: LabBinding | None = None,
    lab_allowlist: LabServiceAllowlist | None = None,
) -> DestinationDecision:
    """Decide whether a destination is inside the authorized scope.

    Production and lab are separate authority domains and the decision never mixes
    them. There is no code path in which a production destination becomes acceptable
    because it happens to look like a lab one.
    """
    validate_host_syntax(host)

    if authority_domain is AuthorityDomain.LAB:
        return _validate_lab(host, port, resolved_addresses, lab_binding, lab_allowlist)
    return _validate_production(host, port, resolved_addresses)


def _validate_production(
    host: str, port: int, resolved_addresses: list[str]
) -> DestinationDecision:
    def reject(reason: str) -> DestinationDecision:
        return DestinationDecision(
            allowed=False,
            authority_domain=AuthorityDomain.PRODUCTION,
            host=host,
            port=port,
            addresses=tuple(resolved_addresses),
            reason=reason,
        )

    if is_ip_literal(host):
        # An IP literal is not an ownership claim. Spec §6/§12 require explicit
        # authorization rather than a typed address.
        return reject(
            f"IP literals are not accepted in the production profile ({host}); "
            "register a hostname with an explicit authorization record"
        )

    if not resolved_addresses:
        return reject(f"{host} did not resolve to any address")

    for address in resolved_addresses:
        if reason := address_rejection_reason(address):
            # Every address must be public. One private answer is enough to reject.
            return reject(f"{host} resolves to {address}: {reason}")

    return DestinationDecision(
        allowed=True,
        authority_domain=AuthorityDomain.PRODUCTION,
        host=host,
        port=port,
        addresses=tuple(resolved_addresses),
        reason="public destination",
    )


def _validate_lab(
    host: str,
    port: int,
    resolved_addresses: list[str],
    lab_binding: LabBinding | None,
    lab_allowlist: LabServiceAllowlist | None,
) -> DestinationDecision:
    def reject(reason: str) -> DestinationDecision:
        return DestinationDecision(
            allowed=False,
            authority_domain=AuthorityDomain.LAB,
            host=host,
            port=port,
            addresses=tuple(resolved_addresses),
            reason=reason,
            lab_service=lab_binding.service if lab_binding else None,
        )

    if lab_binding is None:
        return reject("a lab destination requires an operator-registered lab binding")
    if lab_allowlist is None:
        return reject("no lab service allowlist is configured; failing closed")

    try:
        service = lab_allowlist.validate_binding(lab_binding)
    except LabBindingError as exc:
        # Re-surfaced as a decision rather than propagated: the caller wants a verdict
        # it can record, not an exception to unwind.
        return reject(str(exc))

    # The scope's host must be the approved address itself. Anything else means the
    # binding and the destination disagree, which is a configuration error worth
    # refusing rather than resolving.
    if normalize_host(host) != lab_binding.address:
        return reject(
            f"lab scope host {host!r} does not match its approved binding address "
            f"{lab_binding.address!r}"
        )
    if port != lab_binding.port:
        return reject(
            f"lab scope port {port} does not match its approved binding port {lab_binding.port}"
        )

    if resolved_addresses:
        unexpected = [a for a in resolved_addresses if a not in service.addresses]
        if unexpected:
            return reject(
                f"{host} resolved to address(es) outside the approved set for "
                f"{service.id!r}: {unexpected}"
            )

    return DestinationDecision(
        allowed=True,
        authority_domain=AuthorityDomain.LAB,
        host=host,
        port=port,
        addresses=tuple(resolved_addresses) or (lab_binding.address,),
        reason=f"approved lab service binding: {lab_binding.describe()}",
        lab_service=service.id,
    )


def origin_of(scheme: str, host: str, port: int | None) -> str:
    """``scheme://host[:port]``, omitting a default port."""
    resolved_port = port if port is not None else default_port(scheme)
    if resolved_port == default_port(scheme):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{resolved_port}"


AuthorityLabel = Literal["production", "lab"]
