"""The policy broker's decision function (Build Plan §5.3).

Every target request, redirect and browser subrequest is decided here. The proxy has no
opinion of its own: it asks this module and obeys.

**This calls the same `scope/validator.py::validate_destination` that M0 used at scope
registration.** That reuse is deliberate and load-bearing — if the registration rule and
the enforcement rule were separate implementations they would drift, and the drift would
be invisible until something got through.

Order of checks matters. Cheap, unambiguous refusals happen first so that a revoked or
unauthorized request never reaches DNS, let alone the network:

1. is there a scan behind this egress token, and is it revoked?
2. is the scan cancelled?
3. does a live coordinator lease exist?
4. is the request inside the frozen scope (port, method, path)?
5. does the host still resolve to the pinned address set, all of which must be allowed?
6. is there budget left?

Any failure denies. There is no path where an error inside a check becomes an allow
(§5.3: "Fail closed: if enforcement can't be maintained, deny").
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.domain.budget import BudgetExceeded, BudgetUsage
from scopelens.domain.enums import AuthorityDomain
from scopelens.domain.lab import LabBinding, load_lab_services
from scopelens.domain.scope import ScopeVersion
from scopelens.execution import leases
from scopelens.persistence.models import ScanRow, ScopeVersionRow
from scopelens.persistence.repositories import scope_row_to_domain
from scopelens.scope.dns import Resolver, ResolverError
from scopelens.scope.paths import canonical_path, path_interpretations
from scopelens.scope.validator import ScopeViolation, validate_destination

#: Audit action written for every decision against a known scan. The coordinator counts
#: the "allowed" rows to establish how many requests were actually admitted, which is why
#: this constant is shared rather than duplicated as a string literal.
BROKER_ADMIT_ACTION = "broker.admit"

#: HTTP status the proxy returns on a denial. 403 rather than 502: the request was
#: understood and refused, which is materially different from an upstream failure.
DENY_STATUS = 403


class DenialReason(enum.StrEnum):
    """Why a request was refused. Recorded verbatim so a denial is auditable."""

    UNKNOWN_TOKEN = "unknown_egress_token"
    REVOKED_TOKEN = "revoked_egress_token"
    CANCELLED = "scan_cancelled"
    NO_LIVE_LEASE = "no_live_coordinator_lease"
    UNKNOWN_SCAN = "unknown_scan"
    PORT_NOT_ALLOWED = "port_not_allowed"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    PATH_NOT_ALLOWED = "path_outside_allowed_prefixes"
    PATH_EXCLUDED = "path_explicitly_excluded"
    HOST_NOT_IN_SCOPE = "host_not_in_scope"
    DESTINATION_REFUSED = "destination_refused"
    ADDRESS_REPINNED = "resolved_addresses_changed"
    RESOLUTION_FAILED = "resolution_failed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    INTERNAL_ERROR = "broker_internal_error"


@dataclass(frozen=True)
class BrokerRequest:
    """One request the proxy wants judged."""

    method: str
    scheme: str
    host: str
    port: int
    path: str
    egress_token: str
    probe_task: str | None = None


@dataclass(frozen=True)
class BrokerDecision:
    allowed: bool
    reason: str
    addresses: tuple[str, ...] = ()
    detail: str = ""
    denial: DenialReason | None = None
    scope_version_id: str | None = None
    #: Present only for a scan the token resolved to. An unknown token has no scan to
    #: attribute a decision to, which is why no audit row is written for one.
    scan_id: str | None = None
    extra: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def deny(reason: DenialReason, detail: str) -> BrokerDecision:
        return BrokerDecision(allowed=False, reason=reason.value, detail=detail, denial=reason)

    @staticmethod
    def allow(
        addresses: tuple[str, ...],
        scope_version_id: str,
        detail: str = "",
        scan_id: str | None = None,
    ) -> BrokerDecision:
        return BrokerDecision(
            allowed=True,
            reason="allowed",
            addresses=addresses,
            detail=detail,
            scope_version_id=scope_version_id,
            scan_id=scan_id,
        )


# --- Egress tokens -----------------------------------------------------------------


def hash_egress_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_egress_token(session: Session, *, scan: ScanRow) -> str:
    """Mint the scan's egress capability and return the plaintext once.

    Only the hash is stored. The token is bound to the scan's *current* cancel epoch, so
    a later cancellation invalidates it without needing to reach the worker holding it.
    """
    token = secrets.token_urlsafe(32)
    scan.egress_token_hash = hash_egress_token(token)
    scan.egress_token_epoch = scan.cancel_epoch
    session.flush()
    return token


def revoke_egress(session: Session, *, scan: ScanRow) -> int:
    """Invalidate every token issued under the current epoch. Returns the new epoch.

    Bumping the epoch is the whole mechanism. The stored hash is deliberately left in
    place: clearing it would make a revoked token indistinguishable from one that was
    never issued, and the difference matters — "this scan's capability was withdrawn" is
    an auditable event, whereas "unknown token" is noise.

    Nothing is weakened by keeping it. The value is a SHA-256 of 32 random bytes, and the
    epoch comparison is what denies, so a revoked token cannot be revived by a concurrent
    write the way a re-settable flag could.
    """
    scan.cancel_epoch = scan.cancel_epoch + 1
    session.flush()
    return scan.cancel_epoch


def scan_for_token(session: Session, token: str) -> ScanRow | None:
    return session.scalar(
        select(ScanRow).where(ScanRow.egress_token_hash == hash_egress_token(token))
    )


# --- Decision ----------------------------------------------------------------------


def authorize(
    session: Session,
    *,
    settings: Settings,
    request: BrokerRequest,
    resolver: Resolver,
    now: datetime | None = None,
) -> BrokerDecision:
    """Decide one request, and record the decision.

    Never raises for a denial; raises only on a bug this wrapper has failed to convert
    into one. Every decision against a *known* scan is appended to the audit trail — the
    coordinator reads those rows back to establish how many requests were actually
    admitted, so this is a durable record and not merely a log line.
    """
    now = now or datetime.now(UTC)

    scan = None
    try:
        scan = scan_for_token(session, request.egress_token)
        decision = (
            _authorize_known_scan(session, settings, request, resolver, now, scan)
            if scan is not None
            else BrokerDecision.deny(
                DenialReason.UNKNOWN_TOKEN, "no scan matches this egress token"
            )
        )
    except ScopeViolation as exc:
        decision = BrokerDecision.deny(DenialReason.DESTINATION_REFUSED, str(exc))
    except BudgetExceeded as exc:
        decision = BrokerDecision.deny(DenialReason.BUDGET_EXHAUSTED, str(exc))
    except ResolverError as exc:
        decision = BrokerDecision.deny(DenialReason.RESOLUTION_FAILED, str(exc))
    except Exception as exc:  # noqa: BLE001
        # Fail closed. An unexpected error inside the broker must deny, never allow.
        decision = BrokerDecision.deny(
            DenialReason.INTERNAL_ERROR, f"{exc.__class__.__name__}: {exc}"
        )

    if scan is not None:
        decision = dataclasses.replace(decision, scan_id=str(scan.id))
    _record_decision(session, request, decision)
    return decision


def _record_decision(session: Session, request: BrokerRequest, decision: BrokerDecision) -> None:
    """Append the decision to the audit trail.

    Only for a scan the token resolved to. An unknown token has no scan to attribute to,
    and writing a row per stray request would let anything on the control network fill the
    audit table.
    """
    if decision.scan_id is None:
        return

    from scopelens.persistence.repositories import record_audit

    record_audit(
        session,
        actor="broker",
        action=BROKER_ADMIT_ACTION,
        subject_type="scan",
        subject_id=decision.scan_id,
        outcome="allowed" if decision.allowed else "denied",
        detail={
            "method": request.method,
            "host": request.host,
            "port": request.port,
            "path": request.path,
            "reason": decision.reason,
        },
    )


def _authorize_known_scan(
    session: Session,
    settings: Settings,
    request: BrokerRequest,
    resolver: Resolver,
    now: datetime,
    scan: ScanRow,
) -> BrokerDecision:
    # Revocation first: a cancelled scan must not reach DNS or the network at all.
    if scan.egress_token_epoch != scan.cancel_epoch:
        return BrokerDecision.deny(
            DenialReason.REVOKED_TOKEN,
            f"egress capability was issued under epoch {scan.egress_token_epoch} and the "
            f"scan is now at epoch {scan.cancel_epoch}",
        )
    if scan.cancel_requested_at is not None:
        return BrokerDecision.deny(
            DenialReason.CANCELLED,
            f"scan was cancelled at {scan.cancel_requested_at.isoformat()}",
        )

    if not leases.lease_is_live(session, scan.id, now=now):
        return BrokerDecision.deny(
            DenialReason.NO_LIVE_LEASE,
            "no live coordinator lease; egress is admitted only while a coordinator holds the scan",
        )

    scope_row = session.get(ScopeVersionRow, scan.scope_version_id)
    if scope_row is None:
        return BrokerDecision.deny(DenialReason.UNKNOWN_SCAN, "scan has no scope version")
    primary_scope_row = scope_row
    scope = scope_row_to_domain(scope_row)
    if request.host != scope.host or (
        request.port != scope.port and not _transport_probe(scope, request)
    ):
        related = _related_scope(session, scan, scope, request)
        if related is not None:
            scope_row, scope = related
    if scope.is_expired(now):
        return BrokerDecision.deny(DenialReason.DESTINATION_REFUSED, "scope authorization expired")

    scope_decision = _check_scope_membership(scope, request)
    if scope_decision is not None:
        return scope_decision

    destination = _check_destination(session, settings, scan, scope, request, resolver)
    if isinstance(destination, BrokerDecision):
        return destination

    if _transport_probe(scope, request):
        # Lock/re-read so simultaneous requests cannot both spend the single probe.
        session.refresh(scan, with_for_update=True)
        if scan.transport_probe_used:
            return BrokerDecision.deny(
                DenialReason.DESTINATION_REFUSED, "transport-only probe already used"
            )
    from scopelens.execution.ledger import budget_limits_for

    limits = budget_limits_for(primary_scope_row, settings)
    session.refresh(scan, with_for_update=True)
    page_keys = list((scan.assessment_plan or {}).get("page_request_keys", []))
    page_key = hashlib.sha256(
        (request.scheme + request.host + str(request.port) + request.path).encode()
    ).hexdigest()
    probe_usage = dict((scan.assessment_plan or {}).get("reviewed_probe_requests", {}))
    if request.probe_task is not None:
        from scopelens.broker.probe_tasks import reviewed_request_limit

        task_limit = reviewed_request_limit(
            scan, scope_row_to_domain(primary_scope_row), settings, request
        )
        used = probe_usage.get(request.probe_task, 0)
        if used >= task_limit:
            raise BudgetExceeded("reviewed probe task request cap reached")
        probe_usage[request.probe_task] = used + 1
    if request.method == "GET" and request.probe_task is None and page_key not in page_keys:
        if len(page_keys) >= limits.max_pages:
            raise BudgetExceeded("shared page cap reached")
        page_keys.append(page_key)
    _reserve_budget(session, scan, settings)
    if _transport_probe(scope, request):
        scan.transport_probe_used = True
        session.flush()

    # The scan lock acquired by budget reservation serializes this schedule across callers.
    plan = dict(scan.assessment_plan or {})
    plan["page_request_keys"] = page_keys
    if request.probe_task is not None:
        plan["reviewed_probe_requests"] = probe_usage
    due = datetime.fromisoformat(plan["next_request_at"]) if plan.get("next_request_at") else now
    due = max(due, now)
    plan["next_request_at"] = (due + timedelta(seconds=1 / limits.requests_per_second)).isoformat()
    scan.assessment_plan = plan
    return dataclasses.replace(
        BrokerDecision.allow(
            addresses=destination,
            scope_version_id=str(scope_row.id),
            detail=f"in scope for {scope.origin}",
        ),
        extra={
            "wait_seconds": str((due - now).total_seconds()),
            "max_response_bytes": str(limits.max_response_bytes),
            "max_in_flight": str(limits.max_in_flight),
        },
    )


def _related_scope(session, scan, primary, request):
    """Only immutable, owner-bound scan grants extend a request's scope.

    Resource-only grants never authorize assessment traffic. Browser resource capabilities
    must be separately bound to the observed request before that lane can use a grant.
    """
    grants = (scan.assessment_plan or {}).get("expansion_config", {}).get("related_origins", [])
    for grant in grants:
        if grant.get("purpose") != "scan":
            continue
        try:
            ident = uuid.UUID(grant["scope_version_id"])
        except (KeyError, ValueError, TypeError):
            continue
        row = session.get(ScopeVersionRow, ident)
        if row is None or row.operator_id != scan.operator_id:
            continue
        scope = scope_row_to_domain(row)
        if (
            scope.authority_domain == primary.authority_domain
            and scope.origin == grant.get("origin")
            and request.host == scope.host
            and request.port == scope.port
        ):
            return row, scope
    return None


def _check_scope_membership(scope: ScopeVersion, request: BrokerRequest) -> BrokerDecision | None:
    """Port, method and path checks against the frozen scope version.

    ``CONNECT`` is treated differently on purpose. It is how a client asks the *proxy* to
    open a tunnel, not a request to the target: it carries no path, and its method is not
    something the scope's allowlist has an opinion about. What CONNECT must prove is that
    the destination is in scope — so the host check and the port check below still apply in
    full, and are the whole of its authorization.

    The method and path allowlists then govern the application requests that travel inside
    the tunnel, each of which is authorized separately by the ``request`` hook. Enforcing
    them on the CONNECT itself would mean `allowed_methods: [GET, HEAD]` made every HTTPS
    request impossible, which is a scope rule contradicting the transport it runs on.
    """
    is_tunnel = request.method.upper() == "CONNECT"
    if _transport_probe(scope, request):
        return None
    if not is_tunnel and request.scheme != scope.scheme:
        return BrokerDecision.deny(DenialReason.DESTINATION_REFUSED, "scheme not in scope")

    if request.port != scope.port:
        return BrokerDecision.deny(
            DenialReason.PORT_NOT_ALLOWED, f"port {request.port} is not the scope port {scope.port}"
        )
    if not is_tunnel and request.method.upper() not in {m.upper() for m in scope.allowed_methods}:
        return BrokerDecision.deny(
            DenialReason.METHOD_NOT_ALLOWED,
            f"method {request.method} is not allowed for this scope "
            f"(allowed: {list(scope.allowed_methods)})",
        )

    if is_tunnel:
        return None

    try:
        paths = path_interpretations(request.path or "/")
        exclusions = [canonical_path(p) for p in scope.excluded_paths]
        prefixes = [canonical_path(p) for p in scope.allowed_path_prefixes]
    except (ValueError, UnicodeError):
        return BrokerDecision.deny(DenialReason.PATH_NOT_ALLOWED, "ambiguous scope path")
    if any(
        path.casefold() == excluded.casefold()
        or path.casefold().startswith(excluded.rstrip("/").casefold() + "/")
        for path in paths
        for excluded in exclusions
    ):
        return BrokerDecision.deny(DenialReason.PATH_EXCLUDED, "request matches an excluded path")

    if not all(
        any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)
        for path in paths
    ):
        return BrokerDecision.deny(
            DenialReason.PATH_NOT_ALLOWED,
            f"request is outside the allowed prefixes {list(scope.allowed_path_prefixes)}",
        )
    return None


def _transport_probe(scope: ScopeVersion, request: BrokerRequest) -> bool:
    return (
        scope.scheme == "https"
        and scope.transport_http_port is not None
        and request.scheme == "http"
        and request.host == scope.host
        and request.port == scope.transport_http_port
        and request.method == "GET"
        and request.path == "/"
    )


def _check_destination(
    session: Session,
    settings: Settings,
    scan: ScanRow,
    scope: ScopeVersion,
    request: BrokerRequest,
    resolver: Resolver,
) -> tuple[str, ...] | BrokerDecision:
    """Revalidate DNS, but always connect to the scan's initially approved addresses."""
    if request.host != scope.host:
        return BrokerDecision.deny(
            DenialReason.HOST_NOT_IN_SCOPE,
            f"host {request.host!r} is not the scope host {scope.host!r}",
        )

    lab_binding: LabBinding | None = scope.lab_binding
    if lab_binding and _transport_probe(scope, request):
        lab_binding = lab_binding.model_copy(update={"port": request.port})
    lab_allowlist = load_lab_services(settings.lab_services_file) if lab_binding else None

    if scope.authority_domain is AuthorityDomain.LAB:
        # A lab address is an IP literal, so resolution is identity. Still routed through
        # validate_destination so lab and production share one decision function.
        addresses = [scope.host]
    else:
        addresses = resolver.resolve(scope.host)

    decision = validate_destination(
        host=scope.host,
        port=request.port,
        resolved_addresses=addresses,
        authority_domain=scope.authority_domain,
        lab_binding=lab_binding,
        lab_allowlist=lab_allowlist,
    )
    if not decision.allowed:
        return BrokerDecision.deny(DenialReason.DESTINATION_REFUSED, decision.reason)

    resolved = tuple(decision.addresses)

    # Pin for the entire scan. CDN DNS rotation does not grant a new destination:
    # return the original address set even when today's public answers differ. Fresh
    # private/mixed answers still fail validation above. The proxy connects to the
    # returned literal address and preserves Host/SNI; it never resolves again at dial.
    session.refresh(scan, with_for_update=True)
    if str(scope.id) != str(scan.scope_version_id):
        plan = dict(scan.assessment_plan or {})
        pins = dict(plan.get("related_origin_pins", {}))
        key = scope.origin
        if key not in pins:
            pins[key] = list(resolved)
            scan.assessment_plan = {**plan, "related_origin_pins": pins}
            session.flush()
        return tuple(pins[key])
    if scan.pinned_addresses is None:
        scan.pinned_addresses = list(resolved)
        session.flush()

    # No second address check here. `validate_destination` above already applied the rule
    # for this scope's authority domain, and it is the authority-aware one — a lab scope is
    # *supposed* to resolve to a private address. Re-applying the production public-IP rule
    # on top would refuse every legitimate lab request.
    return tuple(scan.pinned_addresses)


def _reserve_budget(session: Session, scan: ScanRow, settings: Settings) -> None:
    from scopelens.execution import budget as budget_service
    from scopelens.execution.ledger import budget_limits_for

    scope_row = session.get(ScopeVersionRow, scan.scope_version_id)
    assert scope_row is not None
    budget_service.reserve(
        session,
        scan_id=scan.id,
        limits=budget_limits_for(scope_row, settings),
        usage=BudgetUsage().plus_requests(1),
    )


def scan_id_from_token(session: Session, token: str) -> uuid.UUID | None:
    scan = scan_for_token(session, token)
    return scan.id if scan else None
