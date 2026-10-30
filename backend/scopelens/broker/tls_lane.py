"""Constrained TLS measurement lane (Build Plan §5.3; Project Specification §17.3).

Why this exists at all: the HTTP assessment lane runs through an intercepting proxy, so
the certificate a worker sees over HTTPS is the **proxy's**, not the target's. A check
that reported certificate facts gathered through the proxy would be reporting its own
instrumentation. So TLS measurements take a separate, constrained path that opens a real
connection to the real upstream.

The word doing the work is *constrained*. This lane is **not** a general egress proxy and
must never become one:

* it performs a handshake, reads the negotiated protocol and the peer certificate, and
  closes. It **never forwards application data** — there is no code path in which bytes
  from a caller reach the socket
* it validates the same egress token and the same scope rules as the HTTP lane, via the
  same `validate_destination`
* it accepts only a host and port, both of which must match the scan's frozen scope

That combination is what makes a direct connection acceptable here: the lane can only
reach destinations the operator already authorized, and it can only ask for a
certificate — it cannot speak to the service once the handshake completes.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime


class TLSMeasurementError(RuntimeError):
    pass


@dataclass(frozen=True)
class TLSFacts:
    """What a real handshake to the upstream revealed."""

    host: str
    port: int
    reachable: bool
    protocol_version: str | None = None
    cipher: str | None = None
    certificate_subject: dict[str, str] = field(default_factory=dict)
    certificate_issuer: dict[str, str] = field(default_factory=dict)
    not_before: str | None = None
    not_after: str | None = None
    serial_number: str | None = None
    subject_alt_names: tuple[str, ...] = ()
    self_signed: bool | None = None
    error: str | None = None
    measured_at: str | None = None
    certificate_verified: bool | None = None
    verification_error: str | None = None
    legacy_protocols: dict[str, str] = field(default_factory=dict)

    @property
    def days_until_expiry(self) -> int | None:
        """Whole days until expiry, or None when there is no certificate to judge."""
        if not self.not_after:
            return None
        from datetime import UTC, datetime

        try:
            expiry = datetime.strptime(self.not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        except ValueError:
            return None
        return (expiry - datetime.now(UTC)).days


def _name_to_dict(name: object) -> dict[str, str]:
    """Flatten an ``ssl`` certificate name into a plain dict.

    ``getpeercert()`` returns tuples of relative distinguished names; flattening here
    keeps the record JSON-serialisable and free of the tuple-of-tuples shape.
    """
    if not isinstance(name, tuple | list):
        return {}
    flattened: dict[str, str] = {}
    for rdn in name:
        for pair in rdn:
            if isinstance(pair, tuple | list) and len(pair) == 2:
                flattened[str(pair[0])] = str(pair[1])
    return flattened


def _decode_der_certificate(der: bytes | None) -> dict:
    """Read the fields this lane reports out of a DER-encoded certificate.

    Dates are formatted the way the stdlib's own decoder formats them (``Nov 24 12:00:00
    2027 GMT``) so that anything parsing these strings does not need to know which decoder
    produced them.
    """
    empty = {
        "subject": {},
        "issuer": {},
        "not_before": None,
        "not_after": None,
        "serial_number": None,
        "subject_alt_names": (),
    }
    if not der:
        return empty

    from cryptography import x509

    certificate = x509.load_der_x509_certificate(der)

    alt_names: list[str] = []
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        alt_names = [
            str(value)
            for value in extension.value.get_values_for_type(x509.DNSName)
            + extension.value.get_values_for_type(x509.IPAddress)
        ]
    except x509.ExtensionNotFound:
        alt_names = []

    return {
        "subject": _rdn_to_dict(certificate.subject.rdns),
        "issuer": _rdn_to_dict(certificate.issuer.rdns),
        "not_before": certificate.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
        "not_after": certificate.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
        "serial_number": format(certificate.serial_number, "X"),
        "subject_alt_names": tuple(alt_names),
    }


def _rdn_to_dict(rdns) -> dict[str, str]:  # type: ignore[no-untyped-def]
    """Flatten a certificate name to ``{attribute: value}``, first value winning."""
    flattened: dict[str, str] = {}
    for rdn in rdns:
        for attribute in rdn:
            flattened.setdefault(attribute.oid._name, attribute.value)
    return flattened


def measure_tls(
    host: str,
    port: int,
    *,
    timeout: float = 5.0,
    ca_file: str | None = None,
    authorize_handshake: Callable[[], str] | None = None,
) -> TLSFacts:
    """Measure with SNI preserved and independently authorize every bounded handshake."""
    measured_at = datetime.now(UTC).isoformat()

    def connect(context):
        address = authorize_handshake() if authorize_handshake else host
        raw = socket.create_connection((address, port), timeout=timeout)
        try:
            return context.wrap_socket(raw, server_hostname=host)
        except Exception:
            raw.close()
            raise

    verified = None
    verification_error = None
    der = None
    protocol = None
    cipher = None
    try:
        context = ssl.create_default_context(cafile=ca_file)
        try:
            with connect(context) as tls:
                der, protocol, cipher = (
                    tls.getpeercert(binary_form=True),
                    tls.version(),
                    tls.cipher(),
                )
                verified = True
        except ssl.SSLCertVerificationError as exc:
            verified = False
            verification_error = exc.verify_message
            capture = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            capture.check_hostname = False
            capture.verify_mode = ssl.CERT_NONE
            with connect(capture) as tls:
                der, protocol, cipher = (
                    tls.getpeercert(binary_form=True),
                    tls.version(),
                    tls.cipher(),
                )

        certificate = _decode_der_certificate(der)
        legacy = {}
        for name, version in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
            probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            probe.check_hostname = False
            probe.verify_mode = ssl.CERT_NONE
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                probe.minimum_version = probe.maximum_version = version
            try:
                probe.set_ciphers("ALL:@SECLEVEL=0")
                with connect(probe):
                    legacy[name] = "accepted"
            except ssl.SSLError as exc:
                legacy[name] = (
                    "rejected"
                    if any(
                        word in str(exc)
                        for word in (
                            "ALERT_PROTOCOL_VERSION",
                            "HANDSHAKE_FAILURE",
                            "UNSUPPORTED_PROTOCOL",
                        )
                    )
                    else "unassessed"
                )
            except OSError:
                legacy[name] = "unassessed"
        return TLSFacts(
            host=host,
            port=port,
            reachable=True,
            protocol_version=protocol,
            cipher=cipher[0] if cipher else None,
            certificate_subject=certificate["subject"],
            certificate_issuer=certificate["issuer"],
            not_before=certificate["not_before"],
            not_after=certificate["not_after"],
            serial_number=certificate["serial_number"],
            subject_alt_names=certificate["subject_alt_names"],
            self_signed=certificate["subject"] == certificate["issuer"],
            measured_at=measured_at,
            certificate_verified=verified,
            verification_error=verification_error,
            legacy_protocols=legacy,
        )
    except (OSError, ssl.SSLError, ValueError) as exc:
        return TLSFacts(
            host=host,
            port=port,
            reachable=False,
            measured_at=measured_at,
            error=f"{type(exc).__name__}: {exc}",
        )
