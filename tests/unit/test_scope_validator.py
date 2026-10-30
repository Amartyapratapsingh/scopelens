"""Destination validation (Build Plan §5.1, §5.3).

This is the scope boundary's decision function, so the tests are exhaustive about the
addresses that must be refused. A gap here is a gap in the product's only guarantee.
"""

from __future__ import annotations

import pytest

from scopelens.domain.enums import AuthorityDomain
from scopelens.domain.lab import LabBinding, LabServiceAllowlist
from scopelens.scope.validator import (
    METADATA_ADDRESSES,
    ScopeViolation,
    address_rejection_reason,
    is_ip_literal,
    origin_of,
    validate_destination,
    validate_host_syntax,
)

PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:4700:4700::1111"


class TestAddressClassification:
    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("127.0.0.1", "loopback"),
            ("127.1.2.3", "loopback"),
            ("::1", "loopback"),
            ("10.0.0.5", "private"),
            ("192.168.1.10", "private"),
            ("172.16.0.1", "private"),
            ("172.31.255.254", "private"),
            ("fc00::1", "private"),
            ("fd00::1", "private"),
            ("169.254.169.254", "metadata"),
            ("169.254.170.2", "metadata"),
            ("100.100.100.200", "metadata"),
            ("fd00:ec2::254", "metadata"),
            ("100.64.0.1", "CGNAT/not global"),
            ("0.0.0.0", "unspecified/private"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "broadcast"),
            ("::", "unspecified"),
        ],
    )
    def test_non_public_addresses_are_rejected(self, address: str, expected: str) -> None:
        reason = address_rejection_reason(address)
        assert reason is not None, f"{address} ({expected}) must be rejected"

    @pytest.mark.parametrize(
        "address", [PUBLIC_V4, PUBLIC_V6, "8.8.8.8", "1.1.1.1", "93.184.216.34"]
    )
    def test_public_addresses_are_accepted(self, address: str) -> None:
        assert address_rejection_reason(address) is None

    @pytest.mark.parametrize("address", METADATA_ADDRESSES)
    def test_every_named_metadata_address_is_rejected(self, address: str) -> None:
        assert address_rejection_reason(address) is not None

    @pytest.mark.parametrize(
        ("wrapped", "inner"),
        [
            ("::ffff:127.0.0.1", "127.0.0.1"),
            ("::ffff:10.0.0.1", "10.0.0.1"),
            ("::ffff:169.254.169.254", "169.254.169.254"),
        ],
    )
    def test_ipv4_mapped_v6_is_judged_as_its_v4_self(self, wrapped: str, inner: str) -> None:
        # Otherwise the loopback/private checks are bypassed by the v6 wrapper.
        assert address_rejection_reason(wrapped) == address_rejection_reason(inner)

    def test_garbage_is_rejected(self) -> None:
        assert address_rejection_reason("not-an-ip") is not None
        assert address_rejection_reason("") is not None


class TestHostSyntax:
    @pytest.mark.parametrize(
        "host", ["exa mple.com", "example.com/path", "a@b.com", "example.com\\x", "exa\tmple.com"]
    )
    def test_ambiguous_hosts_are_rejected(self, host: str) -> None:
        with pytest.raises(ScopeViolation):
            validate_host_syntax(host)

    def test_unnormalized_host_is_rejected(self) -> None:
        with pytest.raises(ScopeViolation, match="normalized"):
            validate_host_syntax("EXAMPLE.com")

    def test_empty_host_is_rejected(self) -> None:
        with pytest.raises(ScopeViolation):
            validate_host_syntax("")

    @pytest.mark.parametrize(
        ("host", "expected"),
        [("93.184.216.34", True), ("::1", True), ("example.com", False), ("", False)],
    )
    def test_ip_literal_detection(self, host: str, expected: bool) -> None:
        assert is_ip_literal(host) is expected


class TestProductionValidation:
    def test_public_hostname_is_allowed(self) -> None:
        decision = validate_destination(
            host="owned.example.com",
            port=443,
            resolved_addresses=[PUBLIC_V4],
            authority_domain=AuthorityDomain.PRODUCTION,
        )
        assert decision.allowed
        assert decision.addresses == (PUBLIC_V4,)

    @pytest.mark.parametrize("host", ["93.184.216.34", "8.8.8.8", "::1"])
    def test_ip_literals_are_refused(self, host: str) -> None:
        decision = validate_destination(
            host=host,
            port=443,
            resolved_addresses=[host],
            authority_domain=AuthorityDomain.PRODUCTION,
        )
        assert not decision.allowed
        assert "IP literal" in decision.reason

    def test_one_private_answer_rejects_the_whole_host(self) -> None:
        """A dual-resolving host must not be accepted on the strength of its public answer."""
        decision = validate_destination(
            host="dual.example.com",
            port=443,
            resolved_addresses=[PUBLIC_V4, "10.0.0.5"],
            authority_domain=AuthorityDomain.PRODUCTION,
        )
        assert not decision.allowed
        assert "10.0.0.5" in decision.reason

    @pytest.mark.parametrize(
        "resolved",
        [["127.0.0.1"], ["169.254.169.254"], ["100.64.0.1"], ["fe80::1"], ["fc00::1"], ["::1"]],
    )
    def test_non_public_resolutions_are_refused(self, resolved: list[str]) -> None:
        decision = validate_destination(
            host="target.example.com",
            port=443,
            resolved_addresses=resolved,
            authority_domain=AuthorityDomain.PRODUCTION,
        )
        assert not decision.allowed

    def test_unresolvable_host_is_refused(self) -> None:
        decision = validate_destination(
            host="nowhere.example.com",
            port=443,
            resolved_addresses=[],
            authority_domain=AuthorityDomain.PRODUCTION,
        )
        assert not decision.allowed
        assert "did not resolve" in decision.reason

    def test_a_lab_binding_grants_production_nothing(self, lab_binding: LabBinding) -> None:
        """The two authority domains never mix."""
        decision = validate_destination(
            host="dual.example.com",
            port=443,
            resolved_addresses=[PUBLIC_V4, "10.0.0.5"],
            authority_domain=AuthorityDomain.PRODUCTION,
            lab_binding=lab_binding,
        )
        assert not decision.allowed


class TestLabValidation:
    def test_exact_binding_is_allowed(
        self, lab_allowlist: LabServiceAllowlist, lab_binding: LabBinding
    ) -> None:
        decision = validate_destination(
            host=lab_binding.address,
            port=lab_binding.port,
            resolved_addresses=[lab_binding.address],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=lab_binding,
            lab_allowlist=lab_allowlist,
        )
        assert decision.allowed
        assert decision.lab_service == "labs-bad"

    def test_binding_is_required(self, lab_allowlist: LabServiceAllowlist) -> None:
        decision = validate_destination(
            host="172.28.0.11",
            port=80,
            resolved_addresses=["172.28.0.11"],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=None,
            lab_allowlist=lab_allowlist,
        )
        assert not decision.allowed
        assert "requires an operator-registered lab binding" in decision.reason

    def test_missing_allowlist_fails_closed(self, lab_binding: LabBinding) -> None:
        decision = validate_destination(
            host=lab_binding.address,
            port=lab_binding.port,
            resolved_addresses=[lab_binding.address],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=lab_binding,
            lab_allowlist=None,
        )
        assert not decision.allowed
        assert "failing closed" in decision.reason

    def test_empty_allowlist_denies_everything(self, lab_binding: LabBinding) -> None:
        decision = validate_destination(
            host=lab_binding.address,
            port=lab_binding.port,
            resolved_addresses=[lab_binding.address],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=lab_binding,
            lab_allowlist=LabServiceAllowlist(),
        )
        assert not decision.allowed

    def test_unapproved_address_is_refused(self, lab_allowlist: LabServiceAllowlist) -> None:
        binding = LabBinding(
            service="labs-bad",
            address="10.0.0.99",
            port=80,
            environment="docker-compose-labs",
        )
        decision = validate_destination(
            host="10.0.0.99",
            port=80,
            resolved_addresses=["10.0.0.99"],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=binding,
            lab_allowlist=lab_allowlist,
        )
        assert not decision.allowed

    def test_unapproved_port_is_refused(self, lab_allowlist: LabServiceAllowlist) -> None:
        binding = LabBinding(
            service="labs-bad",
            address="172.28.0.11",
            port=9999,
            environment="docker-compose-labs",
        )
        decision = validate_destination(
            host="172.28.0.11",
            port=9999,
            resolved_addresses=["172.28.0.11"],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=binding,
            lab_allowlist=lab_allowlist,
        )
        assert not decision.allowed

    def test_host_must_equal_the_binding_address(
        self, lab_allowlist: LabServiceAllowlist, lab_binding: LabBinding
    ) -> None:
        """A binding and a destination that disagree is a configuration error, not a merge."""
        decision = validate_destination(
            host="172.28.0.12",
            port=lab_binding.port,
            resolved_addresses=["172.28.0.12"],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=lab_binding,
            lab_allowlist=lab_allowlist,
        )
        assert not decision.allowed
        assert "does not match" in decision.reason

    def test_port_must_equal_the_binding_port(
        self, lab_allowlist: LabServiceAllowlist, lab_binding: LabBinding
    ) -> None:
        decision = validate_destination(
            host=lab_binding.address,
            port=8443,
            resolved_addresses=[lab_binding.address],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=lab_binding,
            lab_allowlist=lab_allowlist,
        )
        assert not decision.allowed

    def test_resolution_outside_the_approved_set_is_refused(
        self, lab_allowlist: LabServiceAllowlist, lab_binding: LabBinding
    ) -> None:
        decision = validate_destination(
            host=lab_binding.address,
            port=lab_binding.port,
            resolved_addresses=[lab_binding.address, "10.0.0.7"],
            authority_domain=AuthorityDomain.LAB,
            lab_binding=lab_binding,
            lab_allowlist=lab_allowlist,
        )
        assert not decision.allowed


class TestRequireAllowed:
    def test_require_allowed_raises_with_the_reason(self) -> None:
        decision = validate_destination(
            host="private.example.com",
            port=443,
            resolved_addresses=["10.1.2.3"],
            authority_domain=AuthorityDomain.PRODUCTION,
        )
        with pytest.raises(ScopeViolation, match="private address"):
            decision.require_allowed()


class TestOriginFormatting:
    @pytest.mark.parametrize(
        ("scheme", "host", "port", "expected"),
        [
            ("https", "example.com", None, "https://example.com"),
            ("https", "example.com", 443, "https://example.com"),
            ("http", "example.com", 80, "http://example.com"),
            ("https", "example.com", 8443, "https://example.com:8443"),
            ("http", "172.28.0.11", 8081, "http://172.28.0.11:8081"),
        ],
    )
    def test_default_ports_are_omitted(
        self, scheme: str, host: str, port: int | None, expected: str
    ) -> None:
        assert origin_of(scheme, host, port) == expected
