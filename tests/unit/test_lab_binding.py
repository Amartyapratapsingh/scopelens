"""Lab service allowlist behaviour (Build Plan §5.1).

The allowlist is what keeps "lab scope" from meaning "any private address". These
tests assert it is narrow and strict, and that it fails closed.
"""

from __future__ import annotations

import pytest
from tests.conftest import LAB_BAD_ADDRESS, LAB_GOOD_ADDRESS, write_lab_services

from scopelens.domain.lab import (
    LabBinding,
    LabBindingError,
    LabService,
    LabServiceAllowlist,
    load_lab_services,
)


class TestAllowlistStrictness:
    def test_exact_binding_matches(self, lab_allowlist: LabServiceAllowlist) -> None:
        service = lab_allowlist.validate_binding(
            LabBinding(
                service="labs-bad",
                address=LAB_BAD_ADDRESS,
                port=80,
                environment="docker-compose-labs",
            )
        )
        assert service.id == "labs-bad"

    def test_unknown_service_is_refused(self, lab_allowlist: LabServiceAllowlist) -> None:
        with pytest.raises(LabBindingError, match="unknown lab service"):
            lab_allowlist.validate_binding(
                LabBinding(
                    service="labs-evil",
                    address=LAB_BAD_ADDRESS,
                    port=80,
                    environment="docker-compose-labs",
                )
            )

    def test_address_of_another_service_is_refused(
        self, lab_allowlist: LabServiceAllowlist
    ) -> None:
        """The good fixture's address is approved — but not for the bad service."""
        with pytest.raises(LabBindingError, match="not approved for lab service"):
            lab_allowlist.validate_binding(
                LabBinding(
                    service="labs-bad",
                    address=LAB_GOOD_ADDRESS,
                    port=80,
                    environment="docker-compose-labs",
                )
            )

    def test_unapproved_port_is_refused(self, lab_allowlist: LabServiceAllowlist) -> None:
        with pytest.raises(LabBindingError, match="port"):
            lab_allowlist.validate_binding(
                LabBinding(
                    service="labs-bad",
                    address=LAB_BAD_ADDRESS,
                    port=22,
                    environment="docker-compose-labs",
                )
            )

    def test_environment_must_match(self, lab_allowlist: LabServiceAllowlist) -> None:
        with pytest.raises(LabBindingError, match="environment"):
            lab_allowlist.validate_binding(
                LabBinding(
                    service="labs-bad",
                    address=LAB_BAD_ADDRESS,
                    port=80,
                    environment="production",
                )
            )

    def test_arbitrary_private_address_is_not_covered(
        self, lab_allowlist: LabServiceAllowlist
    ) -> None:
        """The allowlist is not a private-network allowlist."""
        for address in ("10.0.0.1", "192.168.1.1", "172.28.0.99", "169.254.169.254"):
            with pytest.raises(LabBindingError):
                lab_allowlist.validate_binding(
                    LabBinding(
                        service="labs-bad",
                        address=address,
                        port=80,
                        environment="docker-compose-labs",
                    )
                )


class TestAllowlistSchema:
    def test_addresses_must_be_ip_literals(self) -> None:
        with pytest.raises(ValueError, match="IP literal"):
            LabService(
                id="labs-x",
                environment="env",
                addresses=("labs-x.internal",),
                ports=(80,),
            )

    def test_port_range_is_enforced(self) -> None:
        with pytest.raises(ValueError, match="port out of range"):
            LabService(id="labs-x", environment="env", addresses=("10.0.0.1",), ports=(0,))

    def test_schemes_are_constrained(self) -> None:
        with pytest.raises(ValueError, match="unsupported lab scheme"):
            LabService(
                id="labs-x",
                environment="env",
                addresses=("10.0.0.1",),
                ports=(80,),
                schemes=("gopher",),
            )

    def test_extra_fields_are_refused(self, tmp_path) -> None:
        path = write_lab_services(
            tmp_path,
            services=[
                {
                    "id": "labs-bad",
                    "environment": "docker-compose-labs",
                    "addresses": [LAB_BAD_ADDRESS],
                    "ports": [80],
                    "unexpected": "field",
                }
            ],
        )
        with pytest.raises(Exception):  # noqa: B017 - pydantic ValidationError
            load_lab_services(path)


class TestLoading:
    def test_valid_file_loads(self, tmp_path) -> None:
        allowlist = load_lab_services(write_lab_services(tmp_path))
        assert allowlist.ids() == ["labs-bad", "labs-good"]

    def test_missing_file_yields_an_empty_allowlist(self, tmp_path) -> None:
        """Fail closed: absence of the allowlist must not permit lab addresses."""
        allowlist = load_lab_services(tmp_path / "does-not-exist.yaml")
        assert allowlist.services == ()
        assert allowlist.ids() == []

    def test_empty_file_yields_an_empty_allowlist(self, tmp_path) -> None:
        path = tmp_path / "empty.yaml"
        path.write_text("", encoding="utf-8")
        assert load_lab_services(path).services == ()

    def test_non_mapping_file_is_refused(self, tmp_path) -> None:
        path = tmp_path / "list.yaml"
        path.write_text("- one\n- two\n", encoding="utf-8")
        with pytest.raises(LabBindingError, match="mapping"):
            load_lab_services(path)

    def test_shipped_allowlist_is_valid(self) -> None:
        """The repository's own allowlist must parse and contain only the fixtures."""
        from scopelens.config import REPO_ROOT

        allowlist = load_lab_services(REPO_ROOT / "deploy" / "lab_services.yaml")
        assert set(allowlist.ids()) == {
            "labs-discovery-a",
            "labs-discovery-b",
            "labs-academic-a",
            "labs-academic-b",
            "labs-browser-workflows",
            "labs-callbacks",
            "labs-bad",
            "labs-good",
            "labs-validation",
            "juice-shop",
            "labs-session-expiry-a",
            "labs-session-expiry-b",
            "labs-academic-faults",
            "labs-holdout-a",
            "labs-holdout-b",
            "labs-holdout-c",
            "labs-holdout-d",
        }
        for service in allowlist.services:
            assert service.environment == "docker-compose-labs"
            # No host/control-plane or metadata address may appear.
            assert not set(service.addresses) & {"127.0.0.1", "::1", "169.254.169.254"}
