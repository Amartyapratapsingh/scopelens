from types import SimpleNamespace

import pytest

from scopelens.broker.policy import BrokerRequest, _check_scope_membership


def decision(path):
    scope = SimpleNamespace(
        scheme="https",
        host="example.test",
        port=443,
        transport_http_port=None,
        allowed_methods=("GET",),
        allowed_path_prefixes=("/app",),
        excluded_paths=("/app/admin",),
    )
    return _check_scope_membership(
        scope,
        BrokerRequest(
            method="GET",
            scheme="https",
            host="example.test",
            port=443,
            path=path,
            egress_token="test",
        ),
    )


@pytest.mark.parametrize(
    "path",
    [
        "/app/admin?view=1",
        "/app/admin/../safe",
        "/app/%61dmin/../safe",
        "/app/%61dmin",
        "/app/%2561dmin",
        "/app/x/../admin",
        "/app/../outside",
        "/app/%2e%2e/outside",
        "/app//admin",
        "/app/ADMIN",
        "/app/admin;view=1",
        "/app\\admin",
    ],
)
def test_exclusion_and_parent_segments_cannot_be_bypassed(path):
    assert decision(path) is not None


@pytest.mark.parametrize("path", ["/app?view=1", "/app/search?q=%2fadmin", "/app/page"])
def test_query_is_not_part_of_path_membership(path):
    assert decision(path) is None
