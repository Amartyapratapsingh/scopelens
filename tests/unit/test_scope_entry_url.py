from types import SimpleNamespace

import pytest

from scopelens.execution.coordinator import scope_entry_url
from scopelens.execution.supervisor import SupervisorError


@pytest.mark.parametrize(
    "prefixes,excluded,expected",
    [
        (("/",), (), "/"),
        (("/auerp",), (), "/auerp"),
        (("/staff", "/app"), (), "/app"),
        (("/staff", "/app"), ("/app",), "/staff"),
    ],
)
def test_worker_entry_stays_in_approved_application(prefixes, excluded, expected):
    scope = SimpleNamespace(
        origin="https://owned.invalid", allowed_path_prefixes=prefixes, excluded_paths=excluded
    )
    assert scope_entry_url(scope) == "https://owned.invalid" + expected


@pytest.mark.parametrize("excluded", [("/",), ("/auerp",)])
def test_fully_excluded_application_cannot_start_worker(excluded):
    scope = SimpleNamespace(
        origin="https://owned.invalid", allowed_path_prefixes=("/auerp",), excluded_paths=excluded
    )
    with pytest.raises(SupervisorError, match="no permitted entry path"):
        scope_entry_url(scope)
