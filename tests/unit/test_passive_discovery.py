import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from scopelens.discovery import passive
from scopelens.discovery.priorities import prioritize_hosts

NOW = datetime(2026, 10, 11, tzinfo=UTC)


@pytest.mark.parametrize(
    "name,expected",
    [
        ("portal.school.edu.in", "school.edu.in"),
        ("a.example.co.uk", "example.co.uk"),
        ("a.tenant.github.io", "tenant.github.io"),
        ("a.www.ck", "www.ck"),
        ("foo.bar.ck", "foo.bar.ck"),
        ("localhost", None),
        ("127.0.0.1", None),
        ("labs.invalid", None),
        ("co.uk", None),
        ("a.example.com.", "example.com"),
    ],
)
def test_registrable_domain(name, expected):
    assert passive.registrable_domain(name) == expected


def fixture_client(*, failure=None):
    calls = []

    def handler(request):
        calls.append(request)
        if request.url.host in {"crt.sh", "api.certspotter.com"}:
            if request.url.host == "crt.sh":
                assert request.url.params["q"] == "%.example.com"
            if failure:
                return failure(request)
            return httpx.Response(
                200, json=json.loads(Path("tests/fixtures/passive/ct.json").read_text())
            )
        assert request.url.host == "dns.google"
        name = request.url.params["name"]
        if name == "gone.example.com":
            return httpx.Response(200, json={"Status": 3})
        return httpx.Response(
            200, json={"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34"}]}
        )

    return httpx.Client(transport=httpx.MockTransport(handler)), calls


def test_ct_dns_filtering_and_no_target_http():
    client, calls = fixture_client()
    with client:
        snapshot = passive.collect(
            "https://app.example.com/prefix", client=client, sleep=lambda _: None, now=NOW
        )
    assert [h["host"] for h in snapshot["hosts"]] == [
        "example.com",
        "gone.example.com",
        "portal.example.com",
    ]
    assert snapshot["hosts"][1]["dns_status"] == "unresolved"
    assert snapshot["hosts"][2]["dns_status"] == "resolvable"
    assert snapshot["hosts"][0]["observations"][0]["wildcard"] is True
    assert snapshot["target_http_requests"] == 0
    assert all(h["role"] == "inventory_only" for h in snapshot["hosts"])
    assert {r.url.host for r in calls} == {"crt.sh", "dns.google"}
    assert all("cookie" not in r.headers for r in calls)
    assert all(h["observations"][0]["observed_at"] == NOW.isoformat() for h in snapshot["hosts"])


@pytest.mark.parametrize(
    "failure",
    [
        lambda _: httpx.Response(503),
        lambda _: httpx.Response(200, content=b"invalid"),
        lambda _: httpx.Response(302, headers={"location": "https://target.example.com"}),
        lambda _: httpx.Response(200, headers={"content-length": str(passive.CT_CAP + 1)}),
        lambda _: httpx.Response(200, content=b"a" * (passive.CT_CAP + 1)),
    ],
)
def test_source_unavailable_is_coverage_not_empty_success(failure):
    client, calls = fixture_client(failure=failure)
    with client:
        result = passive.collect("https://example.com", client=client)
    assert result["state"] == "source_unavailable"
    assert result["coverage_notes"] == ["certificate_transparency_source_unavailable"]
    assert len(calls) == 2


def test_count_rate_and_dns_unavailable(monkeypatch):
    monkeypatch.setattr(passive, "MAX_RESOLVE", 1)
    clock = [0.0]
    waits = []
    calls = []

    def sleep(seconds):
        waits.append(seconds)
        clock[0] += seconds

    def handler(request):
        calls.append(request)
        if request.url.host == "crt.sh":
            return httpx.Response(200, json=[{"name_value": "a.example.com\nb.example.com"}])
        return httpx.Response(200, json={"Status": 2})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = passive.collect(
            "https://example.com", client=client, clock=lambda: clock[0], sleep=sleep
        )
    assert len(calls) == 2
    assert result["hosts"][0]["dns_status"] == "unavailable"
    assert result["hosts"][1]["dns_status"] == "not_checked"
    assert result["state"] == "partial"
    assert "dns_source_unavailable" in result["coverage_notes"]
    assert "dns_count_or_time_cap" in result["coverage_notes"]


def test_cache_preserves_evidence_time_and_isolation(monkeypatch):
    passive._cache.clear()
    calls = []

    def collect(origin):
        calls.append(origin)
        return {"state": "complete", "hosts": [{"host": "example.com"}]}

    monkeypatch.setattr(passive, "collect", collect)
    first = passive.cached_collect("https://app.example.com")
    first["hosts"].clear()
    assert passive.cached_collect("https://www.example.com")["hosts"]
    assert len(calls) == 1
    passive._cache.clear()


def test_merge_preserves_primary_role_and_priority_provenance():
    client, _ = fixture_client()
    with client:
        discovery = passive.collect(
            "https://example.com", client=client, sleep=lambda _: None, now=NOW
        )
    inventory = passive.merge_inventory(
        [
            {"host": "example.com", "role": "primary", "evidence": "scope"},
            {"host": "portal.example.com", "role": "inventory_only", "evidence": "link"},
        ],
        discovery,
    )
    assert len(inventory) == 3
    assert inventory[0]["role"] == "primary"
    assert inventory[1]["sources"] == ["certificate-transparency", "dns", "link"]
    plan = prioritize_hosts(inventory, {}, owned_domains=("example.com",), discovery=discovery)
    portal = next(h for h in plan.hosts if h.host == "portal.example.com")
    assert portal.role == "inventory_only" and portal.dns_status == "resolvable"
    assert plan.discovery.state == "complete"
    assert all(h.latest_scan_id is None for h in plan.hosts)


def test_recorded_certspotter_fallback_and_dns_fixture():
    ct = json.loads(Path("tests/fixtures/passive/certspotter-arkyon.json").read_text())
    dns = json.loads(Path("tests/fixtures/passive/dns-arkyon.json").read_text())
    queries = []
    elapsed = [0.0]

    def sleep(seconds):
        elapsed[0] += seconds

    def handler(request):
        queries.append(request)
        if request.url.host == "crt.sh":
            return httpx.Response(503)
        if request.url.host == "api.certspotter.com":
            assert request.url.params["domain"] == "arkyon.dev"
            return httpx.Response(200, json=ct)
        assert request.url.host == "dns.google"
        return httpx.Response(200, json=dns[request.url.params["name"]][request.url.params["type"]])

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = passive.collect(
            "https://app.arkyon.dev", client=client, clock=lambda: elapsed[0], sleep=sleep, now=NOW
        )
    assert {h["host"] for h in result["hosts"]} == {
        "arkyon.dev",
        "games.arkyon.dev",
        "pointsolver.arkyon.dev",
        "www.arkyon.dev",
    }
    assert all(h["dns_status"] == "resolvable" for h in result["hosts"])
    assert all(h["observations"][0]["provider"] == "certspotter" for h in result["hosts"])
    assert result["coverage_notes"] == [
        "certificate_transparency_first_page_only",
        "crt_sh_source_unavailable",
    ]
    assert result["state"] == "partial" and result["target_http_requests"] == 0
    assert len(queries) == 10 and elapsed[0] == 1.75
