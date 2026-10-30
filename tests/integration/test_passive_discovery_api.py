import json

import pytest
from sqlalchemy import select

from scopelens.discovery.control import discover_for_scan
from scopelens.persistence.models import EvidenceRow, ScanRow

pytestmark = pytest.mark.db


def snapshot():
    return {
        "version": "passive-hosts-v1",
        "registrable_domain": "example.com",
        "observed_at": "2026-10-11T00:00:00+00:00",
        "state": "partial",
        "coverage_notes": ["dns_count_or_time_cap"],
        "target_http_requests": 0,
        "dns_provider": "dns.google",
        "hosts": [
            {
                "host": "unlinked.example.com",
                "role": "inventory_only",
                "evidence": "CT name",
                "sources": ["certificate-transparency", "dns"],
                "dns_status": "resolvable",
                "dns_addresses": ["93.184.216.34"],
                "dns_observed_at": "2026-10-11T00:00:00+00:00",
                "observations": [
                    {
                        "source": "certificate-transparency",
                        "provider": "crt.sh",
                        "observed_at": "2026-10-11T00:00:00+00:00",
                        "wildcard": False,
                    }
                ],
            }
        ],
    }


def test_control_plane_persists_evidence_once_and_dashboard_does_no_network(
    settings,
    queued_scan,
    db_session,
    authed_client,
    monkeypatch,
):
    from scopelens.discovery import passive

    scan, _ = queued_scan
    calls = []

    def collect(origin):
        calls.append(origin)
        return snapshot()

    monkeypatch.setattr(passive, "cached_collect", collect)
    enabled = settings.model_copy(update={"passive_discovery_enabled": True})
    discover_for_scan(enabled, scan.id, origin="https://example.com")
    discover_for_scan(enabled, scan.id, origin="https://example.com")
    assert calls == ["https://example.com"]
    db_session.expire_all()
    assert db_session.get(ScanRow, scan.id).assessment_plan["passive_host_discovery"] == snapshot()
    evidence = db_session.scalars(
        select(EvidenceRow).where(
            EvidenceRow.scan_id == scan.id, EvidenceRow.producer == "passive_host_discovery"
        )
    ).all()
    assert len(evidence) == 1 and evidence[0].origin == "supervisor"
    before = db_session.query(ScanRow).count()
    for _ in range(2):
        hosts = authed_client.get(f"/api/scans/{scan.id}/hosts").json()
        assert hosts[0]["host"] == "unlinked.example.com" and hosts[0]["role"] == "inventory_only"
        assert hosts[0]["dns_status"] == "resolvable"
        plan = authed_client.get(f"/api/scans/{scan.id}/host-priorities").json()
        assert plan["discovery"]["coverage_notes"] == ["dns_count_or_time_cap"]
        assert plan["hosts"][0]["sources"] == ["certificate-transparency", "dns"]
        export = authed_client.get(f"/api/scans/{scan.id}/export.json").json()
        assert export["host_discovery"]["target_http_requests"] == 0
        from scopelens.api.dashboard import HostInventoryEntry

        assert [
            HostInventoryEntry.model_validate(h).model_dump() for h in export["host_inventory"]
        ] == [HostInventoryEntry.model_validate(h).model_dump() for h in hosts]
    assert db_session.query(ScanRow).count() == before
    assert len(calls) == 1
    assert "Cookie" not in json.dumps(export["host_inventory"])


def test_passive_inventory_remains_owner_bound(client, queued_scan, db_session, authed_client):
    scan, _ = queued_scan
    scan.assessment_plan = {**(scan.assessment_plan or {}), "passive_host_discovery": snapshot()}
    db_session.commit()
    client.cookies.clear()
    assert client.get(f"/api/scans/{scan.id}/hosts").status_code == 401
    assert client.get(f"/api/scans/{scan.id}/host-priorities").status_code == 401
