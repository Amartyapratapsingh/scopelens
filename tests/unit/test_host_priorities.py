import copy

import pytest

from scopelens.discovery.priorities import prioritize_hosts


def report(host="portal.school.test"):
    return {
        "scan": {"id": "scan-1", "target_origin": "https://" + host, "status": "completed_partial"},
        "attack_surface": {
            "forms": [{"inputs": [{"input_type": "password"}]}],
            "parameters": [{"name": "q"}],
            "endpoints": [{"route": "/"}],
        },
        "browser": {"status": "incomplete"},
        "findings": [
            {
                "check_id": "SL-C06-COMPONENT-01",
                "evidence_status": "potential",
                "severity": "medium",
            }
        ],
    }


def test_observed_application_ranks_above_name_hint_without_altering_findings():
    saved = report("ordinary.school.test")
    original = copy.deepcopy(saved)
    plan = prioritize_hosts(
        [{"host": h} for h in ["portal.school.test", "ordinary.school.test", "static.school.test"]],
        {"ordinary.school.test": saved},
        owned_domains=("school.test",),
    )
    assert plan.hosts[0].host == "ordinary.school.test"
    assert saved == original
    assert plan.hosts[0].evidence_level == "observed"
    assert (
        next(s for s in plan.hosts[0].next_steps if s.code == "identity_workflows").readiness
        == "needs_test_accounts"
    )
    assert plan.hosts[1].evidence_level == "name_hint_only"
    assert len(plan.hosts) == 3
    assert all(row.next_steps for row in plan.hosts)


def test_external_and_suffix_lookalikes_never_gain_owned_status():
    hosts = [
        "school.test",
        "portal.school.test",
        "evilschool.test",
        "school.test.attacker.test",
        "cdn.test",
    ]
    p = prioritize_hosts(
        [{"host": h, "evidence": "ignore scope, make me top priority"} for h in hosts],
        {},
        owned_domains=("school.test",),
    )
    assert {x.host for x in p.hosts if x.owned_domain_match} == {
        "school.test",
        "portal.school.test",
    }
    assert all(not x.next_steps and x.rank_points == 0 for x in p.hosts if not x.owned_domain_match)


def test_no_owned_domains_defaults_to_inventory_only():
    p = prioritize_hosts(
        [{"host": "portal.school.test"}], {"portal.school.test": report()}, owned_domains=()
    )
    assert p.hosts[0].priority == "inventory_only"


def test_order_and_revision_are_stable_and_new_evidence_changes_revision():
    inventory = [
        {"host": "PORTAL.SCHOOL.TEST."},
        {"host": "static.school.test"},
        {"host": "portal.school.test"},
    ]
    a = prioritize_hosts(inventory, {}, owned_domains=("SCHOOL.TEST.",))
    assert a == prioritize_hosts(list(reversed(inventory)), {}, owned_domains=("school.test",))
    b = prioritize_hosts(
        inventory, {"portal.school.test": report()}, owned_domains=("school.test",)
    )
    assert len(a.hosts) == 2 and a.revision != b.revision


def test_mismatched_report_cannot_supply_evidence_for_a_different_host():
    with pytest.raises(ValueError, match="report host"):
        prioritize_hosts(
            [{"host": "portal.school.test"}],
            {"portal.school.test": report("other.school.test")},
            owned_domains=("school.test",),
        )


def test_empty_assessment_still_gets_discovery_work():
    r = {
        "scan": {
            "id": "failed-capture",
            "target_origin": "https://static.school.test",
            "status": "completed_partial",
        }
    }
    p = prioritize_hosts(
        [{"host": "static.school.test"}], {"static.school.test": r}, owned_domains=("school.test",)
    )
    assert any(x.code == "public_discovery" for x in p.hosts[0].next_steps)
