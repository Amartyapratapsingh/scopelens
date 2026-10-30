"""Deployed gate contract without Docker execution or target traffic."""

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from scripts.verify_callback_lab import COLLECTOR, configuration, scanner_peer, verify_report

from scopelens.domain.expansion import AssessmentConfiguration


def test_scanner_peer_reads_actual_enforcing_proxy_lab_interface():
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(
            stdout="proxy-container-id\n"
            if args[1] == "ps"
            else json.dumps({"scopelens_labs_net": {"IPAddress": "172.28.0.31"}})
        )

    assert scanner_peer(run) == "172.28.0.31"
    assert "label=com.docker.compose.service=proxy" in calls[0]
    assert calls[1][-1] == "proxy-container-id"


@pytest.mark.parametrize("peer", ["172.28.0.18", "172.28.0.17", "192.168.5.2", ""])
def test_scanner_peer_never_guesses_nat_or_ambiguous_address(peer):
    def run(args, **kwargs):
        return SimpleNamespace(
            stdout="proxy\n"
            if args[1] == "ps"
            else json.dumps({"scopelens_labs_net": {"IPAddress": peer}})
        )

    with pytest.raises((ValueError, RuntimeError)):
        scanner_peer(run)


@pytest.mark.parametrize("family", ["ssrf", "xxe"])
@pytest.mark.parametrize("variant", ["bad", "fixed"])
def test_four_frozen_recipes_have_exact_destination_and_method(family, variant):
    scope = {"origin": "http://172.28.0.18:8080", "id": str(uuid4())}
    value = configuration(scope, family, variant, "172.28.0.31")
    parsed = AssessmentConfiguration.model_validate(value)
    recipe = parsed.callback_recipes[0].recipe
    assert recipe.callback_origin == COLLECTOR
    assert recipe.method == ("GET" if family == "ssrf" else "POST")
    assert recipe.expected_target_peers == {"172.28.0.18"}
    assert recipe.scanner_peers == {"172.28.0.31"}
    with pytest.raises(ValueError):
        configuration({**scope, "origin": "https://external.test"}, family, variant, "172.28.0.31")


def test_gate_requires_trusted_capture_and_does_not_accept_fixed_pass():
    control = "SL-C07-SSRF-02"
    outcome = {
        "check_id": control,
        "status": "inconclusive",
        "completed_instances": [],
        "required_instances": ["owned-ssrf-fixed"],
        "evidence_refs": [],
    }
    report = {"profile": "staging-stateful-v1", "check_outcomes": [outcome], "findings": []}
    evidence = [{"id": "real-ref", "trusted": True, "producer": "reviewed_callback_broker_capture"}]
    captures = {
        "real-ref": {
            "kind": "callback_capture",
            "source": "callback_broker",
            "data": {"dispatches": [{}, {}, {}], "finished_at": 1000},
        }
    }
    counts = {
        "nonces": 3,
        "intents": 3,
        "dispatches": 3,
        "closures": 3,
        "responses": [200, 200, 200],
        "receipts": 0,
    }
    assert verify_report(report, control, evidence, captures, "ssrf", "fixed", counts) == outcome
    outcome["status"] = "pass"
    with pytest.raises(AssertionError):
        verify_report(report, control, evidence, captures, "ssrf", "fixed", counts)
    outcome["status"] = "inconclusive"
    evidence[0]["trusted"] = False
    with pytest.raises(AssertionError):
        verify_report(report, control, evidence, captures, "ssrf", "fixed", counts)
