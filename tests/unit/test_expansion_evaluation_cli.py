"""Offline evaluator failures cannot shrink case denominators or invent proof/cost."""

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from evaluation.expansion import QualificationRun, compare_runs
from evaluation.expansion_bundle import (
    Bindings,
    Protocol,
    digest,
    freeze,
    read_envelope,
    write_envelope,
)
from evaluation.expansion_replay import replay_input
from evaluation.expansion_run import collect, comparison_result, main, measure, qualification_result

CONTROL = "SL-C04-REDIRECT-01"


def inputs():
    bindings = Bindings.model_validate(
        {
            "version": "expansion-evaluator-bindings-v1",
            "exported_at": datetime.now(UTC).isoformat(),
            "trusted_export_ref": "test-only-projection",
            "targets": [
                {
                    "target": name,
                    "scan_id": str(uuid4()),
                    "scope_version_id": str(uuid4()),
                    "origin": "http://fixture.invalid",
                    "profile": "external-active-v2",
                    "candidate_fingerprint": "a" * 64,
                    "fixture_fingerprint": "b" * 64,
                    "scope_fingerprint": "c" * 64,
                    "ceiling_requests": 100,
                    "ceiling_seconds": 60,
                    "ceiling_cost": 1,
                    "mode": "baseline",
                    "bindings": [
                        {
                            "control_id": CONTROL,
                            "task_id": "task-" + name,
                            "template_id": "template-" + name,
                            "plan_id": "plan-" + name,
                            "method": "GET",
                            "route": "/redirect",
                            "role_id": "anonymous",
                            "input_key": "query:next:0",
                        }
                    ],
                }
                for name in ("one", "two")
            ],
        }
    )
    protocol = Protocol.model_validate(
        {
            "version": "expansion-evaluation-protocol-v1",
            "partition": "validation",
            "contaminated": True,
            "declared_families": ["redirect", "unmeasured"],
            "cases": [
                {
                    "id": "case-" + target.target,
                    "target": target.target,
                    "family": "redirect",
                    "scenario_group": "synthetic-one",
                    "check_id": CONTROL,
                    "route": "/redirect",
                    "input_key": "query:next:0",
                    "label": "vulnerable" if target.target == "one" else "fixed",
                }
                for target in bindings.targets
            ],
        }
    )
    return bindings, protocol


def artifact(binding, *, positive=True, browser=False):
    ref = str(uuid4())
    data = {
        "control_id": binding.control_id,
        "task_id": binding.task_id,
        "template_id": binding.template_id,
        "plan_id": binding.plan_id,
        "method": binding.method,
        "route": binding.route,
        "role_id": binding.role_id,
        "input_key": binding.input_key,
        "kind": "html" if browser else "redirect",
        "reviewed": True,
        "state": "confirmed" if positive else "pass",
        "captures": [
            {
                "name": name,
                "status": 200 if name == "baseline" else 302,
                "controlled_location": bool(positive and name != "baseline"),
            }
            for name in ("baseline", "probe1", "probe2")
        ],
    }
    if browser:
        data["captures"] = [
            {
                "name": name,
                "nonce": str(n) * 32,
                "status": 200,
                "response_url_matches": True,
                "blocked_subrequests": [],
                "marker_present": bool(positive and name != "baseline"),
                "nonce_matches": True,
            }
            for n, name in enumerate(("baseline", "probe1", "probe2"))
        ]
    payload = {
        "kind": "expanded_active_probe",
        "source": "expansion_browser" if browser else "expansion",
        "run_id": "trusted-run",
        "data": data,
    }
    raw = json.dumps(payload)
    metadata = {
        "id": ref,
        "trusted": True,
        "truncated": False,
        "redaction_state": "redacted",
        "origin": "supervisor",
        "producer_hash": "d" * 64,
        "run_id": "trusted-run",
        "producer": "reviewed_expansion_browser_capture"
        if browser
        else "reviewed_expansion_capture",
        "content_hash": hashlib.sha256(raw.encode()).hexdigest(),
        "content_bytes": len(raw.encode()),
    }
    return ref, {"metadata": metadata, "raw_utf8": raw}


def bundle():
    bindings, protocol = inputs()
    frozen = freeze(bindings, protocol)
    targets = {}
    for target in bindings.targets:
        binding = target.bindings[0]
        positive = target.target == "one"
        ref, capture = artifact(binding, positive=positive)
        scan = {
            "id": str(target.scan_id),
            "scope_version_id": str(target.scope_version_id),
            "target_origin": target.origin,
            "status": "completed",
            "budget_spent": {"requests": 4},
            "started_at": (frozen.created_at - timedelta(seconds=30)).isoformat(),
            "finished_at": (frozen.created_at - timedelta(seconds=10)).isoformat(),
        }
        outcome = {
            "check_id": CONTROL,
            "status": "confirmed_issue" if positive else "pass",
            "required_instances": [binding.task_id],
            "completed_instances": [binding.task_id],
            "evidence_refs": [ref],
        }
        report = {
            "scan": {k: v for k, v in scan.items() if k != "budget_spent"},
            "profile": target.profile,
            "check_outcomes": [outcome],
            "findings": [
                {
                    "check_id": CONTROL,
                    "evidence_status": "confirmed",
                    "locations": [{"route": binding.route}],
                    "evidence_refs": [ref],
                }
            ]
            if positive
            else [],
        }
        targets[target.target] = {
            "scan": scan,
            "report": report,
            "artifacts": {ref: capture},
            "gaps": [],
        }
    return {
        "version": "expansion-evaluation-bundle-v1",
        "freeze": frozen.model_dump(mode="json"),
        "freeze_sha256": digest(frozen.model_dump(mode="json")),
        "targets": targets,
    }


def rewrite_artifact(capture, change):
    payload = json.loads(capture["raw_utf8"])
    change(payload)
    raw = json.dumps(payload)
    capture["raw_utf8"] = raw
    capture["metadata"].update(
        content_hash=hashlib.sha256(raw.encode()).hexdigest(), content_bytes=len(raw.encode())
    )


def test_measure_replays_bad_fixed_and_posthoc_cannot_qualify():
    result = measure(bundle())
    assert result["aggregate"]["counts"] == {"TP": 1, "TN": 1}
    assert result["frozen_before_run"] is False
    assert all(row["cost"] is None for row in result["usage"].values())
    qualified = qualification_result(result)
    assert not qualified["passed"] and qualified["qualified_families"] == []
    assert qualified["families"]["unmeasured"]["samples"]["positive"] == 0
    assert qualified["families"]["redirect"]["precision"]["interval_95"]


@pytest.mark.parametrize(
    "mutation",
    [
        "hash",
        "untrusted",
        "truncated",
        "producer",
        "run",
        "task",
        "plan",
        "role",
        "input",
        "capture",
        "missing",
        "duplicate",
    ],
)
def test_forged_report_or_invalid_capture_never_earns_true_positive(mutation):
    captured = bundle()
    items = captured["targets"]["one"]["artifacts"]
    _ref, data = next(iter(items.items()))
    if mutation == "hash":
        data["raw_utf8"] += " "
    elif mutation in {"untrusted", "truncated"}:
        data["metadata"]["trusted" if mutation == "untrusted" else "truncated"] = (
            mutation == "truncated"
        )
    elif mutation == "producer":
        data["metadata"]["producer"] = "generated-script"
    elif mutation == "run":
        data["metadata"]["run_id"] = "wrong"
    elif mutation in {"task", "plan", "role", "input"}:
        key = {"task": "task_id", "plan": "plan_id", "role": "role_id", "input": "input_key"}[
            mutation
        ]
        rewrite_artifact(data, lambda payload: payload["data"].update({key: "wrong"}))
    elif mutation == "capture":
        rewrite_artifact(data, lambda payload: payload["data"].update(captures=[]))
    elif mutation == "missing":
        items.clear()
    else:
        items[str(uuid4())] = deepcopy(data)
    result = measure(captured)
    assert result["case_verdicts"][0]["verdict"] == "FN"
    assert len(result["qualification_run"]["cases"]) == 2


def test_false_pass_and_unsupported_callback_are_abstentions():
    captured = bundle()
    captured["targets"]["two"]["artifacts"].clear()
    assert measure(captured)["case_verdicts"][1]["verdict"] == "A-"
    target = inputs()[0].targets[0]
    unsupported = target.bindings[0].model_copy(update={"control_id": "SL-C03-SSRF-01"})
    assert replay_input(target, unsupported, {}).reason == "unsupported_replay_family"


def test_browser_marker_facts_replay_but_reflection_alone_does_not_confirm():
    target = inputs()[0].targets[0]
    binding = target.bindings[0].model_copy(update={"control_id": "SL-C03-HTML-01"})
    ref, capture = artifact(binding, browser=True)
    assert replay_input(target, binding, {ref: capture}).state == "confirmed"
    rewrite_artifact(
        capture, lambda payload: payload["data"]["captures"][1].update(marker_present=False)
    )
    assert replay_input(target, binding, {ref: capture}).state == "inconclusive"


def test_collect_only_reads_uuid_bound_api_routes_and_never_sends_labels():
    captured = bundle()
    frozen = freeze(*inputs())
    # Use exactly the bindings associated with captured scan identities.
    from evaluation.expansion_bundle import Freeze

    frozen = Freeze.model_validate(captured["freeze"])
    requests = []

    def handle(request):
        requests.append(request)
        assert request.method == "GET" and not request.content
        for target in frozen.bindings.targets:
            prefix = f"/api/scans/{target.scan_id}"
            if not request.url.path.startswith(prefix):
                continue
            value = captured["targets"][target.target]
            suffix = request.url.path[len(prefix) :]
            if suffix == "":
                return httpx.Response(200, json=value["scan"])
            if suffix == "/export.json":
                return httpx.Response(200, json=value["report"])
            if suffix == "/evidence":
                return httpx.Response(
                    200, json=[a["metadata"] for a in value["artifacts"].values()]
                )
            ref = suffix.split("/")[2]
            return httpx.Response(200, content=value["artifacts"][ref]["raw_utf8"])
        return httpx.Response(404)

    with httpx.Client(
        base_url="http://127.0.0.1:8090", transport=httpx.MockTransport(handle)
    ) as client:
        result = collect(client, frozen)
    assert measure(result)["aggregate"]["counts"] == {"TP": 1, "TN": 1}
    assert all(
        "vulnerable" not in str(request.url) and "fixed" not in str(request.url)
        for request in requests
    )


def test_bundle_hashes_reject_mutation_and_outputs_cannot_be_overwritten(tmp_path):
    path = tmp_path / "data.json"
    sha = write_envelope(path, {"record": "original"})
    assert read_envelope(path, sha) == {"record": "original"}
    with pytest.raises(FileExistsError):
        write_envelope(path, {"other": True})
    value = json.loads(path.read_text())
    value["payload"]["record"] = "changed"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="hash mismatch"):
        read_envelope(path)


def test_cli_measure_and_qualify_write_real_gate_failure(tmp_path, capsys):
    bundle_path, result_path, qualification_path = [
        tmp_path / name for name in ("bundle.json", "result.json", "qualification.json")
    ]
    sha = write_envelope(bundle_path, bundle())
    assert (
        main(
            [
                "measure",
                "--bundle",
                str(bundle_path),
                "--expected-sha256",
                sha,
                "--output",
                str(result_path),
            ]
        )
        == 0
    )
    assert (
        main(["qualify", "--measurement", str(result_path), "--output", str(qualification_path)])
        == 0
    )
    assert read_envelope(qualification_path)["passed"] is False
    assert '"passed": false' in capsys.readouterr().out


def test_role_input_identity_and_scenario_group_are_comparison_dimensions():
    result = measure(bundle())
    run = QualificationRun.model_validate(result["qualification_run"])
    first = run.cases[0]
    second = first.model_copy(update={"id": "other-role", "role_id": "B"})
    assert len(run.model_copy(update={"cases": (first, second)}).cases) == 2
    # Validate normally: distinct role/input contexts can share a route; duplicate ones cannot.
    QualificationRun.model_validate(
        run.model_dump() | {"cases": [first.model_dump(), second.model_dump()]}
    )
    with pytest.raises(ValueError, match="duplicate measurements"):
        QualificationRun.model_validate(
            run.model_dump()
            | {"cases": [first.model_dump(), first.model_dump() | {"id": "renamed"}]}
        )
    from tests.unit.test_expansion_qualification import budgeted

    before = budgeted((first,))
    after = budgeted((first.model_copy(update={"scenario_group": "different"}),))
    assert compare_runs(before, after)["comparable"] is False


def test_compare_preserves_unknown_cost_and_per_target_budgets():
    baseline = measure(bundle())
    adaptive = deepcopy(baseline)
    for target in adaptive["targets"]:
        target["mode"] = "adaptive"
    assert comparison_result(baseline, adaptive)["comparable"] is False
    for result in (baseline, adaptive):
        for target in result["targets"]:
            target["model_cost"] = 0
            target["model_cost_evidence_ref"] = "synthetic-cost-receipt"
        for usage in result["usage"].values():
            usage["cost"] = 0
            usage["cost_evidence_ref"] = "synthetic-cost-receipt"
    assert comparison_result(baseline, adaptive)["comparable"] is True
    adaptive["usage"]["one"]["requests"] = 150
    adaptive["usage"]["two"]["requests"] = 0
    assert comparison_result(baseline, adaptive)["comparable"] is False
    adaptive["usage"]["one"]["requests"] = 4
    adaptive["targets"][0]["ceiling_requests"] = 50
    adaptive["targets"][1]["ceiling_requests"] = 150
    assert comparison_result(baseline, adaptive)["comparable"] is False


def test_same_route_different_input_does_not_inherit_sibling_finding():
    captured = bundle()
    frozen_data = captured["freeze"]
    target = frozen_data["bindings"]["targets"][0]
    sibling = deepcopy(target["bindings"][0])
    sibling.update(task_id="other-task", template_id="other-template", input_key="query:other:0")
    target["bindings"].append(sibling)
    from evaluation.expansion_bundle import InputBinding

    ref, capture = artifact(InputBinding.model_validate(sibling), positive=False)
    row = captured["targets"]["one"]
    row["artifacts"][ref] = capture
    outcome = row["report"]["check_outcomes"][0]
    outcome["required_instances"].append("other-task")
    outcome["completed_instances"].append("other-task")
    outcome["evidence_refs"].append(ref)
    case = deepcopy(frozen_data["protocol"]["cases"][0])
    case.update(id="other-input", input_key="query:other:0", label="fixed")
    frozen_data["protocol"]["cases"].append(case)
    frozen_data["bindings_sha256"] = digest(frozen_data["bindings"])
    frozen_data["protocol_sha256"] = digest(frozen_data["protocol"])
    captured["freeze_sha256"] = digest(frozen_data)
    assert measure(captured)["aggregate"]["counts"] == {"TP": 1, "TN": 2}


def test_cli_collect_closes_already_authenticated_client_without_reopening(tmp_path, monkeypatch):
    frozen = freeze(*inputs())
    path = tmp_path / "freeze.json"
    write_envelope(path, frozen.model_dump(mode="json"))
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    client.post("http://127.0.0.1:8090/api/auth/login")
    monkeypatch.setattr("evaluation.expansion_run._client", lambda: client)
    monkeypatch.setattr(
        "evaluation.expansion_run.collect", lambda client, frozen: {"fixture": True}
    )
    assert main(["collect", "--freeze", str(path), "--output", str(tmp_path / "bundle.json")]) == 0
    assert client.is_closed


def test_cli_rejects_private_extra_fields_without_printing_input_values(tmp_path, capsys):
    bindings, protocol = inputs()
    data = bindings.model_dump(mode="json")
    data["targets"][0]["bindings"][0]["baseline_value"] = "do-not-print-credential"
    b, p = tmp_path / "bindings.json", tmp_path / "protocol.json"
    b.write_text(json.dumps(data))
    p.write_text(protocol.model_dump_json())
    with pytest.raises(SystemExit) as failed:
        main(
            [
                "freeze",
                "--bindings",
                str(b),
                "--protocol",
                str(p),
                "--output",
                str(tmp_path / "freeze.json"),
            ]
        )
    assert failed.value.code == 2
    output = capsys.readouterr()
    assert "do-not-print-credential" not in output.out + output.err
    assert not (tmp_path / "freeze.json").exists()


def test_json_unicode_surrogate_pairs_roundtrip_without_yaml_corruption(tmp_path):
    path = tmp_path / "unicode.json"
    value = {"report_title": "Browser report \U0001f512", "artifact": {"text": "\U0001f680"}}
    sha = write_envelope(path, value)
    assert read_envelope(path, sha) == value


@pytest.mark.parametrize(
    "redaction_state,accepted",
    [("clean", True), ("redacted", True), ("raw", False), ("pending", False)],
)
def test_replay_accepts_only_intake_processed_redaction_states(redaction_state, accepted):
    target = inputs()[0].targets[0]
    ref, capture = artifact(target.bindings[0])
    capture["metadata"]["redaction_state"] = redaction_state
    assert (
        replay_input(target, target.bindings[0], {ref: capture}).state == "confirmed"
    ) is accepted


def test_comparison_rejects_zero_cost_without_corresponding_evidence():
    before = measure(bundle())
    after = deepcopy(before)
    for target in after["targets"]:
        target["mode"] = "adaptive"
    for result in (before, after):
        for usage in result["usage"].values():
            usage["cost"] = 0
    compared = comparison_result(before, after)
    assert not compared["comparable"]
    assert "model cost lacks matching measurement evidence" in compared["reasons"]
