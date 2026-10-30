"""Freeze and measure captured expansion results; never starts a scan or sees target traffic."""

from __future__ import annotations

import argparse
import hashlib
import json
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import httpx

from evaluation.expansion import (
    BudgetedResult,
    MeasuredCase,
    QualificationRun,
    compare_runs,
    qualify,
)
from evaluation.expansion_bundle import (
    Bindings,
    Freeze,
    Protocol,
    digest,
    evaluator_fingerprint,
    freeze,
    read_envelope,
    read_object,
    write_envelope,
)
from evaluation.expansion_replay import replay_input, verified_payload
from evaluation.metrics import classify, metrics

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 48 * 1024 * 1024
TERMINAL = {"completed", "completed_partial", "cancelled", "failed"}


def _json_get(client, path):
    response = client.get(path)
    response.raise_for_status()
    return response.json()


def _bound_report(target, detail, report):
    scan = report.get("scan", {})
    for actual in (detail, scan):
        if str(actual.get("id")) != str(target.scan_id) or str(
            actual.get("scope_version_id")
        ) != str(target.scope_version_id):
            raise ValueError("export scan/scope binding mismatch")
        if actual.get("status") not in TERMINAL:
            raise ValueError("only completed or terminal partial scans may be measured")
        if actual.get("target_origin") != target.origin:
            raise ValueError("export target binding mismatch")
    if report.get("profile") != target.profile:
        raise ValueError("export profile binding mismatch")


def collect(client: httpx.Client, frozen: Freeze) -> dict:
    """GET existing operator-authorized artifacts. No case/label/config POST occurs."""
    if evaluator_fingerprint() != frozen.evaluator_sha256:
        raise ValueError("evaluator changed after freeze")
    targets, total_bytes = {}, 0
    for target in frozen.bindings.targets:
        scan_id = str(target.scan_id)
        detail = _json_get(client, f"/api/scans/{scan_id}")
        report = _json_get(client, f"/api/scans/{scan_id}/export.json")
        _bound_report(target, detail, report)
        rows = _json_get(client, f"/api/scans/{scan_id}/evidence")
        index = {row["id"]: row for row in rows}
        if len(index) != len(rows):
            raise ValueError("duplicate evidence metadata")
        refs = {
            ref
            for row in report.get("check_outcomes", []) + report.get("findings", [])
            for ref in row.get("evidence_refs", [])
        }
        artifacts, gaps = {}, []
        for ref in sorted(refs):
            # Endpoint path is an admitted UUID, never an artifact-supplied URL/path.
            try:
                UUID(ref)
            except (ValueError, TypeError):
                gaps.append({"reason": "invalid_evidence_identifier"})
                continue
            metadata = index.get(ref)
            if not metadata:
                gaps.append({"evidence_ref": ref, "reason": "evidence_metadata_missing"})
                continue
            if (
                metadata.get("trusted") is not True
                or metadata.get("truncated") is not False
                or metadata.get("redaction_state") not in {"redacted", "clean"}
            ):
                gaps.append(
                    {"evidence_ref": ref, "reason": "evidence_not_complete_trusted_redacted"}
                )
                continue
            try:
                with client.stream(
                    "GET", f"/api/scans/{scan_id}/evidence/{ref}/download"
                ) as response:
                    response.raise_for_status()
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        raw.extend(chunk)
                        if (
                            len(raw) > MAX_ARTIFACT_BYTES
                            or total_bytes + len(raw) > MAX_BUNDLE_BYTES
                        ):
                            raise ValueError("artifact_size_limit")
                raw_utf8 = bytes(raw).decode("utf-8")
                if hashlib.sha256(raw).hexdigest() != metadata.get("content_hash") or len(
                    raw
                ) != metadata.get("content_bytes"):
                    raise ValueError("artifact_hash_or_size_mismatch")
                json.loads(raw_utf8)
                artifacts[ref] = {"metadata": metadata, "raw_utf8": raw_utf8}
                total_bytes += len(raw)
            except (httpx.HTTPError, ValueError, UnicodeError):
                gaps.append({"evidence_ref": ref, "reason": "artifact_unavailable_or_invalid"})
        targets[target.target] = {
            "scan": detail,
            "report": report,
            "artifacts": artifacts,
            "gaps": gaps,
        }
    if evaluator_fingerprint() != frozen.evaluator_sha256:
        raise ValueError("evaluator changed during collection")
    return {
        "version": "expansion-evaluation-bundle-v1",
        "freeze": frozen.model_dump(mode="json"),
        "freeze_sha256": digest(frozen.model_dump(mode="json")),
        "collected_at": datetime.now(UTC).isoformat(),
        "targets": targets,
    }


def _time(value):
    try:
        result = datetime.fromisoformat(value)
        return result if result.tzinfo else None
    except (ValueError, TypeError):
        return None


def measure(bundle: dict) -> dict:
    if bundle.get("version") != "expansion-evaluation-bundle-v1" or digest(
        bundle.get("freeze")
    ) != bundle.get("freeze_sha256"):
        raise ValueError("invalid frozen bundle")
    frozen = Freeze.model_validate(bundle["freeze"])
    if evaluator_fingerprint() != frozen.evaluator_sha256:
        raise ValueError(
            "evaluator changed; refreeze as a new measurement, never reuse old provenance"
        )
    targets = {target.target: target for target in frozen.bindings.targets}
    if set(bundle["targets"]) != set(targets):
        raise ValueError("bundle target inventory changed")
    cases, replay_records, run_usage = [], [], {}
    before = frozen.bindings.exported_at <= frozen.created_at
    candidates = {target.candidate_fingerprint for target in targets.values()}
    candidate = next(iter(candidates)) if len(candidates) == 1 and None not in candidates else None
    for name, target in targets.items():
        captured = bundle["targets"][name]
        _bound_report(target, captured["scan"], captured["report"])
        started = _time(captured["scan"].get("started_at"))
        finished = _time(captured["scan"].get("finished_at"))
        before = bool(before and started and frozen.created_at < started)
        requests = captured["scan"].get("budget_spent", {}).get("requests")
        if type(requests) is not int or requests < 0:
            requests = None
        run_usage[name] = {
            "requests": requests,
            "seconds": (finished - started).total_seconds()
            if started and finished and finished >= started
            else None,
            # Only an explicitly evidenced measured cost supplied by the trusted exporter.
            # Empty/missing model ledgers are not proof of zero cost.
            "cost": target.model_cost,
            "cost_evidence_ref": target.model_cost_evidence_ref,
        }
    for case in frozen.protocol.cases:
        target, captured = targets[case.target], bundle["targets"][case.target]
        binding = next(
            b
            for b in target.bindings
            if b.key() == (case.check_id, case.method, case.route, case.role_id, case.input_key)
        )
        report, artifacts = captured["report"], captured["artifacts"]
        replay = replay_input(target, binding, artifacts)
        outcomes = [
            o for o in report.get("check_outcomes", []) if o.get("check_id") == case.check_id
        ]
        outcome = outcomes[0] if len(outcomes) == 1 else {}
        # A finding may aggregate several inputs. Exact replay evidence and completed task
        # binding determine proof credit; a bare route-level claim cannot earn a TP.
        findings = [
            f
            for f in report.get("findings", [])
            if f.get("check_id") == case.check_id
            and f.get("evidence_status") == "confirmed"
            and any(loc.get("route") == case.route for loc in f.get("locations", []))
        ]
        claim_refs = set()
        for ref, artifact in artifacts.items():
            payload = verified_payload(artifact)
            if (
                payload
                and isinstance(payload.get("data"), dict)
                and payload["data"].get("task_id") == binding.task_id
            ):
                claim_refs.add(ref)
        same_route_cases = [
            c
            for c in frozen.protocol.cases
            if (c.target, c.check_id, c.route) == (case.target, case.check_id, case.route)
        ]
        # One route may hold multiple roles/inputs. A finding bound to one task must not
        # turn every sibling input into a positive. Ambiguous unbound claims stay uncredited.
        findings = [
            f
            for f in findings
            if claim_refs & set(f.get("evidence_refs", []))
            or (len(same_route_cases) == 1 and not claim_refs)
        ]
        confirmed = bool(findings)
        reported_refs = {ref for finding in findings for ref in finding.get("evidence_refs", [])}
        outcome_refs = set(outcome.get("evidence_refs", []))
        binding_complete = binding.task_id in outcome.get(
            "completed_instances", []
        ) and binding.task_id in outcome.get("required_instances", [])
        proof_valid = bool(
            confirmed
            and replay.state == "confirmed"
            and binding_complete
            and set(replay.evidence_refs) <= (reported_refs & outcome_refs)
        )
        conclusive = bool(
            binding_complete
            and outcome.get("status") in {"pass", "confirmed_issue"}
            and replay.state in {"pass", "confirmed"}
            and replay.evidence_refs
            and set(replay.evidence_refs) <= outcome_refs
            and ((replay.state == "pass" and not confirmed) or proof_valid)
        )
        replay_record = {
            "case_id": case.id,
            "state": replay.state,
            "reason": replay.reason,
            "evidence_refs": list(replay.evidence_refs),
            "task_id": binding.task_id,
            "evaluator_sha256": frozen.evaluator_sha256,
        }
        replay_hash = digest(replay_record)
        replay_records.append({**replay_record, "sha256": replay_hash})
        cases.append(
            MeasuredCase(
                **case.model_dump(exclude={"label"}),
                label=case.label,
                confirmed=confirmed,
                conclusive=conclusive,
                proof_valid=proof_valid,
                proof_replay_ref=f"sha256:{replay_hash}" if replay.evidence_refs else None,
            )
        )
    qualification_run = QualificationRun(
        partition=frozen.protocol.partition,
        frozen_before_run=bool(before and candidate),
        contaminated=frozen.protocol.contaminated,
        curator_ref=frozen.protocol.curator_ref,
        candidate_fingerprint=candidate or "unknown-or-mixed",
        frozen_candidate_fingerprint=candidate or "unknown-or-mixed",
        manifest_sha256=frozen.protocol_sha256,
        declared_families=frozen.protocol.declared_families,
        cases=tuple(cases),
    )
    verdicts = [
        classify(c.label, confirmed=c.confirmed, conclusive=c.conclusive, proof_valid=c.proof_valid)
        for c in cases
    ]
    return {
        "version": "expansion-measurement-v1",
        "bundle_sha256": digest(bundle),
        "freeze_sha256": bundle["freeze_sha256"],
        "evaluator_sha256": frozen.evaluator_sha256,
        "frozen_before_run": qualification_run.frozen_before_run,
        "qualification_run": qualification_run.model_dump(mode="json"),
        "replays": replay_records,
        "aggregate": metrics(verdicts),
        "case_verdicts": [{"id": c.id, "verdict": v} for c, v in zip(cases, verdicts, strict=True)],
        "usage": run_usage,
        "targets": frozen.bindings.model_dump(mode="json")["targets"],
        "limitations": [
            "Local authenticated export custody is required; hashes detect changes, not remote attestation.",
            "Only reviewed expanded HTTP/browser input families have offline replay. Other families receive no proof credit.",
            "Existing post-hoc measurements cannot establish pre-run freeze or independent holdout qualification.",
            "Proof replay is independent execution of the registered predicate, not an independent fixture oracle.",
        ],
    }


def qualification_result(measurement: dict) -> dict:
    if measurement.get("version") != "expansion-measurement-v1":
        raise ValueError("measurement version required")
    run = QualificationRun.model_validate(measurement["qualification_run"])
    result = qualify(run)
    return {
        **result,
        "verification_ref": f"sha256:{digest(measurement)}",
        "curator_ref": run.curator_ref,
        "frozen_before_run": run.frozen_before_run,
        "contaminated": run.contaminated,
    }


def _budgeted(measurement: dict, mode: str):
    targets = measurement["targets"]
    errors = []
    for field in ("candidate_fingerprint", "scope_fingerprint", "fixture_fingerprint", "profile"):
        if any(target.get(field) is None for target in targets):
            errors.append(f"unknown {field}")
    if any(target.get("mode") != mode for target in targets):
        errors.append(f"expected {mode} run")
    usage = measurement["usage"]
    if any(
        usage[target["target"]].get(key) is None
        for target in targets
        for key in ("requests", "seconds", "cost")
    ):
        errors.append("unknown measured requests/runtime/model cost")
    if any(
        target.get(key) is None
        for target in targets
        for key in ("ceiling_requests", "ceiling_seconds", "ceiling_cost")
    ):
        errors.append("unknown frozen budget ceiling")
    if not errors:
        for target in targets:
            measured = usage[target["target"]]
            if any(
                measured[key] > target[ceiling]
                for key, ceiling in (
                    ("requests", "ceiling_requests"),
                    ("seconds", "ceiling_seconds"),
                    ("cost", "ceiling_cost"),
                )
            ):
                errors.append("a target exceeded its frozen budget")
    if not errors:
        for target in targets:
            actual = usage[target["target"]]
            if (
                target.get("model_cost") != actual["cost"]
                or not target.get("model_cost_evidence_ref")
                or target["model_cost_evidence_ref"] != actual.get("cost_evidence_ref")
            ):
                errors.append("model cost lacks matching measurement evidence")
    if errors:
        return None, errors
    if len({target["profile"] for target in targets}) != 1:
        return None, ["mixed profiles"]
    return BudgetedResult(
        **{
            field: digest({t["target"]: t[field] for t in targets})
            for field in ("candidate_fingerprint", "scope_fingerprint", "fixture_fingerprint")
        },
        profile=targets[0]["profile"],
        **{
            key: sum(t[key] for t in targets)
            for key in ("ceiling_requests", "ceiling_seconds", "ceiling_cost")
        },
        **{
            key: sum(usage[t["target"]][key] for t in targets)
            for key in ("requests", "seconds", "cost")
        },
        cases=tuple(
            MeasuredCase.model_validate(c) for c in measurement["qualification_run"]["cases"]
        ),
    ), []


def comparison_result(baseline: dict, adaptive: dict) -> dict:
    for measurement in (baseline, adaptive):
        if measurement.get("version") != "expansion-measurement-v1":
            raise ValueError("measurement version required")

    def target_limits(measurement):
        return {
            row["target"]: tuple(
                row.get(key) for key in ("ceiling_requests", "ceiling_seconds", "ceiling_cost")
            )
            for row in measurement["targets"]
        }

    if target_limits(baseline) != target_limits(adaptive):
        return {"comparable": False, "reasons": ["per-target budget ceilings differ"]}
    before, before_errors = _budgeted(baseline, "baseline")
    after, after_errors = _budgeted(adaptive, "adaptive")
    if before_errors or after_errors:
        return {"comparable": False, "reasons": sorted(set(before_errors + after_errors))}
    if baseline["evaluator_sha256"] != adaptive["evaluator_sha256"]:
        return {"comparable": False, "reasons": ["evaluator differs"]}
    return compare_runs(before, after)


def _client():
    # No URL flag: operator secrets are sent only to this project's loopback API.
    from scopelens.config import Settings

    settings = Settings()
    client = httpx.Client(
        base_url="http://127.0.0.1:8090", timeout=30, trust_env=False, follow_redirects=False
    )
    try:
        client.post(
            "/api/auth/login",
            json={
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        ).raise_for_status()
    except Exception:
        client.close()
        raise
    return client


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze_parser = sub.add_parser("freeze")
    freeze_parser.add_argument("--bindings", type=Path, required=True)
    freeze_parser.add_argument("--protocol", type=Path, required=True)
    collect_parser = sub.add_parser("collect")
    collect_parser.add_argument("--freeze", type=Path, required=True)
    collect_parser.add_argument("--expected-sha256")
    measure_parser = sub.add_parser("measure")
    measure_parser.add_argument("--bundle", type=Path, required=True)
    measure_parser.add_argument("--expected-sha256")
    qualify_parser = sub.add_parser("qualify")
    qualify_parser.add_argument("--measurement", type=Path, required=True)
    qualify_parser.add_argument("--expected-sha256")
    compare_parser = sub.add_parser("compare")
    compare_parser.add_argument("--baseline", type=Path, required=True)
    compare_parser.add_argument("--adaptive", type=Path, required=True)
    for child in (freeze_parser, collect_parser, measure_parser, qualify_parser, compare_parser):
        child.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            result = freeze(
                Bindings.model_validate(read_object(args.bindings)),
                Protocol.model_validate(read_object(args.protocol)),
            ).model_dump(mode="json")
        elif args.command == "collect":
            frozen = Freeze.model_validate(read_envelope(args.freeze, args.expected_sha256))
            with closing(_client()) as client:
                result = collect(client, frozen)
        elif args.command == "measure":
            result = measure(read_envelope(args.bundle, args.expected_sha256))
        elif args.command == "qualify":
            result = qualification_result(read_envelope(args.measurement, args.expected_sha256))
        else:
            result = comparison_result(read_envelope(args.baseline), read_envelope(args.adaptive))
        hashed = write_envelope(args.output, result)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, httpx.HTTPError) as exc:
        # Validation messages may include input data. No raw inputs, artifacts or credentials
        # go to terminal/logs when an invalid local input is rejected.
        parser.exit(2, f"Evaluation rejected ({type(exc).__name__}); no result written.\n")
    print(
        json.dumps(
            {
                "command": args.command,
                "sha256": hashed,
                **({"passed": result["passed"]} if "passed" in result else {}),
                **({"comparable": result["comparable"]} if "comparable" in result else {}),
            }
        )
    )
    return 0


if __name__ == "__main__":
    main()
