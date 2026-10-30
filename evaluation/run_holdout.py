"""Prospectively freeze, health-check and measure through the deployed backend API."""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import yaml

from evaluation.expansion import MeasuredCase, QualificationRun, qualify
from evaluation.holdout_api import create_scan, save_http_error
from evaluation.holdout_lab import (
    LOCK_HELPER,
    LOCK_TOKEN_ENV,
    ROOT,
    has_helper_lock,
    locked_cli,
    reset,
    stack_lock,
)
from evaluation.holdout_schedule import INTER_TRIAL_GAP_SECONDS, run_schedule
from evaluation.metrics import classify, metrics
from evaluation.protocol import Protocol
from evaluation.run import assess, fetch_evidence, source_fingerprint
from scopelens.checks.active import proof
from scopelens.config import REPO_ROOT, Settings

PLAN = [(repeat, mode) for repeat in range(1, 4) for mode in ["baseline", "adaptive"]]
random.Random(20261011).shuffle(PLAN)


def write(path, value):
    with path.open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def scope_request(target, authorization_expires_at):
    """Preserve the registered trial scope, extending only BenchmarkJava's wall time."""
    return {
        "authority_domain": "lab",
        "scheme": "http",
        "lab_service": target,
        "lab_port": 8080,
        "allowed_check_profile": "external-dast",
        "budgets_override": {
            "requests_per_second": 20,
            "max_in_flight": 2,
            "max_total_requests": 5000,
            "wall_clock_seconds": 2700 if target == "labs-holdout-d" else 900,
        },
        "authorization_expires_at": authorization_expires_at.isoformat(),
    }


def scope_wall_receipt(request):
    """Keep the exact per-registration before/after request and terminal wait."""
    previous = {**request, "budgets_override": {**request["budgets_override"]}}
    previous["budgets_override"]["wall_clock_seconds"] = 900
    wall = request["budgets_override"]["wall_clock_seconds"]
    return {
        "previous_request": previous,
        "submitted_request": request,
        "changed_fields": (
            {"budgets_override.wall_clock_seconds": {"previous": 900, "submitted": wall}}
            if wall != 900
            else {}
        ),
        "runner_deadline_seconds": wall + 120,
        "authorization_renewal": "Existing fresh scope registration for each target/trial, with the unchanged now + three hours expiry rule.",
        "reason": "Operator-authorized BenchmarkJava time extension after the earlier evaluator deadline; no other scope budget changes.",
    }


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def candidate_source_fingerprint(commit, *, runtime=False):
    """Hash named tracked paths from Git, or their actual runtime counterparts."""
    paths = (
        subprocess.check_output(
            [
                "git",
                "ls-tree",
                "-r",
                "--name-only",
                "-z",
                commit,
                "--",
                "uv.lock",
                "pyproject.toml",
                "backend",
                "workers",
                "checks_registry",
                "skills",
                "deploy",
            ],
            cwd=ROOT,
        )
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    entries = []
    for path in sorted(p for p in paths if p and "__pycache__" not in p):
        blob = (
            (REPO_ROOT / path).read_bytes()
            if runtime
            else subprocess.check_output(["git", "show", commit + ":" + path], cwd=ROOT)
        )
        entries.append(path + ":" + hashlib.sha256(blob).hexdigest())
    return hashlib.sha256("\n".join(entries).encode()).hexdigest()


def routing(role):
    """Record declared routing without provider credentials."""
    return {
        "base_url": role.base_url,
        "model": role.model,
        "reasoning_effort": role.reasoning_effort,
        "max_output_tokens": role.max_output_tokens,
        "vision": role.vision,
        "input_price_per_million": role.input_price_per_million,
        "output_price_per_million": role.output_price_per_million,
        "fallbacks": [routing(fallback) for fallback in role.fallbacks],
    }


def deployed_images():
    names = subprocess.check_output(
        ["docker", "ps", "--filter", "name=scopelens-dev", "--format", "{{.Names}}"], text=True
    ).splitlines()
    result = {}
    for name in sorted(names):
        result[name] = subprocess.check_output(
            ["docker", "inspect", name, "--format", "{{.Image}}"], text=True
        ).strip()
    if not any("api" in name for name in result):
        raise RuntimeError("deployed API image not established")
    return result


def health(output, *, require_all=True, oracle=None):
    image = subprocess.check_output(
        ["docker", "image", "inspect", "scopelens/browser-worker:dev", "--format", "{{.Id}}"],
        text=True,
    ).strip()
    progress = output / "health-progress.jsonl"
    progress.touch(mode=0o600, exist_ok=False)
    with progress.open("w") as stderr:
        result = subprocess.run(
            [
                "docker",
                "run",
                "-i",
                "--rm",
                "--network",
                "scopelens_labs_net",
                "--shm-size=256m",
                "--security-opt",
                "seccomp=" + str(ROOT / "deploy/browser/seccomp.json"),
                "-v",
                str(ROOT / "evaluation/holdout_health.py") + ":/health.py:ro",
                image,
                "python",
                "/health.py",
            ],
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            input=json.dumps(oracle)
            if oracle is not None
            else (ROOT / "evaluation/holdout/oracle.json").read_text(),
            timeout=1800,
        )
    (output / "health.log").write_text(result.stdout)
    os.chmod(output / "health.log", 0o600)
    if not result.stdout.strip():
        result.check_returncode()
        raise RuntimeError(
            "Independent oracle produced no admission receipt; inspect health-progress.jsonl"
        )
    record = json.loads(result.stdout)
    write(output / "health.json", {"evaluator_image": image, **record})
    if require_all:
        result.check_returncode()
        if not record["healthy"]:
            raise RuntimeError("health failed before scanner admission")
    return record


def measure(
    protocol,
    reports,
    artifacts,
    candidate,
    frozen_candidate,
    manifest_hash,
    *,
    oracle=None,
    curator_ref=None,
):
    if oracle is None:
        oracle = json.loads((ROOT / "evaluation/holdout/oracle.json").read_text())
    curators = {case["id"]: case.get("curator_ref") for case in oracle}
    legacy = assess(protocol, reports, artifacts)
    rows, failures = [], []
    for case, verdict in zip(protocol["cases"], legacy["cases"], strict=True):
        kind, route = case["family"], case["route"]
        decisions = []
        for ref, artifact in artifacts.get(case["target"], {}).items():
            raw = artifact["payload"].get("data", artifact["payload"])
            if raw.get("kind") != kind or raw.get("route") != route:
                continue
            metadata = artifact["metadata"]
            source = "browser/active.py" if kind in {"xss", "html"} else "checks/active.py"
            if metadata.get("producer") != "reviewed_active_capture" or metadata.get(
                "producer_hash"
            ) != sha(REPO_ROOT / "backend/scopelens" / source):
                continue
            decision = (
                proof(kind, raw.get("captures", []))
                if raw.get("reviewed") and not raw.get("error")
                else None
            )
            decisions.append((ref, decision, raw.get("error")))
        values = {row[1] for row in decisions}
        replayed = bool(decisions) and len(values) == 1 and next(iter(values), None) is not None
        conclusive = replayed and verdict["verdict"] in {"TP", "FP", "TN"}
        row = MeasuredCase(
            id=case["id"],
            family=kind,
            scenario_group=case["scenario_group"],
            target=case["target"],
            check_id=case["check_id"],
            route=route,
            label=case["label"],
            confirmed=verdict["verdict"] in {"TP", "FP"},
            conclusive=conclusive,
            proof_valid=verdict["verdict"] == "TP" and replayed,
            proof_replay_ref=decisions[0][0] if replayed else None,
        )
        rows.append(row)
        if not conclusive or verdict["verdict"] in {"FN", "FP", "A-"}:
            failures.append(
                {
                    **verdict,
                    "captures": [
                        {"ref": ref, "decision": decision, "error": error}
                        for ref, decision, error in decisions
                    ],
                }
            )
    result = qualify(
        QualificationRun(
            partition=protocol["partition"],
            frozen_before_run=protocol["frozen_before_run"],
            contaminated=protocol["contaminated"],
            curator_ref=curator_ref,
            candidate_fingerprint=candidate,
            frozen_candidate_fingerprint=frozen_candidate,
            manifest_sha256=manifest_hash,
            declared_families=("xss", "html", "sql", "redirect", "cors"),
            cases=tuple(row for row in rows if curators.get(row.id)),
        )
    )
    return {
        "qualification": result,
        "qualification_case_ids": [row.id for row in rows if curators.get(row.id)],
        "supplemental_case_ids": [row.id for row in rows if not curators.get(row.id)],
        "labelled_condition_metrics": {
            family: metrics(
                [
                    classify(
                        row.label,
                        confirmed=row.confirmed,
                        conclusive=row.conclusive,
                        proof_valid=row.proof_valid,
                    )
                    for row in rows
                    if row.family == family
                ]
            )
            for family in ("xss", "html", "sql", "redirect", "cors")
        },
        "cases": [r.model_dump() for r in rows],
        "failure_cases": failures,
        "legacy_evaluation": legacy,
    }


def trial(output, repeat, mode, candidate_commit):
    if not has_helper_lock():
        if os.environ.get(LOCK_TOKEN_ENV):
            raise RuntimeError("Inherited helper ownership token is invalid")
        locked_cli(
            "evaluation.run_holdout",
            [
                "--output",
                str(output),
                "--repeat",
                str(repeat),
                "--mode",
                mode,
                "--candidate-commit",
                candidate_commit,
                "--trial-only",
            ],
        )
        return json.loads((output / "result.json").read_text())
    output.mkdir(parents=True, exist_ok=False)
    protocol_path = ROOT / "evaluation/protocols/active-holdout.yaml"
    protocol = Protocol.model_validate(yaml.safe_load(protocol_path.read_text())).model_dump()
    oracle = json.loads((ROOT / "evaluation/holdout/oracle.json").read_text())
    with stack_lock():
        reset_receipt = reset()
        write(output / "reset.json", {"receipt": reset_receipt})
        # Health is predeclared and runs before any scanner access. Its answers never
        # enter scopes, scan inputs, worker environments or broker-facing endpoints.
        record = health(output)
        if {c["id"] for c in record["cases"]} != {c["id"] for c in protocol["cases"]}:
            raise RuntimeError("health receipt omitted a reserved case")
        images, before = deployed_images(), source_fingerprint()
        named_source = candidate_source_fingerprint(candidate_commit)
        tracked_runtime_source = candidate_source_fingerprint(candidate_commit, runtime=True)
        release = json.loads((ROOT / "runs/release/freeze.json").read_text())
        if release["source_fingerprint"] != before or tracked_runtime_source != named_source:
            raise RuntimeError(
                "Named committed candidate, evaluator runtime source and deployed release freeze differ; no scanner exposure allowed"
            )
        expected_api = release["images"]["SCOPELENS_RELEASE_API_IMAGE"]
        if any(
            value != expected_api
            for name, value in images.items()
            if any(role in name for role in ["-api-", "-dispatcher-", "-supervisor-"])
        ):
            raise RuntimeError("API/coordinator images differ from release freeze")
        fingerprint = hashlib.sha256(
            json.dumps({"images": images, "source": before}, sort_keys=True).encode()
        ).hexdigest()
        settings = Settings()
        write(
            output / "curation.json",
            {
                "curator_credit": "Upstream ground-truth artifacts only; this evaluator lane supplies no independent curator credit",
                "cases": {case["id"]: case.get("curator_ref") for case in oracle},
                "supplemental": "Private and derived HTML labels are measured but excluded from independent qualification",
            },
        )
        curator_ref = "curation.json#sha256=" + sha(output / "curation.json")
        freeze = {
            "created_at": datetime.now(UTC).isoformat(),
            "repeat": repeat,
            "mode": mode,
            "candidate_fingerprint": fingerprint,
            "candidate_commit": candidate_commit,
            "evaluator_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "evaluator_root": str(ROOT),
            "runtime_root": str(REPO_ROOT),
            "stack_lock_helper_sha256": sha(LOCK_HELPER),
            "release_freeze": release,
            "images": images,
            "source_fingerprint": before,
            "named_candidate_source_fingerprint": named_source,
            "tracked_runtime_source_fingerprint": tracked_runtime_source,
            "model_routing": {
                role: routing(getattr(settings, role))
                for role in [
                    "planner_model",
                    "browser_model",
                    "verification_model",
                    "report_writer_model",
                ]
            },
            "model_call_ceiling": settings.model_max_calls,
            "model_cost_ceiling": settings.model_cost_ceiling,
            "evaluator_sha256": {
                str(p.relative_to(ROOT)): sha(p)
                for p in [
                    Path(__file__),
                    ROOT / "evaluation/holdout_lab.py",
                    ROOT / "evaluation/run.py",
                    ROOT / "evaluation/metrics.py",
                    ROOT / "evaluation/expansion.py",
                    ROOT / "evaluation/holdout_health.py",
                    ROOT / "evaluation/holdout_schedule.py",
                    ROOT / "evaluation/holdout_api.py",
                ]
            },
            "manifest_sha256": sha(protocol_path),
            "oracle_sha256": sha(ROOT / "evaluation/holdout/oracle.json"),
            "fixture_artifacts": {
                str(p.relative_to(ROOT)): sha(p)
                for p in [
                    ROOT
                    / "runs/holdout-benchmark/sources/vulnerableapp/build/libs/VulnerableApp-1.0.0.jar",
                    ROOT / "runs/holdout-benchmark/sources/wavsep/target/wavsep.war",
                    ROOT / "runs/holdout-benchmark/sources/benchmarkjava/target/benchmark.war",
                ]
            },
            "fixture_configuration_sha256": {
                str(p.relative_to(ROOT)): sha(p)
                for p in [
                    ROOT / "labs/holdout.compose.yml",
                    ROOT / "evaluation/holdout/source-lock.json",
                    *sorted((ROOT / "labs/holdout").glob("*.py")),
                    *sorted((ROOT / "labs/holdout").glob("routes-*.json")),
                    ROOT / "labs/holdout/benchmark-start.sh",
                    ROOT / "labs/holdout/benchmark-server.xml",
                ]
            },
            "curator_ref": curator_ref,
            "limitations": [
                "Runtime image IDs and host source hashes are local custody records, not source attestation for already running processes.",
                "Public benchmark knowledge may exist in model training; private and derived labels have no upstream curator credit.",
            ],
        }
        write(output / "freeze.json", freeze)
        reports, artifacts, scans = {}, {}, {}
        with httpx.Client(
            base_url="http://127.0.0.1:8090",
            timeout=30,
            follow_redirects=False,
            event_hooks={"response": [lambda response: save_http_error(response, output)]},
        ) as client:
            client.post(
                "/api/auth/login",
                json={
                    "username": settings.operator_username,
                    "password": settings.operator_password.get_secret_value(),
                },
            ).raise_for_status()
            for target in sorted({c["target"] for c in protocol["cases"]}):
                request = scope_request(target, datetime.now(UTC) + timedelta(hours=3))
                scope_receipt = scope_wall_receipt(request)
                write(output / f"{target}-scope-wall-change.json", scope_receipt)
                response = client.post(
                    "/api/scopes",
                    json=request,
                )
                response.raise_for_status()
                scope = response.json()
                response = create_scan(client, scope["id"], mode == "adaptive")
                scan_id = response.json()["id"]
                write(output / f"{target}-scan.json", {"scan_id": scan_id, "scope": scope})
                print(f"repeat {repeat} {mode} {target} scan {scan_id}", flush=True)
                deadline = time.monotonic() + scope_receipt["runner_deadline_seconds"]
                while time.monotonic() < deadline:
                    response = client.get(f"/api/scans/{scan_id}")
                    response.raise_for_status()
                    state = response.json()
                    if state["status"] in {"completed", "completed_partial", "failed", "cancelled"}:
                        break
                    time.sleep(2)
                else:
                    client.post(f"/api/scans/{scan_id}/cancel").raise_for_status()
                    raise RuntimeError("declared wall-clock exceeded; cancellation requested")
                scans[target] = state
                for fmt in ["json", "html"]:
                    response = client.get(f"/api/scans/{scan_id}/export.{fmt}")
                    response.raise_for_status()
                    path = output / f"{target}-export.{fmt}"
                    path.write_text(response.text)
                    os.chmod(path, 0o600)
                    if fmt == "json":
                        reports[target] = response.json()
                artifacts[target] = fetch_evidence(client, scan_id)
                write(output / f"{target}-evidence.json", artifacts[target])
                print(f"{target} terminal {state['status']}", flush=True)
        changed = (
            before != source_fingerprint()
            or sha(LOCK_HELPER) != freeze["stack_lock_helper_sha256"]
            or images != deployed_images()
            or sha(protocol_path) != freeze["manifest_sha256"]
            or sha(ROOT / "evaluation/holdout/oracle.json") != freeze["oracle_sha256"]
            or any(sha(ROOT / path) != value for path, value in freeze["evaluator_sha256"].items())
            or any(
                sha(ROOT / path) != value
                for path, value in freeze["fixture_configuration_sha256"].items()
            )
        )
        measured_candidate = "changed-during-run" if changed else fingerprint
        result = measure(
            protocol,
            reports,
            artifacts,
            measured_candidate,
            fingerprint,
            freeze["manifest_sha256"],
            oracle=oracle,
            curator_ref=curator_ref,
        )
        result.update(freeze=freeze, scans=scans, candidate_changed=changed)
        matched = {(c["target"], c["check_id"], c["route"]) for c in protocol["cases"]}
        result["unmatched_findings"] = [
            {
                "target": target,
                "finding": finding,
                "adjudication": "unresolved; outside frozen named cases; excluded from accuracy",
            }
            for target, report in reports.items()
            for finding in report.get("findings", [])
            if not any(
                (target, finding["check_id"], location["route"]) in matched
                for location in finding.get("locations", [])
            )
        ]
        write(output / "result.json", result)
        print(json.dumps(result["qualification"], indent=2), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat", type=int, choices=[1, 2, 3])
    parser.add_argument("--mode", choices=["baseline", "adaptive"])
    parser.add_argument("--trial-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--candidate-commit",
        help="Exact commit named by the orchestrator for the frozen deployment",
    )
    parser.add_argument(
        "--admit-only",
        action="store_true",
        help="Pre-scan independent candidate health; no API scans",
    )
    args = parser.parse_args()
    if not args.admit_only and not args.candidate_commit:
        parser.error("Scanner trials require --candidate-commit for the named frozen deployment")
    if args.candidate_commit:
        actual_commit = subprocess.check_output(
            ["git", "rev-parse", args.candidate_commit + "^{commit}"], text=True
        ).strip()
        if actual_commit != args.candidate_commit:
            parser.error("--candidate-commit must be the complete commit hash")
    if bool(args.repeat) != bool(args.mode):
        parser.error("--repeat and --mode must be supplied together")
    if args.trial_only:
        if not args.repeat or args.admit_only:
            parser.error("--trial-only requires one scanner trial")
        trial(args.output, args.repeat, args.mode, args.candidate_commit)
        return
    if args.admit_only and not has_helper_lock():
        if os.environ.get(LOCK_TOKEN_ENV):
            raise RuntimeError("Inherited helper ownership token is invalid")
        locked_cli("evaluation.run_holdout", sys.argv[1:])
        return
    if not args.admit_only and os.environ.get(LOCK_TOKEN_ENV):
        parser.error(
            "Run the outer schedule without inherited stack-lock ownership; each trial acquires separately"
        )
    args.output.mkdir(parents=True, exist_ok=False)
    if args.admit_only:
        if args.repeat:
            parser.error("--admit-only cannot select a scanner trial")
        with stack_lock():
            write(args.output / "reset.json", {"receipt": reset()})
            write(
                args.output / "candidate-freeze.json",
                {
                    "created_at": datetime.now(UTC).isoformat(),
                    "oracle_sha256": sha(ROOT / "evaluation/holdout/oracle.json"),
                    "protocol_sha256": sha(ROOT / "evaluation/protocols/active-holdout.yaml"),
                    "scanner_exposure": False,
                },
            )
            record = health(args.output, require_all=False)
            print(
                f"Pre-scan admission: {sum(row['admitted'] for row in record['cases'])}/{len(record['cases'])}",
                flush=True,
            )
        return
    write(
        args.output / "schedule.json",
        {
            "random_seed": 20261011,
            "predeclared_trials": PLAN,
            "selected": [args.repeat, args.mode] if args.repeat else "all",
            "repeated_scans_never_increase_case_counts": True,
            "inter_trial_gap_seconds": INTER_TRIAL_GAP_SECONDS,
        },
    )
    run_schedule(
        args.output,
        [(args.repeat, args.mode)] if args.repeat else PLAN,
        args.candidate_commit,
        trial,
    )


if __name__ == "__main__":
    main()
