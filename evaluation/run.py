"""Offline evaluator and equal-budget API runner. Labels never enter the application."""

import argparse
import hashlib
import json
import time
from pathlib import Path

import httpx
import yaml

from evaluation.metrics import evaluate
from evaluation.protocol import Protocol
from scopelens.checks.active import DEFINITIONS, proof
from scopelens.config import Settings


def source_fingerprint():
    paths = [Path("uv.lock"), Path("pyproject.toml")]
    for root in ["backend", "workers", "checks_registry", "skills", "deploy"]:
        paths.extend(
            p for p in Path(root).rglob("*") if p.is_file() and "__pycache__" not in str(p)
        )
    return hashlib.sha256(
        "\n".join(
            str(p) + ":" + hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)
        ).encode()
    ).hexdigest()


def fetch_evidence(client, scan_id):
    records = client.get(f"/api/scans/{scan_id}/evidence")
    records.raise_for_status()
    result = {}
    for item in records.json():
        if not item["trusted"] or item["truncated"]:
            continue
        response = client.get(f"/api/scans/{scan_id}/evidence/{item['id']}/download")
        if (
            response.status_code != 200
            or hashlib.sha256(response.content).hexdigest() != item["content_hash"]
        ):
            continue
        try:
            result[item["id"]] = {"metadata": item, "payload": response.json()}
        except ValueError:
            continue
    return result


def replay(report, artifacts):
    """Proof replay on hash-checked artifacts, without accepting a finding's own verdict."""
    valid = []
    ids = {d[0]: kind for kind, d in DEFINITIONS.items()}
    for finding in report.get("findings", []):
        kind = ids.get(finding["check_id"])
        if kind is None:
            continue  # Other families need a registered evaluator, never automatic credit.
        for ref in finding.get("evidence_refs", []):
            payload = artifacts.get(ref, {}).get("payload", {})
            data = payload.get("data", payload)
            if (
                data.get("kind") == kind
                and data.get("reviewed")
                and not data.get("error")
                and proof(kind, data.get("captures", [])) is True
            ):
                valid.append(
                    {"check_id": finding["check_id"], "route": data["route"], "evidence_ref": ref}
                )
    return valid


def release_gate(manifest, result):
    reasons = []
    if manifest["partition"] != "holdout":
        reasons.append("development/validation data cannot satisfy the holdout gate")
    if not manifest.get("frozen_before_run") or manifest.get("contaminated", False):
        reasons.append("untouched frozen split not established")
    for family, measured in result["families"].items():
        cases = [c for c in manifest["cases"] if c["family"] == family]
        positives = sum(c["label"] == "vulnerable" for c in cases)
        negatives = len(cases) - positives
        groups = {c["scenario_group"] for c in cases}
        if positives < 30 or negatives < 60 or len(groups) < 3:
            reasons.append(
                f"{family}: insufficient independent cases ({positives} positive, {negatives} negative, {len(groups)} groups)"
            )
        for key, threshold in [
            ("recall", 0.9),
            ("precision", 0.95),
            ("negative_conclusive_coverage", 0.9),
        ]:
            value = measured[key]["value"]
            if value is None or value < threshold:
                reasons.append(f"{family}: {key} target not met")
        value = measured["false_positive_rate"]["value"]
        if value is None or value > 0.05:
            reasons.append(f"{family}: false-positive target not met")
    if not result["families"]:
        reasons.append("no qualified cases")
    return {"passed": not reasons, "reasons": reasons}


def assess(manifest, reports, artifacts):
    verified = {name: replay(report, artifacts.get(name, {})) for name, report in reports.items()}
    result = evaluate(manifest, reports, verified=verified)
    result["release_gate"] = release_gate(manifest, result)
    result["source_fingerprint"] = source_fingerprint()
    return result


def run_pair(client, scope_id, output, timeout=600):
    """Same immutable scope/budgets, baseline before adaptive; no labels in requests."""
    before = source_fingerprint()
    results = {}
    for mode in ["baseline", "adaptive"]:
        response = client.post(
            "/api/scans", json={"scope_version_id": scope_id, "adaptive": mode == "adaptive"}
        )
        response.raise_for_status()
        scan_id = response.json()["id"]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = client.get(f"/api/scans/{scan_id}").json()
            if state["status"] in {"completed", "completed_partial", "cancelled", "failed"}:
                break
            time.sleep(2)
        else:
            client.post(f"/api/scans/{scan_id}/cancel").raise_for_status()
            raise RuntimeError("comparison timed out; cancellation requested")
        response = client.get(f"/api/scans/{scan_id}/export.json")
        response.raise_for_status()
        report = response.json()
        (output / f"{mode}.json").write_text(json.dumps(report, indent=2))
        results[mode] = {
            "scan_id": scan_id,
            "status": state["status"],
            "budget_spent": state["budget_spent"],
            "confirmed_findings": sum(
                f["evidence_status"] == "confirmed" for f in report["findings"]
            ),
            "hypotheses": report["assessment_plan"].get("hypotheses", []),
            "model_calls": report["assessment_plan"].get("model_calls", []),
        }
    if source_fingerprint() != before:
        raise RuntimeError("source changed during comparison; results disqualified")
    return {
        "version": "comparison-v1",
        "scope_id": scope_id,
        "source_fingerprint": before,
        "runs": results,
        "claim": "One development pair. Corroboration and extra cost are measured; no statistical improvement claim.",
        "reset": "Read-only, stateless fixtures only; stateful targets require an external reset between runs.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope-id")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--reports", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    settings = Settings()
    with httpx.Client(base_url="http://127.0.0.1:8090", timeout=20) as client:
        client.post(
            "/api/auth/login",
            json={
                "username": settings.operator_username,
                "password": settings.operator_password.get_secret_value(),
            },
        ).raise_for_status()
        if args.scope_id:
            result = run_pair(client, args.scope_id, args.output)
        else:
            manifest = Protocol.model_validate(
                yaml.safe_load(args.manifest.read_text())
            ).model_dump()
            reports, evidence = {}, {}
            for target in {c["target"] for c in manifest["cases"]}:
                reports[target] = json.loads((args.reports / f"{target}-export.json").read_text())
                evidence[target] = fetch_evidence(client, reports[target]["scan"]["id"])
            result = assess(manifest, reports, evidence)
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result.get("release_gate", {"comparison": "recorded"})))


if __name__ == "__main__":
    main()
