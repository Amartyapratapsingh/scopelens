"""Explain saved misses without target requests or changes to qualification."""

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from evaluation.metrics import classify

STAGES = {
    "a": "No named route observed in retained crawl or browser discovery",
    "b": "Named route discovered; no matching probe in the retained plan or captures",
    "c": "Attested probe capture records a blocked/error HTTP response or execution error",
    "d": "Attested probe responses exist; no accepted case confirmation",
    "unresolved": "Retained outputs do not establish the dispatch/reach stage",
}
FAMILIES = ("xss", "html", "sql", "redirect", "cors")


def route(value):
    if not isinstance(value, str):
        return None
    return urlsplit(value).path if value.startswith(("/", "http://", "https://")) else None


def observed(report, artifacts):
    routes = set()
    surface = report.get("attack_surface") or {}
    for key in ("endpoints", "parameters", "forms"):
        for item in surface.get(key, []):
            if isinstance(item, dict):
                routes.update(
                    filter(None, (route(item.get(k)) for k in ("route", "url", "action")))
                )
    for artifact in artifacts.values():
        data = artifact["payload"].get("data", artifact["payload"])
        # Active-capture route fields establish dispatch, never crawl discovery.
        if data.get("kind") in FAMILIES:
            continue
        states = data.get("states", [])
        if isinstance(states, list):
            routes.update(route(s.get("url")) for s in states if isinstance(s, dict))
        if "state_hash" in data:
            routes.add(route(data.get("url")))
        state = data.get("state")
        if isinstance(state, dict) and "state_hash" in state:
            routes.add(route(state.get("url")))
        if isinstance(data.get("endpoints"), list):
            routes.update(
                route(e.get("route") or e.get("url"))
                for e in data["endpoints"]
                if isinstance(e, dict)
            )
    return routes - {None}


def reach(case, failure, report, artifacts):
    captured, statuses, errors, decisions = [], [], [], []
    for capture in failure.get("captures", []):
        ref = capture["ref"]
        artifact = artifacts.get(ref)
        if artifact is None:
            continue
        raw = artifact["payload"].get("data", artifact["payload"])
        captured.append(ref)
        decisions.append(capture.get("decision"))
        if capture.get("error") or raw.get("error"):
            errors.append("execution_error")  # Never copy response bodies/error secrets.
        for response in raw.get("captures", []):
            status = response.get("status")
            if isinstance(status, int):
                statuses.append(status)
    details = {
        "evidence_refs": captured,
        "http_statuses": sorted(set(statuses)),
        "proof_decisions": decisions,
        "execution_errors": errors,
        "discovered": case["route"] in observed(report, artifacts),
        "planned": any(
            p.get("kind") == case["family"] and p.get("path") == case["route"]
            for p in (report.get("assessment_plan") or {}).get("conditional_probes", [])
        ),
    }
    if captured:
        if errors or any(status >= 400 for status in statuses):
            return "c", "Blocked/error response; origin of denial is not inferred", details
        if statuses:
            return (
                "d",
                "Responses retained; proof false/inconclusive or report confirmation absent",
                details,
            )
        return (
            "unresolved",
            "Capture exists without retained response status or execution error",
            details,
        )
    if any(
        (data := a["payload"].get("data", a["payload"])).get("kind") == case["family"]
        and data.get("route") == case["route"]
        for a in artifacts.values()
    ):
        return (
            "unresolved",
            "Matching artifact exists but lacks accepted capture provenance",
            details,
        )
    if details["planned"]:
        return "unresolved", "Probe planned, but no attested dispatch capture retained", details
    if details["discovered"]:
        return "b", "Observed route has no matching retained conditional plan or capture", details
    return "a", "Absent from retained bounded discovery and conditional plan", details


def analyze(directory):
    inputs = {"result.json": (directory / "result.json").read_bytes()}
    result = json.loads(inputs["result.json"])
    reports, artifacts = {}, {}
    for target in {c["target"] for c in result["cases"]}:
        for suffix, dest in (("export", reports), ("evidence", artifacts)):
            name = f"{target}-{suffix}.json"
            inputs[name] = (directory / name).read_bytes()
            dest[target] = json.loads(inputs[name])
    failures = {c["id"]: c for c in result["failure_cases"]}
    records = []
    for case in result["cases"]:
        verdict = classify(
            case["label"],
            confirmed=case["confirmed"],
            conclusive=case["conclusive"],
            proof_valid=case["proof_valid"],
        )
        if verdict not in {"FN", "A-"}:
            continue
        stage, reason, details = reach(
            case, failures.get(case["id"], {}), reports[case["target"]], artifacts[case["target"]]
        )
        records.append(
            {
                "id": case["id"],
                "family": case["family"],
                "group": case["scenario_group"],
                "target": case["target"],
                "route": case["route"],
                "verdict": verdict,
                "independently_curated": case["id"] in result["qualification_case_ids"],
                "stage": stage,
                "reason": reason,
                **details,
            }
        )
    counts = {}
    for population in ("independent", "supplemental", "all"):
        rows = [
            r
            for r in records
            if population == "all" or r["independently_curated"] == (population == "independent")
        ]
        counts[population] = {
            family: {
                verdict: {
                    stage: sum(
                        r["family"] == family and r["verdict"] == verdict and r["stage"] == stage
                        for r in rows
                    )
                    for stage in STAGES
                }
                for verdict in ("FN", "A-")
            }
            for family in FAMILIES
        }
    return {
        "trial": {
            k: result["freeze"][k]
            for k in ("repeat", "mode", "candidate_commit", "evaluator_commit")
        },
        "stages": STAGES,
        "counts": counts,
        "records": records,
        "examples": {stage: [r for r in records if r["stage"] == stage][:3] for stage in STAGES},
        "input_sha256": {p: hashlib.sha256(data).hexdigest() for p, data in inputs.items()},
        "limitations": [
            "Analysis uses saved outputs only, with no requests, reruns or proof-rule changes.",
            "Stage a describes retained bounded discovery, not all application routes.",
            "Missing dispatch evidence for a planned probe remains unresolved, not assumed untested.",
            "HTTP error responses do not identify broker versus gateway versus upstream without further evidence.",
            "Stage d includes false and inconclusive proof decisions and absent report confirmation; it does not claim complete negative testing.",
        ],
        "miss_counts": dict(Counter(r["verdict"] for r in records)),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.input)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
