"""Attribute saved c208c00 error responses without requests or rescoring."""

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path

RUNTIME_COMMIT = "c208c009e01a45df4abbb8bb7bb6f2259492d30b"
DENIAL_BODY = {
    "error": "scope_denied",
    "reason": "budget_exhausted",
    "detail": "shared page cap reached",
}
DENIAL_HASH = hashlib.sha256(json.dumps(DENIAL_BODY).encode()).hexdigest()


def attributed_responses(failure, artifacts):
    """Only accepted capture references can establish a response attribution."""
    confirmed, unresolved = [], []
    for capture in failure.get("captures", []):
        ref = capture["ref"]
        artifact = artifacts.get(ref)
        if artifact is None:
            continue
        data = artifact["payload"].get("data", artifact["payload"])
        for response in data.get("captures", []):
            if response.get("status") != 403:
                continue
            record = {"evidence_ref": ref, "capture_name": response.get("name")}
            if response.get("body_hash") == DENIAL_HASH:
                confirmed.append(record)
            else:
                unresolved.append(record)
    return confirmed, unresolved


def analyze(directory):
    inputs = {"result.json": (directory / "result.json").read_bytes()}
    result = json.loads(inputs["result.json"])
    if result["freeze"]["candidate_commit"] != RUNTIME_COMMIT:
        raise ValueError("Denial body interpretation is bound to the frozen c208c00 source")
    artifacts = {}
    for target in {c["target"] for c in result["cases"]}:
        name = f"{target}-evidence.json"
        inputs[name] = (directory / name).read_bytes()
        artifacts[target] = json.loads(inputs[name])
    cases = {c["id"]: c for c in result["cases"]}
    qualified = set(result["qualification_case_ids"])
    records = []
    for failure in result["failure_cases"]:
        case = cases[failure["id"]]
        confirmed, unresolved = attributed_responses(failure, artifacts[case["target"]])
        records.append(
            {
                "id": case["id"],
                "family": case["family"],
                "target": case["target"],
                "verdict": failure["verdict"],
                "independently_curated": case["id"] in qualified,
                "body_hash_confirmed_page_cap_denials": confirmed,
                "http403_with_unresolved_origin": unresolved,
            }
        )
    counts = {}
    for population in ("all", "independent", "supplemental"):
        rows = [
            r
            for r in records
            if population == "all" or r["independently_curated"] == (population == "independent")
        ]
        counts[population] = {
            family: {
                verdict: {
                    key: sum(
                        r["family"] == family and r["verdict"] == verdict and bool(r[key])
                        for r in rows
                    )
                    for key in (
                        "body_hash_confirmed_page_cap_denials",
                        "http403_with_unresolved_origin",
                    )
                }
                for verdict in ("FN", "A-")
            }
            for family in ("xss", "html", "sql", "redirect", "cors")
        }
    return {
        "trial": {k: result["freeze"][k] for k in ("repeat", "mode", "candidate_commit")},
        "counts": counts,
        "records": records,
        "confirmed_response_counts": dict(
            Counter(r["family"] for r in records for _ in r["body_hash_confirmed_page_cap_denials"])
        ),
        "source_denial_body": DENIAL_BODY,
        "source_denial_body_sha256": DENIAL_HASH,
        "source_paths": [
            "backend/scopelens/broker/policy.py",
            "backend/scopelens/broker/mitm_addon.py",
        ],
        "input_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()},
        "limitations": [
            "Saved-output analysis only; no target requests, rescoring or scanner changes.",
            "A matching retained response hash establishes the broker's exact page-cap denial body.",
            "HTTP403 without that body hash has unresolved origin; shared status is not proof.",
            "c208c00 exception denials lose scan_id and are absent from broker.admit audit rows.",
            "A case can contain both proven and unattributed refusals; counts are not disjoint.",
            "These authority failures constrain end-to-end evaluation, not conditional detector accuracy.",
        ],
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
