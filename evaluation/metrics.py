"""Independent case matching and uncertainty; abstentions never become true negatives."""

import math
from collections import Counter


def wilson(successes, total):
    if not total:
        return None
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [max(0, centre - margin), min(1, centre + margin)]


def ratio(n, d):
    return {
        "value": n / d if d else None,
        "numerator": n,
        "denominator": d,
        "interval_95": wilson(n, d),
    }


def classify(label, *, confirmed, conclusive, proof_valid):
    if label == "vulnerable":
        return "TP" if confirmed and proof_valid else "FN"
    if confirmed:
        return "FP"
    return "TN" if conclusive else "A-"


def metrics(cases):
    counts = Counter(cases)
    tp, fp, fn, tn, abstain = (counts.get(k, 0) for k in ["TP", "FP", "FN", "TN", "A-"])
    return {
        "counts": dict(counts),
        "recall": ratio(tp, tp + fn),
        "precision": ratio(tp, tp + fp),
        "false_positive_rate": ratio(fp, fp + tn),
        "negative_conclusive_coverage": ratio(fp + tn, fp + tn + abstain),
    }


def evaluate(manifest, reports, *, verified=None):
    results = []
    for case in manifest["cases"]:
        report = reports.get(case["target"])
        outcomes = report.get("check_outcomes", []) if report else []
        matching = [o for o in outcomes if o["check_id"] == case["check_id"]]
        outcome = matching[0] if len(matching) == 1 else {}
        findings = [
            f
            for f in (report or {}).get("findings", [])
            if f["check_id"] == case["check_id"]
            and any(loc["route"] == case["route"] for loc in f["locations"])
        ]
        confirmed = any(f["evidence_status"] == "confirmed" for f in findings)
        proof_valid = bool(
            confirmed
            and any(
                v["check_id"] == case["check_id"] and v["route"] == case["route"]
                for v in (verified or {}).get(case["target"], [])
            )
        )
        # Case-level coverage uses the named route, not a category-level percentage.
        conclusive = outcome.get("status") in {"pass", "confirmed_issue"} and case[
            "route"
        ] in outcome.get("completed_instances", [])
        verdict = classify(
            case["label"], confirmed=confirmed, conclusive=conclusive, proof_valid=proof_valid
        )
        results.append(
            {
                "id": case["id"],
                "family": case["family"],
                "verdict": verdict,
                "status": outcome.get("status", "not_tested"),
                "reason": "matched named control and route; hash-checked proof replay"
                if proof_valid
                else "no matched confirmed proof",
            }
        )
    return {
        "version": "evaluator-v1",
        "partition": manifest["partition"],
        "cases": results,
        "aggregate": metrics([r["verdict"] for r in results]),
        "families": {
            f: metrics([r["verdict"] for r in results if r["family"] == f])
            for f in sorted({r["family"] for r in results})
        },
        "limitations": [
            "Small owned-fixture sample; below the proposed 30-positive/60-negative per-family claim minimum.",
            "Independent fixture health checks and scenario qualification must accompany this report.",
            "These results do not measure whole-website security or unknown vulnerability classes.",
        ],
    }
