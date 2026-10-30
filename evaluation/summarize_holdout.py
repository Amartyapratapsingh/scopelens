"""Describe six reserved trials without pooling repeats or inventing missing results."""

import argparse
import hashlib
import json
from pathlib import Path

from evaluation.metrics import classify, metrics
from evaluation.run_holdout import PLAN, write

FAMILIES = ("xss", "html", "sql", "redirect", "cors")
COUNTS = ("TP", "FP", "FN", "TN", "A-")


def summarize(root):
    trials, missing, definitions, freezes = [], [], [], []
    for repeat, mode in PLAN:
        directory = root / f"repeat-{repeat}-{mode}"
        path = directory / "result.json"
        if not path.exists():
            missing.append(str(path.relative_to(root)))
            continue
        result = json.loads(path.read_text())
        freeze = result["freeze"]
        if (freeze["repeat"], freeze["mode"]) != (repeat, mode):
            raise ValueError("Trial identity differs from reserved schedule")
        rows = result["cases"]
        definitions.append(
            sorted(
                (
                    r["id"],
                    r["family"],
                    r["scenario_group"],
                    r["target"],
                    r["check_id"],
                    r["route"],
                    r["label"],
                )
                for r in rows
            )
        )
        freezes.append(
            {
                key: freeze[key]
                for key in (
                    "candidate_commit",
                    "evaluator_commit",
                    "stack_lock_helper_sha256",
                    "candidate_fingerprint",
                    "manifest_sha256",
                    "oracle_sha256",
                    "model_routing",
                    "model_call_ceiling",
                    "model_cost_ceiling",
                    "fixture_artifacts",
                    "fixture_configuration_sha256",
                    "evaluator_sha256",
                )
            }
        )
        families = {}
        for family in FAMILIES:
            qualified = dict(result["qualification"]["families"][family])
            qualified["counts"] = {key: qualified["counts"].get(key, 0) for key in COUNTS}
            supplemental = metrics(
                [
                    classify(
                        r["label"],
                        confirmed=r["confirmed"],
                        conclusive=r["conclusive"],
                        proof_valid=r["proof_valid"],
                    )
                    for r in rows
                    if r["family"] == family and r["id"] in result["supplemental_case_ids"]
                ]
            )
            supplemental["counts"] = {key: supplemental["counts"].get(key, 0) for key in COUNTS}
            full = dict(result["labelled_condition_metrics"][family])
            full["counts"] = {key: full["counts"].get(key, 0) for key in COUNTS}
            families[family] = {
                "independent": qualified,
                "supplemental": supplemental,
                "all_labelled_conditions": full,
            }
        scans = []
        for target, scan in sorted(result["scans"].items()):
            scans.append(
                {
                    "target": target,
                    "scan_id": scan["id"],
                    "status": scan["status"],
                    "status_reason": scan["status_reason"],
                    "started_at": scan["started_at"],
                    "finished_at": scan["finished_at"],
                    "budget_spent": scan["budget_spent"],
                }
            )
        trials.append(
            {
                "repeat": repeat,
                "mode": mode,
                "result_path": str(path.relative_to(root)),
                "result_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "candidate_commit": freeze["candidate_commit"],
                "evaluator_commit": freeze["evaluator_commit"],
                "candidate_changed": result["candidate_changed"],
                "families": families,
                "scans": scans,
                "failure_cases": result["failure_cases"],
                "unmatched_findings": result["unmatched_findings"],
            }
        )
    comparable = (
        bool(trials)
        and all(d == definitions[0] for d in definitions)
        and all(f == freezes[0] for f in freezes)
    )
    stable = bool(trials) and all(not t["candidate_changed"] for t in trials)
    complete = not missing and len(trials) == len(PLAN)
    qualified = [
        f
        for f in FAMILIES
        if complete
        and comparable
        and stable
        and all(t["families"][f]["independent"]["qualified"] for t in trials)
    ]
    variability = {}
    for mode in ("baseline", "adaptive"):
        mode_trials = [t for t in trials if t["mode"] == mode]
        variability[mode] = {
            family: {
                key: [t["families"][family]["independent"]["counts"][key] for t in mode_trials]
                for key in COUNTS
            }
            for family in FAMILIES
        }
    return {
        "version": "holdout-summary-v1",
        "schedule": PLAN,
        "complete": complete,
        "missing_trials": missing,
        "same_frozen_candidate_and_cases": comparable,
        "candidate_stable_in_all_trials": stable,
        "qualified_families_in_all_trials": qualified,
        "passed": complete and comparable and stable and len(qualified) == len(FAMILIES),
        "trials": trials,
        "per_mode_repeat_counts": variability,
        "limitations": [
            "Repeated trials never increase case denominators; XSS/HTML overlap is not pooled.",
            "Trial results retain Wilson 95% intervals and evaluator qualification reasons.",
            "Model cost is not exposed in the terminal scan API; equal-cost effectiveness is unmeasured.",
            "Missing trials or inconsistent freezes prevent aggregate qualification.",
        ],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write(args.output, summarize(args.input))


if __name__ == "__main__":
    main()
