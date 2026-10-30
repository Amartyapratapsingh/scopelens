"""Evaluator-only source selection. Never import this module into runtime code."""

import argparse
import csv
import hashlib
import json
import os
import re
from pathlib import Path

import yaml

from evaluation.manifest import EvaluationManifest
from evaluation.protocol import Protocol

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "runs/holdout-benchmark/sources"
LOCK = json.loads((ROOT / "evaluation/holdout/source-lock.json").read_text())
CONTROLS = {
    "xss": "SL-C03-XSS-01",
    "html": "SL-C03-HTML-01",
    "sql": "SL-C03-SQL-01",
    "redirect": "SL-C04-REDIRECT-01",
    "cors": "SL-C04-CORS-01",
}


def selection():
    cases = []

    def add(source, families, endpoint, label, parameter, baseline, evidence_path, **extra):
        for family in families:
            cases.append(
                dict(
                    source=source,
                    family=family,
                    upstream_path=endpoint,
                    label=label,
                    parameter=parameter,
                    baseline=baseline,
                    evidence_path=evidence_path,
                    **extra,
                )
            )

    java = "src/main/java/org/sasanlabs/service/vulnerability/"
    for level, label in [(1, "vulnerable"), (4, "fixed"), (5, "fixed")]:
        add(
            "vulnerableapp",
            ["xss", "html"],
            f"/VulnerableApp/XSSWithHtmlTagInjection/LEVEL_{level}",
            label,
            "value",
            "hello",
            java + "xss/reflected/XSSWithHtmlTagInjection.java",
        )
    for level, label in [
        (1, "vulnerable"),
        (2, "vulnerable"),
        (3, "fixed"),
        (4, "fixed"),
        (5, "fixed"),
    ]:
        add(
            "vulnerableapp",
            ["sql"],
            f"/VulnerableApp/BlindSQLInjectionVulnerability/LEVEL_{level}",
            label,
            "id",
            "1",
            java + "sqlInjection/BlindSQLInjectionVulnerability.java",
            sql_quote="" if level in {1, 4, 5} else "'",
        )
    for level, label in [
        (1, "vulnerable"),
        (2, "vulnerable"),
        (8, "fixed"),
        (11, "fixed"),
        (12, "fixed"),
    ]:
        add(
            "vulnerableapp",
            ["redirect"],
            f"/VulnerableApp/Http3xxStatusCodeBasedInjection/LEVEL_{level}",
            label,
            "returnTo",
            "/",
            java + "openRedirect/Http3xxStatusCodeBasedInjection.java",
        )
    wave = "WebContent/active/"
    for directory, filename, label in [
        (
            "Reflected-XSS/RXSS-Detection-Evaluation-GET",
            "Case01-Tag2HtmlPageScope.jsp",
            "vulnerable",
        ),
        (
            "Reflected-XSS/RXSS-FalsePositives-GET",
            "Case07-AngleBracketsEncodingInBody.jsp",
            "fixed",
        ),
    ]:
        path = wave + directory + "/" + filename
        add(
            "wavsep",
            ["xss", "html"],
            "/wavsep/" + path.removeprefix("WebContent/"),
            label,
            "userinput",
            "hello",
            path,
        )
    for directory, filename, label in [
        (
            "SQL-Injection/SInjection-Detection-Evaluation-GET-200Valid",
            "Case03-InjectionInCalc-String-BooleanExploit-WithDifferent200Responses.jsp",
            "vulnerable",
        ),
        (
            "SQL-Injection/SInjection-FalsePositives-GET",
            "Case05-FalsePositiveInjectionInLogin-PsAndIv-Different200ValidOnIvFailure.jsp",
            "fixed",
        ),
    ]:
        path = wave + directory + "/" + filename
        add(
            "wavsep",
            ["sql"],
            "/wavsep/" + path.removeprefix("WebContent/"),
            label,
            "username",
            "user1",
            path,
            sql_quote="'",
            fixed_parameters={"password": "password"},
        )
    for directory, filename, label in [
        (
            "Unvalidated-Redirect/Redirect-Detection-Evaluation-GET-302Redirect",
            "Case01-Redirect-RedirectMethod-FilenameContext-Unrestricted-HttpURL-DefaultFullInput-AnyPathReq-Read.jsp",
            "vulnerable",
        ),
        (
            "Unvalidated-Redirect/Redirect-FalsePositives-GET",
            "Case08-Redirect-FalsePositive-RedirectMethod-FilenameContext-WhiteList-HttpURL-DefaultFullInput-AnyPathReq-Read.jsp",
            "fixed",
        ),
    ]:
        path = wave + directory + "/" + filename
        add(
            "wavsep",
            ["redirect"],
            "/wavsep/" + path.removeprefix("WebContent/"),
            label,
            "target",
            "/",
            path,
        )
    for families, first, second, baseline in [
        (["xss", "html"], "render-raw", "render-text", "hello"),
        (["sql"], "find-sql", "find-param", "pear"),
        (["redirect"], "next-free", "next-local", "/"),
        (["cors"], "cors-echo", "cors-constant", "hello"),
    ]:
        for endpoint, label in [(first, "vulnerable"), (second, "fixed")]:
            add(
                "private",
                families,
                "/" + endpoint,
                label,
                "value",
                baseline,
                "labs/holdout/private.py",
                sql_quote="'",
            )
    benchmark = SOURCES / "benchmarkjava"
    expected = benchmark / "expectedresults-1.2.csv"
    seen = set()
    for row in csv.reader(expected.read_text().splitlines()[1:]):
        name, category, vulnerable, *_ = row
        if category not in {"xss", "sqli"}:
            continue
        source_path = f"src/main/java/org/owasp/benchmark/testcode/{name}.java"
        text = (benchmark / source_path).read_text()
        # Native GET -> POST delegation, query input, no cookie/header adapter.
        # SQL selection excludes writes/procedure calls regardless of CSV label.
        if "doPost(request, response);" not in text or "request.getParameter" not in text:
            continue
        if category == "sqli" and re.search(r"UPDATE |INSERT |DELETE |\{call", text, re.I):
            continue
        family = "sql" if category == "sqli" else "xss"
        label = "vulnerable" if vulnerable == "true" else "fixed"
        # Reserve every distinct native read-only function before scanner exposure.
        # Independent health determines whether this narrower named condition applies.
        canonical = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
        canonical = re.sub(r"BenchmarkTest\d+", "BenchmarkTest", canonical)
        canonical = re.sub(r"/[\w]+-\d+/", "/category/", canonical)
        key = hashlib.sha256(re.sub(r"\s+", "", canonical).encode()).hexdigest()
        if (family, label, key) in seen:
            continue
        seen.add((family, label, key))
        endpoint = re.search(r'@WebServlet\(value = "([^"]+)"', text).group(1)
        add(
            "benchmarkjava",
            [family] if family == "sql" else ["xss", "html"],
            "/benchmark" + endpoint,
            label,
            name,
            "bar" if family == "sql" else "hello",
            source_path,
            sql_quote="'",
            canonical_source_sha256=key,
        )
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--admission",
        type=Path,
        help="Independent pre-scan health receipt; retain admitted cases without relabelling",
    )
    args = parser.parse_args()
    selected = selection()
    admitted, receipt_rows = None, {}
    if args.admission:
        receipt = json.loads(args.admission.read_text())
        expected_ids = {
            f"holdout-{index:03d}-{case['family']}" for index, case in enumerate(selected)
        }
        receipt_rows = {row["id"]: row for row in receipt["cases"]}
        if set(receipt_rows) != expected_ids or len(receipt_rows) != len(receipt["cases"]):
            raise ValueError("Admission must cover every original candidate exactly once")
        for row in receipt_rows.values():
            if row["admitted"] != (
                row["error"] is None and row["condition_present"] == row["expected_present"]
            ):
                raise ValueError("Admission decision inconsistent with independent condition check")
        admitted = {row["id"] for row in receipt["cases"] if row["admitted"]}
    protocols, records, oracle = [], [], []
    maps = {suffix: {} for suffix in "abcd"}
    for index, case in enumerate(selected):
        source = case["source"]
        suffix = {"vulnerableapp": "a", "wavsep": "b", "private": "c", "benchmarkjava": "d"}[source]
        # The hash is an opaque path identifier, not a label or difficulty level.
        route = "/r/" + hashlib.sha256(case["upstream_path"].encode()).hexdigest()[:16]
        target = "labs-holdout-" + suffix
        case_id = f"holdout-{index:03d}-{case['family']}"
        source_path = (
            ROOT / case["evidence_path"]
            if source == "private"
            else SOURCES / source / case["evidence_path"]
        )
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        if receipt_rows:
            row = receipt_rows[case_id]
            if (
                row["source_sha256"] != digest
                or row["expected_present"] != (case["label"] == "vulnerable")
                or row["family"] != case["family"]
            ):
                raise ValueError("Admission source/label differs from reserved candidate")
        if admitted is not None and case_id not in admitted:
            continue
        maps[suffix][route] = {
            k: v
            for k, v in case.items()
            if k in {"upstream_path", "parameter", "baseline", "fixed_parameters"}
        }
        protocols.append(
            dict(
                id=case_id,
                target=target,
                check_id=CONTROLS[case["family"]],
                family=case["family"],
                route=route,
                label=case["label"],
                scenario_group=source,
            )
        )
        public_parameter = "input" if source == "benchmarkjava" else case["parameter"]
        if source == "benchmarkjava":
            maps[suffix][route]["upstream_parameter"] = case["parameter"]
            maps[suffix][route]["parameter"] = public_parameter
        curator = None
        if source != "private" and case["family"] != "html":
            artifact = (
                "expectedresults-1.2.csv" if source == "benchmarkjava" else case["evidence_path"]
            )
            curator = {
                "project": source,
                "revision": LOCK[source]["revision"],
                "path": artifact,
                "sha256": hashlib.sha256((SOURCES / source / artifact).read_bytes()).hexdigest(),
            }
        oracle.append(
            {
                **case,
                **protocols[-1],
                "parameter": public_parameter,
                "source_sha256": digest,
                "curator_ref": curator,
            }
        )
        upstream = LOCK.get(source, {})
        claim = {
            "xss": "Reflected input can execute a same-document script in the HTML response.",
            "html": "Reflected input creates attacker-supplied markup in the HTML response.",
            "sql": "A read-only boolean predicate changes the named public lookup; no timing or row extraction.",
            "redirect": "The response can direct the supplied URL to an unapproved HTTP(S) origin.",
            "cors": "The response reflects arbitrary foreign origins with credentials allowed; no protected-data exposure claim.",
        }[case["family"]]
        records.append(
            dict(
                case=dict(
                    id=case_id,
                    canonical_control=CONTROLS[case["family"]],
                    family=case["family"],
                    route_or_input=route + ":" + public_parameter,
                    expected_label=case["label"],
                    claim_boundary=claim,
                ),
                build=dict(
                    project=source,
                    source_url=upstream.get("url", "local:labs/holdout/private.py"),
                    commit=upstream.get("revision"),
                    dependencies=["evaluation/holdout/source-lock.json"],
                    license=upstream.get("license", "repository license"),
                ),
                lifecycle=dict(
                    seed_method="Pinned source startup seed; WAVSEP evaluator-only installer; private fixture per-request SQLite seed.",
                    reset_method="python -m evaluation.holdout_lab reset; replaces only this disposable stack's containers.",
                    readiness_check="evaluation.holdout_health verifies baseline, named condition and blocked answer-key paths before admission.",
                    cleanup_proof="requires a health receipt from this invocation; not inferred from an earlier run",
                ),
                proof=dict(
                    positive_validation="Source digest + evaluator-only independent behavior oracle; require current health receipt.",
                    negative_validation="Named escaping/parameterization/allowlist implementation and independent behavior oracle; require current health receipt.",
                    permitted_confirmation_method="Frozen registered predicate replay on trusted deployed supervisor captures.",
                    forbidden_side_effects=[
                        "SQL writes",
                        "timing payloads",
                        "data extraction",
                        "following foreign redirects",
                        "external callbacks",
                    ],
                ),
                split=dict(
                    partition="holdout",
                    scenario_group=source,
                    split_version="holdout-v1",
                    exposure_history="Not used to tune scanner controls. Public upstream content may occur in model training; private fixtures authored for this evaluation.",
                    contaminated=False,
                ),
                notes=f"Evaluator source {case['evidence_path']}; SHA256 {digest}. Same upstream implementation and siblings stay in holdout. Curator: {json.dumps(curator)}. Private and derived HTML labels have no upstream curator credit.",
            )
        )
    protocol = Protocol.model_validate(
        dict(
            version="holdout-v1",
            partition="holdout",
            frozen_before_run=True,
            contaminated=False,
            cases=protocols,
        )
    )
    manifest = EvaluationManifest.model_validate(
        dict(
            split_version="holdout-v1",
            created="2026-10-11",
            status="reserved_requires_current_health_and_measurement",
            cases=records,
        )
    )
    (ROOT / "evaluation/protocols/active-holdout.yaml").write_text(
        yaml.safe_dump(protocol.model_dump(), sort_keys=False)
    )
    (ROOT / "evaluation/manifests/holdout.yaml").write_text(
        yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=False)
    )
    (ROOT / "evaluation/holdout/oracle.json").write_text(json.dumps(oracle, indent=2) + "\n")
    for path in [
        "evaluation/protocols/active-holdout.yaml",
        "evaluation/manifests/holdout.yaml",
        "evaluation/holdout/oracle.json",
    ]:
        os.chmod(ROOT / path, 0o600)
    for path in (ROOT / "evaluation/holdout").glob("*.json"):
        os.chmod(path, 0o600)
    for suffix, routes in maps.items():
        (ROOT / f"labs/holdout/routes-{suffix}.json").write_text(
            json.dumps(routes, indent=2) + "\n"
        )
    # Ship ordinary endpoint documentation with the candidate, without labels.
    pack_path = ROOT / "checks_registry/tooling/conditional-pack.json"
    pack = json.loads(pack_path.read_text())
    for suffix in maps:
        target = "labs-holdout-" + suffix
        entries = []
        for case in oracle:
            if case["target"] != target:
                continue
            entry = {"kind": case["family"], "path": case["route"], "parameter": case["parameter"]}
            if case["family"] == "sql":
                entry["baseline_value"] = case["baseline"]
            entries.append(entry)
        pack["lab_services"][target] = entries
    pack_path.write_text(json.dumps(pack, indent=2) + "\n")
    print(f"Reserved {len(protocols)} cases; no qualification or health claim.")


if __name__ == "__main__":
    main()
