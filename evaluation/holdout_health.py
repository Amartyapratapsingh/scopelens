"""Independent named-condition oracle. Only mounted in the evaluator container."""

import json
import sys
from urllib.parse import urlencode

import httpx
from playwright.sync_api import sync_playwright

ORIGINS = {
    "labs-holdout-a": "http://172.28.0.30:8080",
    "labs-holdout-b": "http://172.28.0.31:8080",
    "labs-holdout-c": "http://172.28.0.32:8080",
    "labs-holdout-d": "http://172.28.0.33:8080",
}


def main():
    cases = json.load(sys.stdin)
    results, isolation, metadata_isolation = [], [], []
    with httpx.Client(trust_env=False, timeout=25, follow_redirects=False) as http:
        for target, origin in ORIGINS.items():
            http.get(origin + "/healthz").raise_for_status()
            for path in [
                "/scanner/dast",
                "/scanner/sast",
                "/VulnerableApp/scanner/dast",
                "/VulnerableApp/scanner/benchmark",
                "/wavsep/wavsep-install/install.jsp",
                "/oracle.json",
                "/answers",
                "/%2e%2e/scanner/dast",
                "/r/unknown",
                "/r/unknown?path=/scanner/dast",
            ]:
                response = http.get(origin + path)
                assert response.status_code == 404, (target, path, response.status_code)
                isolation.append({"target": target, "path": path, "status": response.status_code})
        with sync_playwright() as pw:
            browser = pw.chromium.launch(chromium_sandbox=True)
            for case in cases:
                url = ORIGINS[case["target"]] + case["route"]
                family, parameter, baseline = case["family"], case["parameter"], case["baseline"]
                observed, statuses, error = None, [], None
                context = None
                try:
                    response = http.get(url, params={parameter: baseline})
                    exposed = response.text + "\n" + "\n".join(response.headers.values())
                    for native in [
                        case["upstream_path"],
                        "BenchmarkTest",
                        "/benchmark",
                        "/wavsep",
                        "/VulnerableApp",
                    ]:
                        if native in exposed:
                            raise AssertionError("upstream identity leaked")
                    if "server" in response.headers or "x-powered-by" in response.headers:
                        raise AssertionError("upstream technology banner leaked")
                    metadata_isolation.append({"id": case["id"], "baseline_identity_leak": False})
                    if family == "redirect":
                        assert response.status_code in {200, 302, 400}, case["id"]
                    else:
                        response.raise_for_status()
                    statuses = [response.status_code]
                    if family in {"xss", "html"}:
                        payload = (
                            "<script>document.documentElement.dataset.oracle='executed'</script>"
                            if family == "xss"
                            else '<mark data-independent-oracle="present">test</mark>'
                        )
                        context = browser.new_context()
                        context.route(
                            "**/*",
                            lambda route, _request, target_origin=ORIGINS[case["target"]]: (
                                route.continue_()
                                if route.request.url.startswith(target_origin + "/")
                                else route.abort()
                            ),
                        )
                        page = context.new_page()
                        navigation = page.goto(
                            url + "?" + urlencode({parameter: payload}),
                            wait_until="domcontentloaded",
                            timeout=5000,
                        )
                        assert navigation.status == 200, case["id"]
                        observed = (
                            page.evaluate("document.documentElement.dataset.oracle === 'executed'")
                            if family == "xss"
                            else page.locator('[data-independent-oracle="present"]').count() == 1
                        )
                    elif family == "sql":
                        quote = case["sql_quote"]
                        probes = [
                            baseline,
                            "0" if baseline == "1" else "missing-entry",
                            baseline + quote + " AND 7=7" + (" -- " if quote else ""),
                            baseline + quote + " AND 7=8" + (" -- " if quote else ""),
                        ]
                        responses = [http.get(url, params={parameter: value}) for value in probes]
                        statuses = [r.status_code for r in responses]
                        observed = (
                            statuses[0] == statuses[2] == 200
                            and responses[0].text == responses[2].text
                            and responses[0].text != responses[3].text
                            and responses[1].text != responses[0].text
                        )
                    elif family == "redirect":
                        foreign = "https://independent-oracle.invalid/destination"
                        result = http.get(url, params={parameter: foreign})
                        statuses.append(result.status_code)
                        observed = (
                            result.status_code in {301, 302, 303, 307, 308}
                            and result.headers.get("location") == foreign
                        )
                    else:
                        foreign = "https://independent-oracle.invalid"
                        result = http.get(url, headers={"Origin": foreign})
                        statuses.append(result.status_code)
                        observed = (
                            result.headers.get("access-control-allow-origin") == foreign
                            and result.headers.get("access-control-allow-credentials") == "true"
                        )
                except Exception as exc:  # noqa: BLE001 - preserve every pre-run admission failure
                    error = type(exc).__name__
                finally:
                    if context:
                        context.close()
                results.append(
                    {
                        "id": case["id"],
                        "family": family,
                        "route": case["route"],
                        "condition_present": observed,
                        "expected_present": case["label"] == "vulnerable",
                        "statuses": statuses,
                        "admitted": error is None and observed == (case["label"] == "vulnerable"),
                        "error": error,
                        "source_sha256": case["source_sha256"],
                    }
                )
                print(json.dumps(results[-1]), file=sys.stderr, flush=True)
            browser.close()
    print(
        json.dumps(
            {
                "healthy": all(r["admitted"] for r in results),
                "cases": results,
                "isolation": isolation,
                "metadata_isolation": metadata_isolation,
            }
        )
    )
    if not all(r["admitted"] for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
