"""Independent fixture oracle. Run only in an evaluator container, never a worker."""

import json
from urllib.parse import urlencode

import httpx
from playwright.sync_api import sync_playwright


def main():
    origin = "http://172.28.0.15:8080"
    results = []
    with httpx.Client(base_url=origin, trust_env=False, timeout=10) as http:
        http.get("/healthz").raise_for_status()
        # These truth predicates do not import the scanner's probes or proof functions.
        for variant in ["single", "double", "numeric", "bound", "integer", "empty"]:
            quote = '"' if variant == "double" else "'"
            base = "1" if variant in {"numeric", "integer"} else "pear"
            suffix = "" if variant in {"numeric", "integer"} else quote
            true = base + suffix + " AND 7=7" + (" -- " if suffix else "")
            false = base + suffix + " AND 7=8" + (" -- " if suffix else "")
            bodies = [
                http.get(f"/sql/{variant}", params={"q": v}).text for v in [base, true, false]
            ]
            observed = bodies[0] == bodies[1] and bodies[1] != bodies[2]
            expected = variant in {"single", "double", "numeric"}
            assert observed == expected, (variant, bodies)
            results.append({"route": f"/sql/{variant}", "condition_present": observed})
        for variant in ["301", "303", "307", "308", "local", "echo"]:
            r = http.get(f"/redirect/{variant}", params={"next": "https://oracle.invalid/health"})
            observed = (
                r.status_code in {301, 302, 303, 307, 308}
                and r.headers.get("location") == "https://oracle.invalid/health"
            )
            assert observed == variant.isdigit(), variant
            results.append({"route": f"/redirect/{variant}", "condition_present": observed})
        for variant in [
            "reflect",
            "empty",
            "wildcard",
            "allowlist",
            "no-credentials",
            "invalid-credentials",
        ]:
            r = http.get(f"/cors/{variant}", headers={"Origin": "https://oracle.invalid"})
            observed = (
                r.headers.get("access-control-allow-origin") == "https://oracle.invalid"
                and r.headers.get("access-control-allow-credentials") == "true"
            )
            assert observed == (variant in {"reflect", "empty"}), variant
            results.append({"route": f"/cors/{variant}", "condition_present": observed})
    with sync_playwright() as pw:
        browser = pw.chromium.launch(chromium_sandbox=True)
        for family in ["xss", "html"]:
            for variant in ["markup", "template", "escaped", "plaintext"]:
                page = browser.new_page()
                # Different tag and marker from the scanner: verifies the underlying sink.
                value = (
                    '<img src="/missing" onerror="document.title=\'oracle-executed\'">'
                    if family == "xss"
                    else '<strong id="oracle-element">fixture</strong>'
                )
                page.goto(
                    origin + f"/{family}/{variant}?" + urlencode({"q": value}),
                    wait_until="networkidle",
                )
                observed = (
                    page.title() == "oracle-executed"
                    if family == "xss"
                    else page.locator("#oracle-element").count() == 1
                )
                assert observed == (variant in {"markup", "template"}), (family, variant)
                results.append({"route": f"/{family}/{variant}", "condition_present": observed})
                page.close()
        browser.close()
    print(
        json.dumps(
            {
                "healthy": True,
                "cases": results,
                "lifecycle": "Stateless; each SQL request creates a fresh in-memory database, each browser case a fresh context.",
            }
        )
    )


if __name__ == "__main__":
    main()
