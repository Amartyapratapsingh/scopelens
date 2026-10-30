"""Opt-in live provider qualification with synthetic inputs, never target actions."""

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from playwright.sync_api import sync_playwright

from scopelens.adapters.roles import PROMPT_VERSION, complete
from scopelens.config import Settings


def browser_fixture():
    """Render our own fixed disclosure button; its location is absent from the prompt."""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 720})
            page.set_content(
                '<body style="margin:0;background:white"><button style="position:absolute;'
                'left:440px;top:300px;width:280px;height:80px;font-size:24px">'
                "Show scan details</button></body>"
            )
            screenshot = page.screenshot(type="jpeg")
        finally:
            browser.close()
    return {
        "dom": "Synthetic fixture: one visible read-only disclosure button. Locate its centre from the screenshot.",
        "screenshot": base64.b64encode(screenshot).decode(),
    }


def semantic_check(name, value):
    if name == "planner":
        return value.get("candidate_id") == "synthetic-case"
    if name == "browser":
        # Require the button's central area, not merely a valid viewport coordinate.
        return 510 <= value.get("x", -1) <= 650 and 320 <= value.get("y", -1) <= 360
    fields = {
        "verification": ("alternative_explanation", "missing_proof"),
        "report_writer": ("what", "why", "fix"),
        "script": ("source", "purpose"),
    }[name]
    return all(isinstance(value.get(k), str) and value[k].strip() for k in fields)


def main():
    settings = Settings()
    payloads = {
        "planner": {"candidates": [{"id": "synthetic-case", "signal": "fixture header missing"}]},
        "verification": {
            "observation": "Synthetic response omitted CSP; offer an alternative explanation."
        },
        "report_writer": {
            "what": "A fixture omitted CSP.",
            "why": "Browser protection is absent.",
            "fix": "Configure and test a CSP.",
        },
        "script": {"responses": [{"route": "/", "status": 200, "content_type": "text/html"}]},
        "browser": browser_fixture(),
    }
    results = []
    for name, payload in payloads.items():
        role = getattr(settings, ("planner" if name == "script" else name) + "_model")
        result = complete(
            role,
            name,
            payload,
            approved=settings.approved_model_base_urls,
            remaining_cost=min(settings.model_cost_ceiling / len(payloads), 0.25),
        )
        passed = result["state"] == "completed" and semantic_check(name, result.get("value", {}))
        results.append(
            {
                "role": name,
                "model": role.model,
                "provider": role.base_url,
                "state": result["state"],
                "smoke_passed": passed,
                "cost": result.get("cost"),
                "configuration": {
                    k: getattr(role, k)
                    for k in (
                        "reasoning_effort",
                        "max_output_tokens",
                        "token_limit_parameter",
                        "response_format",
                        "context_tokens",
                        "vision",
                        "json_mode",
                        "timeout_seconds",
                        "input_price_per_million",
                        "output_price_per_million",
                    )
                },
                "attempts": result.get("attempts", []),
                "fixture_sha256": hashlib.sha256(
                    json.dumps(payload, sort_keys=True).encode()
                ).hexdigest(),
            }
        )
        print(name, result["state"], "smoke_passed=" + str(passed), flush=True)
    out = Path("runs/model-qualification.json")
    out.parent.mkdir(exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "recorded_at": datetime.now(UTC).isoformat(),
                "prompt_version": PROMPT_VERSION,
                "adapter_sha256": hashlib.sha256(
                    Path("backend/scopelens/adapters/roles.py").read_bytes()
                ).hexdigest(),
                "synthetic_only": True,
                "results": results,
                "limitations": [
                    "Development smoke fixtures, not an independent model-quality benchmark.",
                    "Browser check measures a synthetic disclosure-button coordinate, not arbitrary-site action safety.",
                    "Script output is schema-checked, not executed by this qualification script.",
                    "Live smoke complements malformed-response, refusal, budget and fallback contract tests.",
                ],
            },
            indent=2,
        )
        + "\n"
    )
    return 0 if all(r["smoke_passed"] for r in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
