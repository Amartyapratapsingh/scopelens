"""Opt-in synthetic qualification; does not change live settings or execute target actions."""

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scopelens.adapters.roles import complete
from scopelens.config import ModelRoleSettings, Settings


def candidate(primary):
    # Rates verified against https://commandcode.ai/docs/plans/goat, 2026-09-29.
    return ModelRoleSettings(
        base_url=primary.base_url,
        api_key=primary.api_key,
        model="gpt-5.6-sol",
        reasoning_effort="medium",
        timeout_seconds=60,
        max_output_tokens=2048,
        json_mode=True,
        context_tokens=32000,
        input_price_per_million=5,
        output_price_per_million=30,
    )


def main():
    import httpx
    from openai import OpenAI

    settings = Settings()
    results = []
    payloads = {
        "planner": {
            "candidates": [{"id": "fixture-header-review", "signal": "fixture omitted CSP"}]
        },
        "verification": {
            "observation": "Fixture omitted CSP on one response. Confirmation pending."
        },
        "report_writer": {
            "what": "CSP was absent on one fixture response.",
            "why": "A browser protection was not observed.",
            "fix": "Configure and test CSP. Only one response was checked.",
        },
        "script": {"responses": [{"route": "/", "status": 200, "content_type": "text/html"}]},
    }
    for name, payload in payloads.items():
        primary = getattr(settings, ("planner" if name == "script" else name) + "_model")
        role = primary.model_copy(update={"fallbacks": [candidate(primary)]})
        clients = []

        def factory(route, primary=primary, clients=clients):
            if route.model == primary.model:

                def timeout(**kwargs):
                    raise TimeoutError("qualification: injected primary timeout")

                return SimpleNamespace(
                    chat=SimpleNamespace(completions=SimpleNamespace(create=timeout))
                )
            client = OpenAI(
                base_url=route.base_url,
                api_key=route.api_key.get_secret_value(),
                max_retries=0,
                timeout=route.timeout_seconds,
                http_client=httpx.Client(trust_env=False, follow_redirects=False),
            )
            clients.append(client)
            return client

        try:
            result = complete(
                role,
                name,
                payload,
                approved=settings.approved_model_base_urls,
                remaining_cost=2 * settings.model_cost_ceiling / settings.model_max_calls,
                client_factory=factory,
            )
        finally:
            for client in clients:
                client.close()
        passed = result["state"] == "completed"
        if name == "planner":
            passed = (
                passed and result.get("value", {}).get("candidate_id") == "fixture-header-review"
            )
        results.append(
            {
                "role": name,
                "state": result["state"],
                "passed": passed,
                "attempts": result["attempts"],
                "cost": result["cost"],
            }
        )
        print(name, result["state"], "passed=" + str(passed), flush=True)
    Path("runs/fallback-chain-qualification.json").write_text(
        json.dumps(
            {
                "recorded_at": datetime.now(UTC).isoformat(),
                "synthetic_only": True,
                "primary_failure_injected": True,
                "fallback_provider_live": True,
                "reasoning_effort_requested": "medium",
                "results": results,
                "limitations": [
                    "No target scan or generated-script execution in this qualification.",
                    "Schema validation does not establish model quality or vulnerability detection accuracy.",
                ],
            },
            indent=2,
        )
        + "\n"
    )
    return 0 if all(r["passed"] for r in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
