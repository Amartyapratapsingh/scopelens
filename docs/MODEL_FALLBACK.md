# Model fallback and recovery

GLM-5.3 remains primary for planning, verification, report prose and generated local-artifact proposals. The configured fallback is `gpt-5.6-sol` through the same approved CommandCode provider, with `reasoning_effort=medium`. The browser vision role has its separate existing configuration; this change does not claim vision qualification.

## Runtime behavior

- Provider SDK retries are disabled. Each route is attempted once per logical call, with at most two configured fallback routes.
- The configured timeout is honored, bounded by settings validation to 120 seconds per route. The gateway caller allows the sum of configured route timeouts plus 10 seconds. HTTP timeouts are inactivity limits, not a guarantee against every slow-streaming response.
- A shared Redis circuit opens after two failed provider calls. Model, provider and credential identity define a circuit. Credentials are hashed into the key and never included in attempt logs.
- Open circuits skip the route for 60 seconds and try an eligible fallback. At cooldown expiry, Redis atomically admits one recovery probe. A successful response closes the circuit; failed probes reopen it. Expired probe leases can be replaced, and late responses cannot close a newer circuit generation.
- A valid response, including a refusal or invalid application schema, establishes provider availability. Malformed outputs still fail schema validation; they cannot become executable proposals or findings.
- Refusals and content-filter responses end the call without model switching. Cancellation, provider approval, schema and cost checks remain in effect.
- If Redis is unavailable, no new provider call is admitted. If a circuit update fails after a response, the paid response is retained and the update failure is recorded.
- Fallbacks reserve both attempt slots and their spending allowance within the unchanged scan-wide ceiling. A timeout's unknown usage remains unknown; it consumes its reservation before fallback. Skipped open circuits cost zero, but the durable outer reservation remains conservative.
- Each attempted route records model, provider, state, elapsed time and known usage. No raw model prose or credentials enter the public attempt ledger.

Circuit state is shared across gateway processes. The current Redis deployment is ephemeral, so a Redis restart resets its health history. Scan accounting remains durable in PostgreSQL.

## Local configuration

The existing nested `SCOPELENS_<ROLE>_MODEL__FALLBACKS` JSON list stores explicit fallback configuration for planner, verification and report writer. Script proposals use planner configuration. Credentials remain in the ignored local `.env` file. The gateway and scan coordinator must load matching configuration because the coordinator reserves attempts before contacting the gateway.

Qualification configuration: 60-second timeout, 2,048 output tokens, 32,000 context limit, medium reasoning, JSON mode. Conservative uncached prices use $5 input and $30 output per million tokens from the [provider's published table](https://commandcode.ai/docs/plans/goat), checked 2026-09-29. No pricing discount is assumed.

## Verification

- `uv run pytest tests/unit/test_model_circuit.py tests/unit/test_m4_roles.py tests/integration/test_m4_models.py tests/unit/test_m2_crawler.py tests/contract/test_containment.py -q`: 58 passed.
- Circuit tests start a private Redis process with a Unix socket; they exercise actual Lua scripts, concurrency, cooldown, stale replies, abandoned probes, credential isolation and Redis failure.
- `uv run python -m scripts.qualify_fallback`: all four text roles completed after an injected primary timeout and a real GPT-5.6 Sol call. Results: `runs/fallback-chain-qualification.json`. Script output was schema-checked, not executed in qualification.
- A direct live planner call returned the expected candidate in 2.17 seconds. Results: `runs/fallback-qualification.json`.

These checks prove adapter behavior and basic provider compatibility. They do not establish vulnerability detection accuracy or successful completion of a public-site scan. Runtime and repeat-scan results are recorded separately in `docs/UI_PROGRESS.md`.

## Real website verification

The local deployed application repeated the existing authorized scope for `https://www.alliance.edu.in` in scan `ddc74783-91d5-4aa3-ac26-10cf8b4f2236`. All 15 logical AI calls completed. One planner call actually switched from a GLM-5.3 `ValueError` to GPT-5.6 Sol, which completed in 5.304 seconds. This verifies real fallback integration in addition to synthetic timeout tests. The primary exception is not recorded as a transport timeout, so it does not demonstrate the circuit opening in the live scan; circuit transitions were verified separately against real Redis in the regression suite.

The scan produced five findings and HTML/JSON reports, but 4.5% coverage and incomplete scanner tools. See `docs/UI_PROGRESS.md` for those independent limitations. The application is not being signed off as a complete scanner on the strength of model compatibility.
