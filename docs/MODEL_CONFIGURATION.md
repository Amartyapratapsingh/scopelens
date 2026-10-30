# Model configuration

ScopeLens uses an OpenAI-compatible endpoint configured by the operator. No model is selected
in code. With roles unset, the reviewed deterministic scanner, bounded fallback planner,
verification rules and report templates still run.

Configure each role independently in `.env`. For example, replace the values below with your
provider's endpoint, model and current pricing; do not use the example endpoint itself:

```dotenv
SCOPELENS_APPROVED_MODEL_BASE_URLS=["https://your-provider.example/v1"]
SCOPELENS_PLANNER_MODEL__BASE_URL=https://your-provider.example/v1
SCOPELENS_PLANNER_MODEL__MODEL=your-model
SCOPELENS_PLANNER_MODEL__API_KEY=your-local-key
SCOPELENS_PLANNER_MODEL__JSON_MODE=true
SCOPELENS_PLANNER_MODEL__CONTEXT_TOKENS=32000
SCOPELENS_PLANNER_MODEL__MAX_OUTPUT_TOKENS=1024
SCOPELENS_PLANNER_MODEL__INPUT_PRICE_PER_MILLION=1.0
SCOPELENS_PLANNER_MODEL__OUTPUT_PRICE_PER_MILLION=1.0
```

Prices above illustrate the fields, not a quoted provider price. Set the corresponding
`VERIFICATION_MODEL`, `REPORT_WRITER_MODEL` and `BROWSER_MODEL` fields for those roles.
The browser also requires `VISION=true`. A provider must be in the exact base-URL allowlist.
API keys stay in the model gateway and are never passed to scanner workers or scripts.

Structured roles require configured pricing before a call is admitted against the monetary
ceiling. Missing provider usage remains unknown, and its reservation stays charged. Configure
`SCOPELENS_MODEL_MAX_CALLS` and `SCOPELENS_MODEL_COST_CEILING` for a scan-wide ceiling.
Fallback routes use each role's `FALLBACKS` array and must independently pass the same provider,
capability, context and budget checks. A refusal terminates that request; it is not rerouted.

Generated local analysis additionally requires the dedicated VM (`make sandbox-up`), its
host gateway (`make sandbox-gateway`) and `SCOPELENS_GENERATED_SCRIPTS_ENABLED=true`. It is
never executed inside the ordinary tool worker. Results are untrusted observations.

Restart the stack after changing `.env`. Live provider qualification requires a configured
provider; local contract tests do not establish that a particular hosted model is compatible.

## Direct API request options

Each role and fallback can select `TOKEN_LIMIT_PARAMETER=max_completion_tokens` instead
of the default `max_tokens`, and `RESPONSE_FORMAT=json_schema` instead of the default
`json_object`. Both formats retain local Pydantic validation, provider allowlisting,
cost reservations and refusal handling. Current direct GPT-6.1 Sol calls require the
completion-token parameter. The direct Claude Opus 5.5 endpoint used in the comparison
requires the schema format. CommandCode's existing routes keep their defaults.

For example, a direct Claude text role uses base URL `https://api.anthropic.com/v1`, model
`claude-opus-5-5`, `JSON_MODE=true` and `RESPONSE_FORMAT=json_schema`. Supply its credential
in that role's `API_KEY` field and approve the exact base URL before enabling it. A standalone
`ANTHROPIC_API_KEY` is read by the comparison runner, not automatically by live scan roles.
Claude's compatibility endpoint does not honor `reasoning_effort`; leave that field unset.
Do not use the schema option for browser no-action decisions without separately qualifying
abstention behavior; the current point schema requires coordinates.

Compare text roles without changing the running configuration:

```sh
uv run python -m evaluation.model_comparison --repeats 2 --budget-usd 5 \
  --output runs/model-comparison-new
```

The runner uses the configured CommandCode credential plus `ANTHROPIC_API_KEY` and
`OPENAI_API_KEY` from the process or ignored `.env`, when available. It freezes synthetic
fixtures, checks and configuration hashes before calls, records each response and usage,
and writes a summary. It never executes generated proposals or starts a target scan.
Codex's ChatGPT login remains separate from direct API credentials. The reported costs
use dated public uncached rates recorded in the plan, and must be reviewed before re-use.

## Measured local configuration — 26 September 2026

The operator authorized the existing Command Code credential. It is stored only in ignored
`.env` (mode 0600); no key is included in these documents or qualification artifacts.

| Role | Model | Reasoning effort |
|---|---|---|
| Planner, verification assistant, report writer, script proposal | `zai-org/GLM-5.3` | `low` |
| Browser screenshot interpretation | `z-ai/glm-5.3-flash` | `low` |

Base URL: `https://api.commandcode.ai/provider/v1`. Set the optional
`SCOPELENS_<ROLE>_MODEL__REASONING_EFFORT` field per role. Leaving it unset omits the parameter
for providers that do not support it. The adapter still limits responses to 4096 tokens,
uses the existing 30-second request timeout, and retains unknown-cost reservations on timeout.
Initial Flash verification/script calls timed out at default reasoning; those failures are
preserved in `runs/model-qualification-initial.json`. Low-effort qualification passed all five
roles. This establishes protocol/schema compatibility on development fixtures, not a model
quality ranking or a guarantee that every future call succeeds.

Pricing configured from Command Code's official
[pricing table](https://commandcode.ai/docs/resources/pricing-limits): GLM-5.3 $1.40 input /
$4.40 output per million tokens; Flash $0.15 / $0.50. The
[provider documentation](https://commandcode.ai/docs/provider) defines the compatible endpoint;
its live `/models` catalog supplies the exact case-sensitive IDs. Pricing must be reviewed
when the provider changes it. Recorded cost is an estimate from token usage and these rates,
not an invoice; cache discounts are not subtracted.

Run `make qualify-models` to exercise all roles with synthetic inputs, including an actual
rendered disclosure-button screenshot whose coordinates must fall inside its central area.
The script writes `runs/model-qualification.json`. Reviewed evidence is copied to
`checks_registry/model_qualification.json`; the release manifest includes it only when the
adapter hash and configured role settings match. This command never executes the model's
script proposal. Actual generated execution is tested separately in the dedicated VM.

After configuration changes, use `make run-worker-vm` to preserve the reviewed-worker VM
boundary in this deployment. Do not start the container-only override by accident.

Live integration found and fixed two additional adapter/reporting issues: browser `{}` now
records `abstained` without retrying another model, and schema failures retain known usage
costs. A terminal scan status is now published after model prose is stored; provider calls
run outside database transactions while the scan lease continues renewing.
