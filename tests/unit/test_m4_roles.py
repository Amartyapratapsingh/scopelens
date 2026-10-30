import json
from types import SimpleNamespace

import pytest

from scopelens.adapters.roles import complete
from scopelens.config import ModelRoleSettings


def role(**kw):
    return ModelRoleSettings(
        base_url="http://provider.invalid/v1",
        model="configured-test-model",
        json_mode=True,
        input_price_per_million=1,
        output_price_per_million=1,
        **kw,
    )


def factory(content=None, refusal=None, usage=True, fail=False):
    def make(_):
        def create(**kwargs):
            assert kwargs["model"] == "configured-test-model"
            assert "tools" not in kwargs
            if fail:
                raise TimeoutError()
            return SimpleNamespace(
                usage=SimpleNamespace(
                    model_dump=lambda: {"prompt_tokens": 10, "completion_tokens": 20}
                )
                if usage
                else None,
                choices=[
                    SimpleNamespace(
                        message=SimpleNamespace(content=json.dumps(content), refusal=refusal)
                    )
                ],
            )

        return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))

    return make


def run(r, **kwargs):
    return complete(
        r,
        "planner",
        {"candidates": []},
        approved=["http://provider.invalid/v1"],
        remaining_cost=1,
        **kwargs,
    )


def test_proposal_schema_and_usage():
    r = run(role(), client_factory=factory({"candidate_id": "one", "reason": "observed"}))
    assert r["state"] == "completed" and r["cost"] == 0.00003


@pytest.mark.parametrize(
    "output",
    [
        {"confirmed": True},
        {"candidate_id": "one", "reason": "x", "execute": "curl other-site"},
        {"candidate_id": 1, "reason": "x"},
        None,
    ],
)
def test_wrong_schema_never_executes(output):
    assert run(role(), client_factory=factory(output))["state"] == "unavailable"


def test_unknown_usage_stays_unknown():
    assert (
        run(role(), client_factory=factory({"candidate_id": "one", "reason": "x"}, usage=False))[
            "cost"
        ]
        is None
    )


def test_refusal_does_not_fallback():
    calls = []

    def client(route):
        calls.append(route.model)
        return factory(refusal="refused")(route)

    r = role(fallbacks=[role()])
    assert run(r, client_factory=client)["state"] == "refused"
    assert len(calls) == 1


def test_unapproved_fallback_receives_no_data():
    calls = []
    r = role(
        fallbacks=[
            ModelRoleSettings(base_url="http://unapproved.invalid", model="evil", json_mode=True)
        ]
    )

    def client(route):
        calls.append(route.base_url)
        return factory(fail=True)(route)

    assert run(r, client_factory=client)["state"] == "unavailable"
    assert calls == ["http://provider.invalid/v1"]


def test_cancel_context_pricing_and_budget_prevent_calls():
    def never(_):
        raise AssertionError("must not call")

    assert run(role(), client_factory=never, cancelled=lambda: True)["state"] == "cancelled"
    r = role()
    r.context_tokens = 1024
    assert run(r, client_factory=never)["state"] == "unavailable"
    r = role()
    r.input_price_per_million = None
    assert run(r, client_factory=never)["state"] == "unavailable"
    r = role()
    r.output_price_per_million = 1e9
    assert run(r, client_factory=never)["state"] == "unavailable"


@pytest.mark.parametrize("effort", [None, "low"])
def test_optional_reasoning_effort_reaches_provider(effort):
    seen = []

    def client(route):
        original = factory({"candidate_id": "one", "reason": "observed"})(route)
        create = original.chat.completions.create

        def capture(**kwargs):
            seen.append(kwargs)
            return create(**kwargs)

        original.chat.completions.create = capture
        return original

    assert run(role(reasoning_effort=effort), client_factory=client)["state"] == "completed"
    if effort is None:
        assert "reasoning_effort" not in seen[0]
    else:
        assert seen[0]["reasoning_effort"] == effort


def test_browser_no_action_is_an_abstention_without_fallback():
    calls = []
    r = role(vision=True, fallbacks=[role(vision=True)])

    def client(route):
        calls.append(route)
        return factory({})(route)

    result = complete(
        r,
        "browser",
        {"dom": "No buttons", "screenshot": ""},
        approved=[r.base_url],
        remaining_cost=1,
        client_factory=client,
    )
    assert result["state"] == "abstained"
    assert result["cost"] == 0.00003
    assert len(calls) == 1
    assert "value" not in result


@pytest.mark.parametrize("token_parameter", ["max_tokens", "max_completion_tokens"])
def test_provider_request_options_keep_validation_and_accounting(token_parameter):
    seen = []

    def client(route):
        original = factory({"candidate_id": "one", "reason": "observed"})(route)
        create = original.chat.completions.create

        def capture(**kwargs):
            seen.append(kwargs)
            return create(**kwargs)

        original.chat.completions.create = capture
        return original

    configured = role(
        token_limit_parameter=token_parameter,
        response_format="json_schema",
        max_output_tokens=2048,
    )
    result = run(configured, client_factory=client)
    assert result["state"] == "completed"
    assert result["cost"] == 0.00003
    request = seen[0]
    assert request[token_parameter] == 2048
    other = "max_completion_tokens" if token_parameter == "max_tokens" else "max_tokens"
    assert other not in request
    schema = request["response_format"]["json_schema"]
    assert schema["strict"] is True
    assert set(schema["schema"]["required"]) == {"candidate_id", "reason"}
    assert schema["schema"]["additionalProperties"] is False
    assert run(configured, client_factory=factory({"confirmed": True}))["state"] == "unavailable"


def test_invalid_schema_keeps_known_billed_usage():
    result = run(role(), client_factory=factory({"unexpected": "shape"}))
    assert result["state"] == "unavailable"
    assert result["cost"] == 0.00003
