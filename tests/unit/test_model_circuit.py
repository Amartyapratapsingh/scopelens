"""Exercise the real Lua transitions against a private, disposable Redis process."""

import json
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from redis import Redis
from redis.exceptions import RedisError

from scopelens.adapters.circuit import ProviderCircuit
from scopelens.adapters.roles import complete
from scopelens.config import ModelRoleSettings


@pytest.fixture
def circuits():
    executable = shutil.which("redis-server")
    if not executable:
        pytest.skip("redis-server required for real circuit concurrency tests")
    directory = tempfile.TemporaryDirectory(prefix="sl-cb-", dir="/tmp")
    sock = directory.name + "/redis.sock"
    process = subprocess.Popen(
        [executable, "--port", "0", "--unixsocket", sock, "--save", "", "--appendonly", "no"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    client = Redis(unix_socket_path=sock, decode_responses=True)
    try:
        for _ in range(100):
            try:
                if client.ping():
                    break
            except RedisError:
                time.sleep(0.01)
        assert client.ping()
        yield ProviderCircuit(client), ProviderCircuit(client)
    finally:
        client.close()
        process.terminate()
        process.wait(timeout=5)
        directory.cleanup()


def route(model="primary", **kwargs):
    return ModelRoleSettings(
        base_url="http://provider.invalid/v1",
        model=model,
        json_mode=True,
        input_price_per_million=1,
        output_price_per_million=1,
        **kwargs,
    )


def age_open(circuit, role):
    # Advance the cooldown without sleeping; acquisition still uses Redis's clock.
    circuit.redis.hset(circuit.key(role), "until", 1)


def test_shared_open_single_probe_and_recovery(circuits):
    first, second = circuits
    r = route()
    late = first.acquire(r)
    for _ in range(2):
        first.finish(first.acquire(r), success=False)
    assert second.acquire(r) is None
    first.finish(late, success=True)  # Old calls cannot close the newer open generation.
    assert second.acquire(r) is None
    age_open(first, r)
    with ThreadPoolExecutor(max_workers=12) as pool:
        grants = list(pool.map(lambda _: second.acquire(r), range(24)))
    probes = [grant for grant in grants if grant]
    assert len(probes) == 1 and probes[0].probe
    first.finish(probes[0], success=True)
    assert second.acquire(r).probe == ""


def test_failed_or_abandoned_probe_and_isolation(circuits):
    first, second = circuits
    r = route(api_key="key-one")
    for _ in range(2):
        first.finish(first.acquire(r), success=False)
    assert second.acquire(route(api_key="key-two"))
    assert second.acquire(route("fallback", api_key="key-one"))
    assert "key-one" not in first.key(r)
    age_open(first, r)
    old_probe = first.acquire(r)
    first.redis.hset(first.key(r), "probe_until", 1)
    new_probe = second.acquire(r)
    first.finish(old_probe, success=True)
    assert first.acquire(r) is None
    second.finish(new_probe, success=False)
    assert first.acquire(r) is None


def response(content, **kwargs):
    return SimpleNamespace(
        usage=None,
        choices=[
            SimpleNamespace(
                finish_reason=kwargs.get("finish_reason", "stop"),
                message=SimpleNamespace(content=json.dumps(content), refusal=kwargs.get("refusal")),
            )
        ],
    )


def test_timeout_fallback_medium_and_open_skips_primary(circuits):
    circuit, _ = circuits
    primary = route(fallbacks=[route("gpt-5.6-sol", reasoning_effort="medium")])
    calls = []

    def factory(r):
        def create(**kw):
            calls.append(kw)
            if r.model == "primary":
                raise TimeoutError()
            assert kw["reasoning_effort"] == "medium"
            return response({"candidate_id": "fixture", "reason": "observed"})

        return SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))

    results = [
        complete(
            primary,
            "planner",
            {},
            approved=[primary.base_url],
            remaining_cost=1,
            client_factory=factory,
            circuit=circuit,
        )
        for _ in range(3)
    ]
    assert all(result["state"] == "completed" for result in results)
    assert sum(call["model"] == "primary" for call in calls) == 2
    assert results[-1]["attempts"][0]["state"] == "circuit_open"
    assert results[-1]["attempts"][0]["cost"] == 0
    assert results[0]["cost"] is None  # Timeout billing is unknown, never silently zero.


@pytest.mark.parametrize("finish_reason,refusal", [("content_filter", None), ("stop", "refused")])
def test_refusal_never_falls_back(circuits, finish_reason, refusal):
    circuit, _ = circuits
    r = route(fallbacks=[route("fallback")])
    calls = []

    def factory(current):
        calls.append(current.model)
        return SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(
                    create=lambda **kw: response({}, finish_reason=finish_reason, refusal=refusal)
                )
            )
        )

    result = complete(
        r,
        "planner",
        {},
        approved=[r.base_url],
        remaining_cost=1,
        client_factory=factory,
        circuit=circuit,
    )
    assert result["state"] == "refused" and calls == ["primary"]
    assert circuit.acquire(r)


def test_redis_outage_prevents_uncontrolled_calls():
    class Broken:
        def acquire(self, route):
            raise RedisError()

    r = route()

    def never(_):
        pytest.fail("provider called while breaker store unavailable")

    result = complete(
        r,
        "planner",
        {},
        approved=[r.base_url],
        remaining_cost=1,
        client_factory=never,
        circuit=Broken(),
    )
    assert result["attempts"][0]["state"] == "circuit_unavailable"
    assert result["cost"] == 0


def test_sdk_uses_configured_timeout_without_hidden_cap(monkeypatch):
    seen = []

    def factory(**kwargs):
        seen.append(kwargs)
        return SimpleNamespace(
            close=lambda: None,
            chat=SimpleNamespace(
                completions=SimpleNamespace(
                    create=lambda **kw: response({"candidate_id": "fixture", "reason": "observed"})
                )
            ),
        )

    monkeypatch.setattr("scopelens.adapters.roles.OpenAI", factory)
    r = route(timeout_seconds=60)
    result = complete(r, "planner", {}, approved=[r.base_url], remaining_cost=1)
    assert result["state"] == "completed"
    assert seen[0]["timeout"] == 60 and seen[0]["max_retries"] == 0
    seen[0]["http_client"].close()
