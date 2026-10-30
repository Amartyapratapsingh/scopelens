"""A denied active navigation does not advance the worker's action sequence."""

import json
from types import SimpleNamespace

from scopelens.browser.active import collect
from scopelens.browser.worker import ActionDenied


def test_denied_41_does_not_make_next_action_42(monkeypatch, capsys):
    entries = [
        {"kind": "xss", "path": "/first", "parameter": "q"},
        {"kind": "xss", "path": "/second", "parameter": "q"},
    ]
    monkeypatch.setenv("SCOPELENS_CONDITIONAL_PROBES", json.dumps(entries))
    instance = SimpleNamespace(
        config=SimpleNamespace(origin="https://fixture.invalid"), sequence=40
    )
    observed = []

    def command(operation, **fields):
        if operation == "admit":
            proposed = fields.get("sequence", instance.sequence)
            observed.append(proposed)
            # The cap remains exhausted, so each attempt must get the budget denial,
            # never a fabricated ordering violation caused by local counter drift.
            raise ActionDenied("action_budget" if proposed == 41 else "action_order_or_inflight")

    instance.command = command
    collect(instance, SimpleNamespace(), "current")
    assert observed == [41, 41]
    assert instance.sequence == 40
    assert capsys.readouterr().out.count('"error": "ActionDenied"') == 2


def test_next_admitted_action_commits_proposed_sequence(monkeypatch):
    monkeypatch.setenv(
        "SCOPELENS_CONDITIONAL_PROBES",
        json.dumps(
            [
                {"kind": "xss", "path": "/first", "parameter": "q"},
                {"kind": "xss", "path": "/second", "parameter": "q"},
            ]
        ),
    )
    instance = SimpleNamespace(
        config=SimpleNamespace(origin="https://fixture.invalid"), sequence=40
    )
    observed, completed = [], []

    def command(operation, **fields):
        if operation == "admit":
            observed.append(fields["sequence"])
            if len(observed) == 1:
                raise ActionDenied("action_budget")
        else:
            completed.append(instance.sequence)

    instance.command = command
    page = SimpleNamespace(
        goto=lambda url, **kwargs: SimpleNamespace(status=200, url=url),
        evaluate=lambda *args: "",
    )
    collect(instance, page, "current")
    assert observed == [41, 41, 42, 43]
    assert completed == [41, 42, 43]
    assert instance.sequence == 43
    assert instance.probe_request is None


def test_crawl_action_denial_also_leaves_local_counter_unchanged():
    import pytest

    from scopelens.browser.policy import BrowserAction
    from scopelens.browser.worker import Controller

    instance = Controller.__new__(Controller)
    instance.sequence = 40
    proposed = []

    def command(operation, **fields):
        proposed.append(fields["sequence"])
        raise ActionDenied("action_budget")

    instance.command = command
    for _ in range(2):
        with pytest.raises(ActionDenied):
            instance.act(
                None, BrowserAction(kind="navigate", url="https://fixture.invalid/"), lambda: None
            )
    assert proposed == [41, 41]
    assert instance.sequence == 40
