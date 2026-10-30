"""The scheduler yields between trials and stops on failure or interruption."""

import json

import pytest
from evaluation import holdout_schedule


def test_gap_waits_full_minimum_and_records_intervening_owner(monkeypatch, tmp_path):
    clock = [0]
    sleeps = []
    owner = tmp_path / "owner"
    monkeypatch.setattr(holdout_schedule, "LOCK_OWNER", owner)
    monkeypatch.setattr(holdout_schedule.time, "monotonic", lambda: clock[0])

    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds
        if clock[0] == 15:
            owner.write_text("peer pid=123 since=example")
        elif clock[0] == 40:
            owner.unlink()

    monkeypatch.setattr(holdout_schedule.time, "sleep", sleep)
    receipt = tmp_path / "gap.json"
    holdout_schedule.inter_trial_gap(receipt)
    data = json.loads(receipt.read_text())
    assert data["complete"] is True
    assert data["elapsed_seconds"] == 60
    assert sum(sleeps) == 60
    assert max(sleeps) <= 5
    assert data["observed_lock_tokens"] == [
        {"elapsed_seconds": 15, "token": "peer pid=123 since=example"}
    ]
    assert receipt.stat().st_mode & 0o777 == 0o600


def test_failed_trial_stops_before_wait_or_next_trial(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(holdout_schedule, "inter_trial_gap", lambda path: calls.append("gap"))

    def failed(*args):
        calls.append("failed trial")
        raise RuntimeError("trial failed")

    with pytest.raises(RuntimeError, match="trial failed"):
        holdout_schedule.run_schedule(tmp_path, [(1, "baseline"), (1, "adaptive")], "sha", failed)
    assert calls == ["failed trial"]


def test_completed_trial_returns_before_gap_and_no_gap_after_last(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(holdout_schedule, "inter_trial_gap", lambda path: calls.append(path.name))
    holdout_schedule.run_schedule(
        tmp_path,
        [(1, "baseline"), (3, "baseline")],
        "sha",
        lambda path, repeat, mode, candidate: calls.append((repeat, mode, candidate)),
    )
    assert calls == [
        (1, "baseline", "sha"),
        "gap-after-repeat-1-baseline.json",
        (3, "baseline", "sha"),
    ]


def test_interrupted_gap_preserves_receipt_and_never_starts_next_trial(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(holdout_schedule, "LOCK_OWNER", tmp_path / "absent-owner")
    monkeypatch.setattr(holdout_schedule.time, "monotonic", lambda: 0)

    def interrupted(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(holdout_schedule.time, "sleep", interrupted)
    with pytest.raises(KeyboardInterrupt):
        holdout_schedule.run_schedule(
            tmp_path,
            [(1, "baseline"), (3, "baseline")],
            "sha",
            lambda *args: calls.append("trial"),
        )
    assert calls == ["trial"]
    data = json.loads((tmp_path / "gap-after-repeat-1-baseline.json").read_text())
    assert data["complete"] is False


def test_outer_scheduler_refuses_to_keep_shared_lock_during_gap(monkeypatch, tmp_path):
    from evaluation import run_holdout

    output = tmp_path / "schedule"
    candidate = "a" * 40
    monkeypatch.setenv(run_holdout.LOCK_TOKEN_ENV, "inherited-owner")
    monkeypatch.setattr(
        run_holdout.sys,
        "argv",
        ["runner", "--output", str(output), "--candidate-commit", candidate],
    )
    monkeypatch.setattr(run_holdout.subprocess, "check_output", lambda *a, **k: candidate)
    with pytest.raises(SystemExit) as error:
        run_holdout.main()
    assert error.value.code == 2
    assert not output.exists()
