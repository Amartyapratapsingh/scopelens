"""Heartbeat diagnostics retain timing and error classes without exception text."""

import logging
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from scopelens.config import Settings
from scopelens.execution import heartbeat as module
from scopelens.execution.leases import Lease, LeaseLost


@pytest.fixture
def probe(monkeypatch):
    # Earlier DB tests run Alembic's fileConfig, which disables existing loggers.
    # Restore this logger only for the test; monkeypatch restores the prior state.
    monkeypatch.setattr(module.logger, "disabled", False)
    start = datetime(2026, 10, 11, 14, 13, tzinfo=UTC)
    lease = Lease(uuid.uuid4(), "holder", 7, start + timedelta(seconds=30))
    settings = Settings(_env_file=None, lease_ttl_seconds=30, lease_renew_interval_seconds=10)

    @contextmanager
    def session_scope(_settings):
        yield object()

    monkeypatch.setattr(module, "session_scope", session_scope)

    class Clock:
        @staticmethod
        def now(_tz):
            return start

    monkeypatch.setattr(module, "datetime", Clock, raising=False)
    return module.LeaseHeartbeat(settings, lease), lease, start


def duration(monkeypatch, seconds):
    ticks = iter([100.0, 100.0 + seconds])
    monkeypatch.setattr(
        module, "time", SimpleNamespace(monotonic=lambda: next(ticks)), raising=False
    )


def test_slow_success_logs_committed_expiry(probe, monkeypatch, caplog):
    heartbeat, lease, start = probe
    renewed = Lease(lease.scan_id, lease.holder, lease.fencing_token, start + timedelta(seconds=40))
    monkeypatch.setattr(module, "renew_lease", lambda *_args, **_kwargs: renewed)
    duration(monkeypatch, 6)
    with caplog.at_level(logging.WARNING):
        assert heartbeat._renew_once()
    record = caplog.records[0]
    assert record.levelno == logging.WARNING
    assert record.scan_id == str(lease.scan_id)
    assert record.attempt_at == start.isoformat()
    assert record.duration_seconds == 6
    assert record.error_class is None
    assert record.remaining_ttl_seconds == 40
    assert heartbeat.status.renewals == 1
    assert heartbeat.status.healthy


def test_fast_success_is_quiet(probe, monkeypatch, caplog):
    heartbeat, lease, _start = probe
    monkeypatch.setattr(module, "renew_lease", lambda *_args, **_kwargs: lease)
    duration(monkeypatch, 5)
    with caplog.at_level(logging.WARNING):
        assert heartbeat._renew_once()
    assert not caplog.records


def test_failed_commit_logs_warning_and_terminal_loss_retains_error_class(
    probe, monkeypatch, caplog
):
    heartbeat, lease, start = probe
    secret = "password=never-log-this"
    renewed = Lease(lease.scan_id, lease.holder, lease.fencing_token, start + timedelta(seconds=90))
    monkeypatch.setattr(module, "renew_lease", lambda *_args, **_kwargs: renewed)

    @contextmanager
    def failed_commit(_settings):
        yield object()
        raise ConnectionError(secret)

    monkeypatch.setattr(module, "session_scope", failed_commit)
    duration(monkeypatch, 1)
    with caplog.at_level(logging.WARNING):
        assert heartbeat._renew_once()
    first = caplog.records[0]
    assert first.levelno == logging.WARNING
    assert first.error_class == "ConnectionError"
    assert first.remaining_ttl_seconds == 30  # Failed commit never advances known expiry.
    assert heartbeat.status.healthy
    assert heartbeat.status.renewals == 0

    @contextmanager
    def session_scope(_settings):
        yield object()

    def lost(*_args, **_kwargs):
        raise LeaseLost("lease expired")

    monkeypatch.setattr(module, "session_scope", session_scope)
    monkeypatch.setattr(module, "renew_lease", lost)
    duration(monkeypatch, 1)
    with caplog.at_level(logging.WARNING):
        assert not heartbeat._renew_once()
    assert caplog.records[-1].levelno == logging.ERROR
    assert caplog.records[-1].error_class == "LeaseLost"
    assert "ConnectionError" in heartbeat.status.lost_reason
    assert "lease expired" in heartbeat.status.lost_reason
    assert secret not in caplog.text
    assert secret not in heartbeat.status.lost_reason
    assert all(record.exc_info is None for record in caplog.records)
    assert heartbeat.status.lost
