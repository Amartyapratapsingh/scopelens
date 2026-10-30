import json
import sys
from types import SimpleNamespace

from scopelens.adapters import runner
from scopelens.adapters.scanners import ScannerResult
from scopelens.domain.collection import CollectedResponse


def responses(count=12):
    return [
        CollectedResponse(
            url=f"https://fixture.invalid/{i}",
            route=f"/{i}",
            status=200,
            body_excerpt="x" * 1000000,
        )
        for i in range(count)
    ]


def test_batches_preserve_every_capture_without_exceeding_disk_bound():
    original = responses()
    batches = list(runner.capture_batches(original))
    assert len(batches) > 1
    assert [row for batch in batches for row in batch] == original
    assert all(
        len(json.dumps(runner.har(batch)).encode()) <= runner.ZAP_BATCH_BYTES for batch in batches
    )


def test_failed_later_batch_does_not_claim_full_assessment_or_skip_next_tool(monkeypatch):
    calls = []

    def zap(config, batch, *, timeout):
        calls.append(batch)
        return ScannerResult(
            tool="zap",
            version="test",
            state="completed" if len(calls) == 1 else "error",
            errors=[] if len(calls) == 1 else ["disk full"],
        )

    monkeypatch.setattr(runner, "_run_zap", zap)
    monkeypatch.setattr(
        runner,
        "_run_nuclei",
        lambda config: ScannerResult(tool="nuclei", version="test", state="completed"),
    )
    output = list(runner.run_tools(None, SimpleNamespace(responses=responses())))
    assert output[0].state == "partial"
    assert "disk full" in output[0].errors
    assert output[1].state == "completed"


def test_tool_log_flood_is_drained_and_keeps_bounded_tail(tmp_path):
    result = runner.invoke(
        "nuclei",
        "test",
        [
            sys.executable,
            "-c",
            "import sys;sys.stdout.write('x'*10_000_000+'LAST-DIAGNOSTIC');sys.exit(1)",
        ],
        tmp_path / "output.json",
        timeout=10,
    )
    assert result.state == "error"
    assert result.errors[-1].endswith("LAST-DIAGNOSTIC")
    assert len(result.errors[-1]) <= 3000
    assert list(tmp_path.iterdir()) == []


def test_global_zap_deadline_preserves_next_tool(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(runner.time, "monotonic", lambda: clock[0])

    def zap(config, batch, *, timeout):
        clock[0] += runner.ZAP_TOTAL_SECONDS + 1
        return ScannerResult(tool="zap", version="test", state="completed")

    monkeypatch.setattr(runner, "_run_zap", zap)
    monkeypatch.setattr(
        runner,
        "_run_nuclei",
        lambda config: ScannerResult(tool="nuclei", version="test", state="completed"),
    )
    output = list(runner.run_tools(None, SimpleNamespace(responses=responses())))
    assert output[0].state == "partial"
    assert "time budget" in output[0].errors[0]
    assert output[1].state == "completed"


def test_timeout_reports_the_actual_limit(tmp_path):
    result = runner.invoke(
        "nuclei",
        "test",
        [sys.executable, "-c", "import time;time.sleep(5)"],
        tmp_path / "output.json",
        timeout=0.1,
    )
    assert result.state == "timeout"
    assert "time allowance exhausted after 0.1s" in result.errors[-1]


def test_zap_uses_coordinator_time_allowance(monkeypatch):
    monkeypatch.setenv("SCOPELENS_ZAP_TIMEOUT", "540")
    monkeypatch.setattr(runner.time, "monotonic", lambda: 10)
    limits = []

    def zap(config, batch, *, timeout):
        limits.append(timeout)
        return ScannerResult(tool="zap", version="test", state="completed")

    monkeypatch.setattr(runner, "_run_zap", zap)
    monkeypatch.setattr(
        runner,
        "_run_nuclei",
        lambda config: ScannerResult(tool="nuclei", version="test", state="completed"),
    )
    assert (
        next(runner.run_tools(None, SimpleNamespace(responses=responses(1)))).state == "completed"
    )
    assert limits == [540]
