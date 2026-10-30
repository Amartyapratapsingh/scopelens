"""Explicit real-proxy workflow probe; run with mitmdump on PATH."""

import faulthandler
from pathlib import Path

import pytest
from test_browser_workflows import workflow_app as workflow_app
from test_expansion_browser_worker import setup
from tests.containment import proxy_bypass

from scopelens.browser.bridge import Bridge
from scopelens.expansion.browser_worker import collect_browser_assessments


@pytest.mark.parametrize("wait_seconds", [0, 0.5])
def test_upload_workflow_through_real_proxy(workflow_app, tmp_path, monkeypatch, wait_seconds):
    monkeypatch.setattr(
        proxy_bypass, "ADDON", Path("backend/scopelens/broker/mitm_addon.py").resolve()
    )
    policy = proxy_bypass.PolicyStub()
    policy.wait_seconds = wait_seconds
    proxy = proxy_bypass.Proxy(policy.url, tmp_path)
    assert proxy.wait_ready(), proxy.log()
    config, catalogue, plan, crawl, original, control = setup(
        workflow_app, tmp_path, "bad", "upload_serving"
    )
    try:
        with Bridge(f"http://127.0.0.1:{proxy.port}", "fixture-egress") as bridge:
            browser = original.browser_type.launch(
                headless=True,
                proxy={"server": bridge},
                args=["--proxy-bypass-list=<-loopback>"],
            )
            artifacts = []
            faulthandler.dump_traceback_later(35)
            try:
                summary = collect_browser_assessments(
                    config,
                    catalogue,
                    plan,
                    browser,
                    control,
                    crawl,
                    lambda kind, data: artifacts.append({"kind": kind, "data": data}),
                    owner="proxy-fixture-owner",
                    token="fixture-egress",
                    cancelled=lambda: False,
                )
                result = next(a["data"] for a in artifacts if a["kind"] == "workflow_capture")
                assert result["state"] == "confirmed", result
                assert result["cleanup_state"] == "clean", result
                assert summary["complete"]
                assert any(p.get("path") == "/bad/upload" for p in policy.seen)
            finally:
                faulthandler.cancel_dump_traceback_later()
                browser.close()
    finally:
        proxy.stop()
        policy.close()
