"""Execute a separate browser worker under the scan's existing lease and budget."""

import json
from dataclasses import replace

from scopelens.execution.supervisor import (
    ARTIFACT_MARKER,
    RESULT_MARKER,
    SupervisorError,
    WorkerResult,
)


def run_browser(settings, supervisor, spec, crawl, *, run_id):
    browser_id = run_id + "-browser"
    browser_spec = replace(
        spec,
        image=settings.browser_worker_image,
        command=["python", "-m", "scopelens.browser.worker"],
        browser=True,
        environment={
            **spec.environment,
            "SCOPELENS_BROWSER_OWNER": browser_id,
            "SCOPELENS_BROWSER_MAX_ACTIONS": str(settings.browser_max_actions),
            "SCOPELENS_BROWSER_MAX_STATES": str(settings.browser_max_states),
        },
        labels={**spec.labels, "scopelens.run_id": browser_id},
    )
    try:
        browser = supervisor.run(browser_spec, run_id=browser_id)
    except SupervisorError:
        # Preserve the completed crawl when browser admission or startup fails.
        browser = WorkerResult(browser_id, 1, "", "browser startup unavailable", 0)
    captures = browser.artifacts()
    if not any(item.get("kind") == "browser_summary" for item in captures):
        captures.append(
            {
                "kind": "browser_summary",
                "data": {
                    "states": sum(item.get("kind") == "browser_state" for item in captures),
                    "actions": 0,
                    "gaps": [
                        {
                            "reason": "browser_timeout"
                            if browser.timed_out
                            else "browser_interrupted"
                        }
                    ],
                },
            }
        )
    artifacts = []
    for item in captures:
        item = {**item, "source": "browser", "run_id": browser_id}
        if item.get("kind") == "browser_summary":
            item["data"] = {
                **item["data"],
                "status": "completed" if browser.succeeded else "incomplete",
            }
        artifacts.append(ARTIFACT_MARKER + json.dumps(item))
    a = crawl.declared_result() or {}
    b = browser.declared_result() or {}
    browser_error = b.get("error") or b.get("reason")
    if not browser_error:
        gaps = [
            gap
            for item in captures
            if item.get("kind") == "browser_summary"
            for gap in item.get("data", {}).get("gaps", [])
        ]
        if gaps:
            browser_error = gaps[-1].get("detail") or gaps[-1].get("reason")
    combined = {
        **a,
        "ok": bool(a.get("ok") and b.get("ok")),
        "body_bytes": int(a.get("body_bytes", 0)) + int(b.get("body_bytes", 0)),
        "browser_ok": bool(b.get("ok", False)),
        "crawl_ok": bool(a.get("ok", False)),
        "error": str(browser_error)[:1000] if not b.get("ok") and browser_error else a.get("error"),
        "reason": "browser incomplete" if not b.get("ok") else a.get("reason", ""),
    }
    return WorkerResult(
        run_id=run_id,
        exit_code=0 if combined["ok"] else 1,
        stdout=crawl.stdout
        + "\n"
        + "\n".join(artifacts)
        + "\n"
        + RESULT_MARKER
        + json.dumps(combined),
        stderr=crawl.stderr + "\n" + browser.stderr,
        duration_seconds=crawl.duration_seconds + browser.duration_seconds,
        timed_out=crawl.timed_out or browser.timed_out,
        killed=crawl.killed or browser.killed,
    )
