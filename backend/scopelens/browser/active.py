"""Harmless, ephemeral marker checks in the scanner-owned browser context."""

import json
import os
import secrets
from contextlib import suppress
from urllib.parse import urlencode

from scopelens.broker.probe_tasks import conditional_reference
from scopelens.browser.policy import BrowserAction


def collect(controller, page, current):
    for entry in json.loads(os.environ.get("SCOPELENS_CONDITIONAL_PROBES", "[]")):
        if entry["kind"] not in {"xss", "html"}:
            continue
        captures = []
        error = None
        for index in range(3):
            nonce = secrets.token_hex(16)
            if index == 0:
                value = "scopelens-" + nonce
            elif entry["kind"] == "xss":
                value = f"<svg onload=\"document.documentElement.dataset.scopelensMarker='{nonce}'\"></svg>"
            else:
                value = f'<span data-scopelens-marker="{nonce}">ScopeLens preview</span>'
            url = (
                controller.config.origin
                + entry["path"]
                + "?"
                + urlencode({entry["parameter"]: value})
            )
            response = None

            def navigate(url=url):
                nonlocal response
                response = page.goto(url, wait_until="networkidle", timeout=10000)

            admitted = False
            try:
                # Avoid storing executable test input in general page captures or reports.
                controller.active_probe = True
                sequence = controller.sequence + 1
                action = BrowserAction(kind="navigate", url=url, state_hash=current)
                controller.command(
                    "admit",
                    sequence=sequence,
                    action=action.model_dump(),
                    probe_task=conditional_reference(entry),
                )
                controller.sequence = sequence
                controller.probe_request = (url, conditional_reference(entry))
                admitted = True
                navigate()
                seen = (
                    page.evaluate("document.documentElement.dataset.scopelensMarker || ''")
                    if entry["kind"] == "xss"
                    else page.locator("[data-scopelens-marker]").first.get_attribute(
                        "data-scopelens-marker"
                    )
                    if page.locator("[data-scopelens-marker]").count()
                    else ""
                )
                captures.append(
                    {
                        "status": response.status if response else None,
                        "marker_present": bool(seen),
                        "nonce_matches": seen == nonce,
                        "nonce": nonce,
                        "response_url_matches": bool(response and response.url == url),
                    }
                )
                controller.command(
                    "complete", before_hash=current, after_hash=nonce, result="succeeded"
                )
                current = nonce
            except Exception as exc:  # noqa: BLE001 - denied/failed actions remain incomplete
                error = type(exc).__name__
                if admitted:
                    with suppress(Exception):
                        controller.command(
                            "complete", before_hash=current, after_hash=current, result="failed"
                        )
                break
            finally:
                controller.active_probe = False
                controller.probe_request = None
        print(
            "SCOPELENS_ARTIFACT "
            + json.dumps(
                {
                    "kind": "active_probe",
                    "source": "browser",
                    "data": {
                        "kind": entry["kind"],
                        "route": entry["path"],
                        "parameter": entry["parameter"],
                        "captures": captures,
                        "error": error,
                        "reviewed": True,
                    },
                }
            ),
            flush=True,
        )
    return current
