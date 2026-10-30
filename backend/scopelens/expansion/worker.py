"""Fixed-code expansion collector. All target clients use the enforced scan proxy."""

import json
import os
import signal
from urllib.parse import urlsplit

from scopelens.checks.crawl import Crawler, config_from_env
from scopelens.checks.packs.exposure import collect_exposure_pack
from scopelens.domain.assessment import AssessmentPlanVersion, DiscoveryCatalogue
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.execution.supervisor import ARTIFACT_MARKER, RESULT_MARKER
from scopelens.expansion.client import AssessmentControlClient

_cancelled = False


def _cancel(*_):
    global _cancelled
    _cancelled = True


def emit(kind, data):
    print(ARTIFACT_MARKER + json.dumps({"kind": kind, "data": data}), flush=True)


def main():
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGINT, _cancel)
    payload = json.loads(os.environ["SCOPELENS_EXPANSION_INPUT"])
    catalogue = DiscoveryCatalogue.model_validate(payload["catalogue"])
    plan = AssessmentPlanVersion.model_validate(payload["plan"])
    configuration = AssessmentConfiguration.model_validate(payload["configuration"])
    crawler = Crawler(config_from_env())
    with crawler._http() as client:
        result = collect_exposure_pack(
            client,
            catalogue.origin,
            technologies=payload.get("technologies", ()),
            admit_url=lambda url: (
                crawler._in_scope(url) and not crawler._excluded(urlsplit(url).path or "/")
            ),
            discovered_urls=[
                t.origin + t.path
                for t in catalogue.templates
                if t.authority == "primary" and t.baseline_complete
            ],
            cancelled=lambda: _cancelled,
        )
        emit("exposure_pack", result.model_dump(mode="json"))
        control = AssessmentControlClient(client)
        if plan.tasks:
            from scopelens.expansion.authenticated_inputs import run_authenticated_inputs

            for artifact in run_authenticated_inputs(
                catalogue,
                plan,
                client,
                configuration.identities,
                lambda role: Crawler(config_from_env())._http(),
                control.secret,
                cancelled=lambda: _cancelled,
                max_requests=240,
            ):
                print(ARTIFACT_MARKER + json.dumps(artifact), flush=True)
    if configuration.callback_recipes:
        from scopelens.callbacks.integration import collect_callback_diagnostics

        with Crawler(config_from_env())._http() as callback_http:
            collect_callback_diagnostics(
                configuration,
                AssessmentControlClient(callback_http),
                callback_http,
                owner_id=payload["owner_id"],
                scan_id=payload["scan_id"],
                emit=emit,
                cancelled=lambda: _cancelled,
            )
    if configuration.identities:
        from scopelens.expansion.identity_collector import collect_identity_assessments

        with Crawler(config_from_env())._http() as control_http:
            collect_identity_assessments(
                configuration,
                AssessmentControlClient(control_http),
                lambda role: Crawler(config_from_env())._http(),
                emit,
                cancelled=lambda: _cancelled,
                configuration_binding=payload.get("configuration_binding"),
            )
    if os.environ.get("SCOPELENS_SCANNER_TOOLS_ENABLED", "false").lower() == "true":
        from scopelens.adapters.expansion_runner import run_expansion_tools

        for tool_result in run_expansion_tools(
            config_from_env(),
            technologies=payload.get("technologies", ()),
            cancelled=lambda: _cancelled,
        ):
            emit("scanner_result", tool_result.model_dump(mode="json"))
    print(
        RESULT_MARKER
        + json.dumps(
            {"ok": not _cancelled, "body_bytes": sum(o.bytes_read for o in result.observations)}
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
