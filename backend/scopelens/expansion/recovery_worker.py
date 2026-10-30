"""Fixed read-only resource recovery worker, through the existing scan broker."""

import json
import os
import signal

from scopelens.checks.crawl import Crawler, config_from_env
from scopelens.execution.supervisor import ARTIFACT_MARKER, RESULT_MARKER
from scopelens.expansion.client import AssessmentControlClient
from scopelens.expansion.recovery import RecoverySpec, collect_recovery

_cancelled = False


def _cancel(*_):
    global _cancelled
    _cancelled = True


def main():
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGINT, _cancel)
    spec = RecoverySpec.model_validate_json(os.environ["SCOPELENS_RECOVERY_INPUT"])
    with Crawler(config_from_env())._http() as control_http:
        control = AssessmentControlClient(control_http)
        artifact = collect_recovery(
            spec,
            lambda role: Crawler(config_from_env())._http(),
            control.secret,
            cancelled=lambda: _cancelled,
        )
    print(ARTIFACT_MARKER + json.dumps(artifact), flush=True)
    print(
        RESULT_MARKER
        + json.dumps({"ok": not _cancelled and not artifact["data"].get("error"), "body_bytes": 0}),
        flush=True,
    )


if __name__ == "__main__":
    main()
