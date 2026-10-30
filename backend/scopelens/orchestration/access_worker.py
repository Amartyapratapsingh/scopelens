"""Read-only authorization follow-up over existing supplied test sessions."""

import json
import os
import signal

from scopelens.checks.crawl import Crawler, config_from_env
from scopelens.execution.supervisor import RESULT_MARKER
from scopelens.expansion.client import AssessmentControlClient
from scopelens.expansion.identity_collector import collect_identity_assessments
from scopelens.expansion.worker import emit
from scopelens.identities.sessions import SessionUnavailable
from scopelens.orchestration.followup_contexts import access_configuration


def collect_access_followup(configuration, proof_id, control, client_factory, emit, *, cancelled):
    subset = access_configuration(configuration, proof_id)
    if subset is None:
        raise SessionUnavailable("existing read-only identity sessions required")
    count = 0
    urls = {obj.request.url for obj in subset.permission_matrix.objects}
    urls.update(profile.probe.request.url for profile in subset.identities if profile.probe)

    class BoundedClient:
        def __init__(self, client):
            self.client = client
            self.cookies = client.cookies

        def stream(self, method, url, **kwargs):
            nonlocal count
            if cancelled() or count >= 12 or method not in {"GET", "HEAD"} or url not in urls:
                raise SessionUnavailable("access follow-up request denied")
            if kwargs.get("data") or kwargs.get("json"):
                raise SessionUnavailable("access follow-up body denied")
            count += 1
            return self.client.stream(method, url, **kwargs)

        def close(self):
            self.client.close()

    collect_identity_assessments(
        subset,
        control,
        lambda role: BoundedClient(client_factory(role)),
        emit,
        cancelled=cancelled,
    )
    return count


def main():
    cancelled = False

    def cancel(*_):
        nonlocal cancelled
        cancelled = True

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    payload = json.loads(os.environ["SCOPELENS_FOLLOWUP_INPUT"])
    crawler = Crawler(config_from_env())
    with crawler._http() as http:
        count = collect_access_followup(
            payload["configuration"],
            payload["proof_id"],
            AssessmentControlClient(http),
            lambda role: Crawler(config_from_env())._http(),
            emit,
            cancelled=lambda: cancelled,
        )
    print(RESULT_MARKER + json.dumps({"ok": not cancelled, "requests_used": count}), flush=True)


if __name__ == "__main__":
    main()
