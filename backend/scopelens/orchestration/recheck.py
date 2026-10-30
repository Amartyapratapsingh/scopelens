"""One reviewed no-cache response capture. No redirects, plugins or arbitrary commands."""

import json
import os
from urllib.parse import urlsplit

from scopelens.checks.crawl import Crawler, config_from_env
from scopelens.domain.collection import CollectedResponse
from scopelens.execution.supervisor import ARTIFACT_MARKER, RESULT_MARKER


def main():
    config = config_from_env()
    target = os.environ["SCOPELENS_TARGET_URL"]
    crawler = Crawler(config)
    with (
        crawler._http() as client,
        client.stream(
            "GET", target, headers={"Cache-Control": "no-cache"}, follow_redirects=False
        ) as r,
    ):
        body = bytearray()
        truncated = False
        for chunk in r.iter_bytes():
            available = config.max_body_bytes - len(body)
            body.extend(chunk[:available])
            if len(chunk) > available:
                truncated = True
                break
        capture = CollectedResponse(
            url=target,
            route=urlsplit(target).path or "/",
            status=r.status_code,
            headers=dict(r.headers),
            content_type=r.headers.get("content-type"),
            body_excerpt=body.decode("utf-8", "replace"),
            body_bytes=len(body),
            truncated=truncated,
            via_proxy=True,
        )
    print(
        ARTIFACT_MARKER + json.dumps({"kind": "response", "data": capture.model_dump(mode="json")}),
        flush=True,
    )
    print(RESULT_MARKER + json.dumps({"outcome": "completed", "body_bytes": len(body)}), flush=True)


if __name__ == "__main__":
    main()
