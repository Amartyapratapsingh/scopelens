import httpx
import pytest
from scripts.fetch_advisories import fetch_snapshot


def run(payloads, **kwargs):
    replies = iter(payloads)
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=next(replies)))
    ) as client:
        return fetch_snapshot(client, packages={"jquery": "npm:jquery"}, **kwargs)


def test_empty_page_with_token_is_not_completion():
    record = {"id": "test", "modified": "2026-01-01T00:00:00Z", "affected": []}
    result = run([{"next_page_token": "next"}, {"vulns": [record]}])
    assert result.records == [record]
    assert [r["complete"] for r in result.provenance["queries"]] == [False, True]


@pytest.mark.parametrize("payload", [[], {"vulns": {}}, {"vulns": [{}]}, {"next_page_token": 3}])
def test_malformed_feed_cannot_be_published(payload):
    with pytest.raises(ValueError):
        run([payload])


def test_pagination_loop_and_cap_fail_whole_update():
    with pytest.raises(ValueError, match="loop"):
        run([{"next_page_token": "again"}, {"next_page_token": "again"}])
    with pytest.raises(ValueError, match="cap"):
        run([{"next_page_token": "next"}], max_pages=1)


def test_http_failure_is_not_a_clean_empty_corpus():
    with (
        httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(503))) as client,
        pytest.raises(httpx.HTTPStatusError),
    ):
        fetch_snapshot(client, packages={"jquery": "npm:jquery"})
