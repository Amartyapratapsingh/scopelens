"""Callback bearer paths must not survive audit or report serialization."""

from urllib.parse import quote

import pytest

from scopelens.security.redaction import redact, redact_text


@pytest.mark.parametrize("encode", [False, True])
def test_callback_capability_redacted_in_target_query_and_xml(encode):
    token = "canary-only-secret-token-with-32-characters"
    url = "http://collector.test/callback/" + token
    if encode:
        url = quote(url, safe="")
    text = "/preview?url=" + url
    assert token not in redact_text(text)
    assert "[redacted]" in redact({"path": text})["path"]
    assert token not in redact_text(f'<capture url="{url}"/>')
