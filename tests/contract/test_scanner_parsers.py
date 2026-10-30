import json

import pytest

from scopelens.adapters.scanners import parse_output

SAMPLES = {
    "zap": json.dumps(
        {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "99999",
                            "name": "Unclassified issue",
                            "riskcode": "3",
                            "confidence": "2",
                            "instances": [
                                {"uri": "https://example.test/", "evidence": "captured marker"}
                            ],
                        }
                    ]
                }
            ]
        }
    ),
    "nuclei": json.dumps(
        {
            "template-id": "unmapped-rule",
            "info": {"name": "Candidate", "severity": "critical"},
            "matched-at": "https://example.test/",
            "response": "captured marker",
        }
    ),
    "testssl": json.dumps(
        [{"id": "TLS1", "severity": "HIGH", "finding": "offered", "ip": "192.0.2.1", "port": "443"}]
    ),
}


@pytest.mark.parametrize("tool", SAMPLES)
def test_valid_outputs_preserve_severity_without_confirmation(tool):
    result = parse_output(tool, "pinned", SAMPLES[tool])
    assert result.state == "completed"
    assert result.observations[0].status == "potential"
    assert result.observations[0].reported_severity in {"high", "critical"}
    assert result.observations[0].mapped_control is None
    assert result.observations[0].serious


@pytest.mark.parametrize("tool", SAMPLES)
@pytest.mark.parametrize(
    "override,state",
    [
        ({"truncated": True}, "partial"),
        ({"exit_code": 2}, "partial"),
        ({"timed_out": True}, "timeout"),
        ({"cancelled": True}, "cancelled"),
    ],
)
def test_failed_execution_keeps_candidates_but_never_claims_completion(tool, override, state):
    result = parse_output(tool, "pinned", SAMPLES[tool], **override)
    assert result.state == state
    assert result.observations


@pytest.mark.parametrize("tool", SAMPLES)
def test_malformed_and_empty_failure(tool):
    assert parse_output(tool, "pinned", "broken").state == "error"
    assert parse_output(tool, "pinned", "", exit_code=1).state == "error"


@pytest.mark.parametrize("tool,raw", [("zap", '{"site":[]}'), ("nuclei", ""), ("testssl", "[]")])
def test_valid_empty_output(tool, raw):
    result = parse_output(tool, "pinned", raw)
    assert result.state == "completed" and not result.observations
