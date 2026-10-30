import httpx
import pytest

from scopelens.expansion.client import AssessmentControlClient


@pytest.mark.parametrize("failure", ["status", "timeout", "malformed", "shape"])
def test_transport_failures_use_cleanup_preservation_contract(monkeypatch, failure):
    monkeypatch.setenv("SCOPELENS_EXPANSION_CAPABILITY", "synthetic-private-capability")

    def transport(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("synthetic-private-capability", request=request)
        if failure == "status":
            return httpx.Response(503, text="synthetic-private-capability")
        if failure == "malformed":
            return httpx.Response(200, text="not-json")
        return httpx.Response(200, json=[])

    with httpx.Client(transport=httpx.MockTransport(transport)) as http:
        control = AssessmentControlClient(http)
        assert control.claim("recipe", "resource") is False
        with pytest.raises(PermissionError, match="assessment_control_") as caught:
            control.mark("recipe", "resource", "cleanup_failed")
        assert "synthetic-private-capability" not in str(caught.value)
