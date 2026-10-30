from scopelens.checks.engine import CheckContext
from scopelens.domain.collection import CollectedData, CollectedResponse, TLSMeasurement
from scopelens.domain.enums import ProfileName
from scopelens.domain.surface import AttackSurfaceMap, EndpointRecord, TechFingerprint


def response(route="/", body="<html><p>Example</p></html>", status=200, **overrides):
    defaults = dict(
        url="https://example.test" + route,
        route=route,
        status=status,
        content_type="text/html",
        body_excerpt=body,
        body_bytes=len(body),
        via_proxy=True,
        headers={
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "strict-transport-security": "max-age=63072000",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "allow": "GET, HEAD",
        },
        set_cookie=("sessionid=synthetic; Secure; HttpOnly; SameSite=Strict; Path=/",),
    )
    defaults.update(overrides)
    return CollectedResponse(**defaults)


def context(responses=None, **overrides):
    responses = (
        responses
        if responses is not None
        else (
            response(),
            *(
                response(path, "", 404)
                for path in (
                    "/.env",
                    "/.git/config",
                    "/backup.sql",
                    "/.scopelens-not-found-control",
                )
            ),
        )
    )
    tls = TLSMeasurement(
        host="example.test",
        port=443,
        reachable=True,
        protocol_version="TLSv1.3",
        not_before="Jan 01 00:00:00 2026 GMT",
        not_after="Jan 01 00:00:00 2028 GMT",
        measured_at="2026-09-25T00:00:00+00:00",
        certificate_verified=True,
        legacy_protocols={"TLSv1": "rejected", "TLSv1.1": "rejected"},
    )
    data = CollectedData(
        origin="https://example.test",
        scheme="https",
        host="example.test",
        port=443,
        responses=tuple(responses),
        tls=tls,
        transport_http_authorized=True,
        cleartext_probe=response(
            "transport-http:/",
            "",
            301,
            url="http://example.test/",
            headers={"location": "https://example.test/"},
        ),
    )
    defaults = dict(
        data=data,
        surface=AttackSurfaceMap(
            origin=data.origin,
            endpoints=(
                EndpointRecord(url=data.origin + "/", route="/", discovered_via="seed", depth=0),
            ),
            tech=(
                TechFingerprint(
                    name="fixture", version="2.0.0", source="header", evidence="fixture/2.0.0"
                ),
            ),
        ),
        profile=ProfileName.EXTERNAL_CONFIGURATION,
        evidence={
            "crawl": "capture-1",
            "tls": "capture-2",
            "scope": "scope-1",
            "cleartext": "capture-3",
            "advisories": "advisory-1",
        },
        advisory_snapshot={
            "sha256": "a" * 64,
            "bundle": {
                "version": "fixture-v1",
                "source": "synthetic test data",
                "packages": {"fixture": "npm:fixture"},
                "records": [
                    {
                        "id": "x_FIXTURE-1",
                        "modified": "2026-09-25T00:00:00Z",
                        "affected": [
                            {
                                "package": {"ecosystem": "npm", "name": "fixture"},
                                "ranges": [
                                    {
                                        "type": "SEMVER",
                                        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
        },
    )
    defaults.update(overrides)
    return CheckContext(**defaults)
