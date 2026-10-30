from dataclasses import replace

import pytest
from tests.m2_helpers import context, response

from scopelens.checks.controls import CONTROLS, browser, exposure, transport
from scopelens.checks.engine import ControlInvariantError, _record_instances, validate_outcome
from scopelens.domain.enums import ControlOutcome as Outcome


@pytest.mark.parametrize(
    "control",
    [
        c
        for c in CONTROLS
        if c.check_id
        not in {
            "SL-C03-XSS-01",
            "SL-C03-SQL-01",
            "SL-C03-HTML-01",
            "SL-C04-REDIRECT-01",
            "SL-C04-CORS-01",
        }
    ],
    ids=lambda c: c.check_id,
)
def test_fixed_captured_controls_have_valid_evidenced_outcomes(control):
    ctx = context()
    result = _record_instances(control.evaluate(ctx), ctx)
    validate_outcome(result)
    assert result.status in {Outcome.PASS, Outcome.NOT_APPLICABLE}
    assert result.proof.evidence_refs if result.status == Outcome.PASS else result.na_evidence_ref


@pytest.mark.parametrize("control", CONTROLS, ids=lambda c: c.check_id)
def test_missing_evidence_cannot_be_conclusive(control):
    ctx = context(evidence={})
    result = control.evaluate(ctx)
    try:
        result = _record_instances(result, ctx)
    except ControlInvariantError:
        return
    assert not result.is_fully_assessed


@pytest.mark.parametrize("body", ["", "<html>Page not found</html>"])
def test_soft_404_and_empty_200_do_not_confirm_exposure(body):
    ctx = context([response("/.env", body), response("/.scopelens-not-found-control", body)])
    assert exposure.evaluate_exposed_files(ctx).status != Outcome.CONFIRMED_ISSUE


def test_file_content_requires_negative_control_and_keeps_missing_paths_unassessed():
    ctx = context(
        [
            response("/.env", "API_KEY=synthetic", content_type="text/plain"),
            response("/.scopelens-not-found-control", "not found", 404),
        ]
    )
    result = exposure.evaluate_exposed_files(ctx)
    assert result.status == Outcome.CONFIRMED_ISSUE
    assert not result.is_fully_assessed
    assert result.completed_instances == ("/.env",)
    assert "synthetic" not in result.summary


def test_one_404_does_not_pass_three_probes():
    result = exposure.evaluate_exposed_files(context([response("/.env", "", 404)]))
    assert result.status == Outcome.INCONCLUSIVE
    assert not result.is_fully_assessed


def test_missing_cleartext_authority_is_unassessed():
    ctx = context()
    result = transport.evaluate_http_redirect(
        replace(
            ctx,
            data=ctx.data.model_copy(
                update={"cleartext_probe": None, "transport_http_authorized": False}
            ),
        )
    )
    assert result.status == Outcome.NOT_TESTED


def test_redirect_to_another_origin_is_not_a_pass():
    ctx = context()
    probe = ctx.data.cleartext_probe.model_copy(
        update={"headers": {"location": "https://elsewhere.test/"}}
    )
    assert (
        transport.evaluate_http_redirect(
            replace(ctx, data=ctx.data.model_copy(update={"cleartext_probe": probe}))
        ).status
        != Outcome.PASS
    )


@pytest.mark.parametrize("verified", [False, None])
def test_unverified_certificate_never_passes(verified):
    ctx = context()
    tls = ctx.data.tls.model_copy(
        update={"certificate_verified": verified, "verification_error": "hostname mismatch"}
    )
    assert (
        transport.evaluate_tls_certificate(
            replace(ctx, data=ctx.data.model_copy(update={"tls": tls}))
        ).status
        != Outcome.PASS
    )


def test_tls_uses_capture_time_and_legacy_offers():
    ctx = context()
    assert transport.evaluate_tls_certificate(ctx) == transport.evaluate_tls_certificate(ctx)
    tls = ctx.data.tls.model_copy(
        update={"legacy_protocols": {"TLSv1": "accepted", "TLSv1.1": "rejected"}}
    )
    assert (
        transport.evaluate_tls_certificate(
            replace(ctx, data=ctx.data.model_copy(update={"tls": tls}))
        ).status
        == Outcome.CONFIRMED_ISSUE
    )


@pytest.mark.parametrize(
    "html, expected",
    [
        ('<a href="http://example.test/docs">Docs</a>', Outcome.PASS),
        ('<script src="http://example.test/app.js"></script>', Outcome.CONFIRMED_ISSUE),
        ('<iframe src="http://example.test/frame"></iframe>', Outcome.CONFIRMED_ISSUE),
    ],
)
def test_mixed_resources_exclude_navigation(html, expected):
    assert transport.evaluate_mixed_content(context([response(body=html)])).status == expected


@pytest.mark.parametrize(
    "policy, expected",
    [
        ("default-src * 'unsafe-inline'", Outcome.CONFIRMED_ISSUE),
        ("default-src 'self'", Outcome.PASS),
        ("default-src *; default-src 'none'", Outcome.CONFIRMED_ISSUE),
        ("default-src *, default-src 'none'", Outcome.PASS),
        ("script-src-elem *; default-src 'none'", Outcome.CONFIRMED_ISSUE),
    ],
)
def test_effective_script_policy(policy, expected):
    assert (
        browser.evaluate_csp(
            context([response(headers={"content-security-policy": policy})])
        ).status
        == expected
    )


@pytest.mark.parametrize(
    "headers, expected",
    [
        (
            {"content-security-policy": "frame-ancestors *", "x-frame-options": "DENY"},
            Outcome.CONFIRMED_ISSUE,
        ),
        ({"x-frame-options": "garbage"}, Outcome.CONFIRMED_ISSUE),
        ({"x-frame-options": "DENY"}, Outcome.PASS),
        ({"content-security-policy": "frame-ancestors *, frame-ancestors 'none'"}, Outcome.PASS),
    ],
)
def test_frame_policy_precedence(headers, expected):
    assert (
        browser.evaluate_frame_protection(context([response(headers=headers)])).status == expected
    )


def test_blocked_and_truncated_instances_do_not_pass_coverage():
    ctx = context([response(), response("/later", truncated=True)])
    result = _record_instances(browser.evaluate_csp(ctx), ctx)
    assert not result.is_fully_assessed
    assert "/later" in result.required_instances
    assert "/later" not in result.completed_instances


def test_discovered_endpoint_without_capture_cannot_pass():
    from tests.m2_helpers import context

    from scopelens.checks.controls.browser import evaluate_csp
    from scopelens.checks.engine import _record_instances
    from scopelens.domain.surface import EndpointRecord

    ctx = context()
    ctx = replace(
        ctx,
        surface=ctx.surface.model_copy(
            update={
                "endpoints": (
                    *ctx.surface.endpoints,
                    EndpointRecord(
                        route="/missing",
                        method="GET",
                        url=ctx.data.origin + "/missing",
                        discovered_via="link",
                        depth=1,
                    ),
                )
            }
        ),
    )
    outcome = _record_instances(evaluate_csp(ctx), ctx)
    assert not outcome.is_fully_assessed
    assert "/missing" in outcome.required_instances
