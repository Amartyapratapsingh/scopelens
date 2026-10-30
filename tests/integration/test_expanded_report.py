"""Frozen expansion score metadata and public reach summary in both exports."""

import pytest

from scopelens.checks.analyze import _snapshot_payload
from scopelens.domain.enums import Category, ProfileName
from scopelens.persistence.models import CheckOutcomeRow, ScoreSnapshotRow
from scopelens.scoring.profiles import rubric_for
from scopelens.scoring.score import OVERALL_LABEL, score
from scopelens.writer.report import build_report, render_html, render_json

pytestmark = pytest.mark.db


def save_snapshot(session, scan, profile):
    snapshot = score(
        profile=profile,
        outcomes=[],
        findings=[],
        mandatory_controls={"missing-auth"},
        planned_controls={"missing-auth": Category.C08_AUTHENTICATION},
    )
    session.add(
        ScoreSnapshotRow(
            scan_id=scan.id,
            profile=profile.value,
            score_version=snapshot.score_version,
            verdict=snapshot.verdict,
            overall_score=None,
            coverage_percent=0,
            payload=_snapshot_payload(snapshot),
        )
    )
    session.flush()
    return snapshot


@pytest.mark.parametrize(
    "profile", [ProfileName.AUTHENTICATED_API_V1, ProfileName.STAGING_STATEFUL_V1]
)
def test_report_uses_persisted_expanded_weights_label_and_exclusions(
    queued_scan, db_session, profile
):
    scan, _ = queued_scan
    scan.profile = profile.value
    snapshot = save_snapshot(db_session, scan, profile)
    report = build_report(session=db_session, scan=scan)
    assert report["overall_label"] == snapshot.overall.label
    assert report["score_version"] == snapshot.score_version
    assert report["score"]["profile_weights"] == {
        c.value: w for c, w in rubric_for(profile).weights
    }
    excluded = {row["category"] for row in report["score"]["out_of_profile_categories"]}
    assert "C08" not in excluded and "C09" not in excluded
    assert ("C10" in excluded) == (profile == ProfileName.AUTHENTICATED_API_V1)
    assert report["score"]["score"] is None
    assert snapshot.score_version in render_html(report)


def test_public_summary_has_counts_and_declared_roles_without_configuration_secrets(
    queued_scan, db_session
):
    scan, _ = queued_scan
    scan.profile = ProfileName.STAGING_STATEFUL_V1.value
    scan.assessment_plan = {
        "expansion_capability_hash": "opaque-capability-not-public",
        "expansion_config": {
            "identities": [
                {
                    "id": "alice",
                    "role": "<em>fixture-role</em>",
                    "tenant": "private-tenant",
                    "login": {"request": {"url": "https://secret-login.example/"}},
                    "supplied_headers": {"X-API-Key": "private-credential-reference"},
                }
            ],
            "browser_workflows": [{"recipe_id": "private-recipe-detail"}],
        },
        "cleanup_status": [{"recipe_id": "fixture-flow", "state": "mutation_sent"}],
    }
    db_session.add(
        CheckOutcomeRow(
            scan_id=scan.id,
            check_id="SL-C09-AUTH-01",
            canonical_control="authorization.object",
            category="C09",
            status="inconclusive",
            summary="Incomplete role comparison",
            payload={
                "required_instances": ["owner", "other", "other"],
                "completed_instances": ["owner", "unplanned"],
                "incomplete_reasons": ["<strong>cleanup pending</strong>"],
            },
        )
    )
    db_session.flush()
    report = build_report(session=db_session, scan=scan)
    summary = report["assessment_summary"]
    assert summary["identities"] == [{"id": "alice", "role": "<em>fixture-role</em>"}]
    assert (summary["required"], summary["completed"], summary["missing"]) == (2, 1, 1)
    assert summary["checks"][0]["missing"] == 1
    assert summary["cleanup"] == [{"recipe_id": "fixture-flow", "state": "mutation_sent"}]
    assert "declaration does not prove" in summary["scope_note"]
    exported = render_json(report)
    html = render_html(report)
    for secret in (
        "private-tenant",
        "secret-login.example",
        "private-credential-reference",
        "private-recipe-detail",
        "opaque-capability-not-public",
    ):
        assert secret not in exported and secret not in html
    assert "<em>fixture-role</em>" not in html
    assert "&lt;em&gt;fixture-role&lt;/em&gt;" in html
    assert "<strong>cleanup pending</strong>" not in html
    assert "&lt;strong&gt;cleanup pending&lt;/strong&gt;" in html
    assert "mutation_sent" in html


def test_legacy_report_without_snapshot_keeps_metadata_and_omits_expansion_section(
    queued_scan, db_session
):
    scan, _ = queued_scan
    report = build_report(session=db_session, scan=scan)
    assert report["overall_label"] == OVERALL_LABEL
    assert report["assessment_summary"] is None
    assert "C08" not in report["score"]["profile_weights"]
    assert {row["category"] for row in report["score"]["out_of_profile_categories"]} == {
        "C08",
        "C09",
        "C10",
        "C11",
        "C12",
    }
    assert "Assessment reach and cleanup" not in render_html(report)
