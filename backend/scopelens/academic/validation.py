"""Validate stored plan bindings before displaying frozen report coverage."""

from scopelens.discovery.review import project_review


def validate_frozen_plans(scan):
    frozen = scan.assessment_plan or {}
    revisions = frozen.get("assessment_plan_revisions", [])
    if not isinstance(revisions, list):
        raise ValueError("invalid revision history")
    for row in revisions:
        project_review(
            scan_id=scan.id,
            scope_version_id=scan.scope_version_id,
            profile=scan.profile,
            origin=scan.target_origin,
            frozen=frozen,
            plan_id=row["plan"]["id"],
            limit=1,
        )
    current = frozen.get("input_assessment_plan")
    catalogue = frozen.get("request_catalogue")
    if current is None:
        return
    if catalogue is None:
        raise ValueError("plan catalogue missing")
    if revisions and not any(
        r["plan"] == current and r["catalogue"] == catalogue for r in revisions
    ):
        raise ValueError("current plan does not match history")
    project_review(
        scan_id=scan.id,
        scope_version_id=scan.scope_version_id,
        profile=scan.profile,
        origin=scan.target_origin,
        frozen={"assessment_plan_revisions": [{"plan": current, "catalogue": catalogue}]},
        plan_id=current["id"],
        limit=1,
    )
