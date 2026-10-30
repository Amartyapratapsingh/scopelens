"""Optional prose rewrite after deterministic report creation; failure keeps templates."""

from scopelens.adapters.roles import Explanation
from scopelens.orchestration.models import call_model
from scopelens.persistence.models import ScanRow
from scopelens.persistence.session import session_scope
from scopelens.writer.plain_language import COPY
from scopelens.writer.report import build_report


def enrich(settings, scan_id):
    if not settings.report_writer_model.configured:
        return
    with session_scope(settings) as db:
        scan = db.get(ScanRow, scan_id)
        findings = build_report(session=db, scan=scan)["findings"]
    prose = {}
    # Reviewed plain-language controls already have complete, evidence-bounded prose.
    # Do not spend provider budget producing copy that the public report deliberately ignores.
    findings = [finding for finding in findings if finding["check_id"] not in COPY]
    for finding in findings[: settings.model_max_calls]:
        result = call_model(
            settings,
            scan_id,
            "report_writer",
            {k: finding[k] for k in ["check_id", "severity", "detail", "what", "why", "fix"]},
        )
        if result.get("state") == "completed":
            prose[finding["id"]] = Explanation.model_validate(result["value"]).model_dump()
    with session_scope(settings) as db:
        from sqlalchemy import select

        scan = db.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
        scan.assessment_plan = {**(scan.assessment_plan or {}), "report_prose": prose}
