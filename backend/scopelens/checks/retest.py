"""Settle finding retests from fresh, persisted control outcomes."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from scopelens.domain.check import ControlOutcome
from scopelens.domain.enums import ControlOutcome as OutcomeStatus
from scopelens.domain.enums import ProfileName
from scopelens.persistence.models import CheckOutcomeRow, FindingRow, ScanRow
from scopelens.persistence.repositories import record_audit


def reconcile_retests(session: Session, scan: ScanRow) -> None:
    if scan.status not in {"completed", "completed_partial", "failed", "cancelled"}:
        return
    originals = session.scalars(
        select(FindingRow)
        .where(FindingRow.retest_scan_id == scan.id, FindingRow.retest_state == "requested")
        .with_for_update()
    ).all()
    for original in originals:
        source_scan = session.get(ScanRow, original.scan_id)
        result = session.scalar(
            select(CheckOutcomeRow).where(
                CheckOutcomeRow.scan_id == scan.id, CheckOutcomeRow.check_id == original.check_id
            )
        )
        outcome = ControlOutcome.model_validate(result.payload) if result else None
        routes = {loc["route"] for loc in original.locations}
        completed = set(outcome.completed_instances) if outcome else set()
        special = original.check_id in {"SL-C01-TLS-01", "SL-C01-REDIR-01"}
        coverage_ok = bool(
            outcome and outcome.is_fully_assessed and (special or routes <= completed)
        )
        if any("{id}" in route for route in routes):
            coverage_ok = False  # A normalized route is not a concrete retest location.
        expanded = bool(source_scan and ProfileName(source_scan.profile).expanded)
        binding_ok = True
        if expanded:
            source_plan, fresh_plan = source_scan.assessment_plan or {}, scan.assessment_plan or {}
            binding_ok = bool(
                source_scan.scope_version_id == scan.scope_version_id
                and source_scan.profile == scan.profile
                and source_scan.operator_id == scan.operator_id
                and source_plan.get("configuration_hash")
                and source_plan.get("configuration_hash") == fresh_plan.get("configuration_hash")
                and source_plan.get("configuration_id") == fresh_plan.get("configuration_id")
                and source_plan.get("expansion_config") == fresh_plan.get("expansion_config")
            )
            if not binding_ok and fresh_plan.get("retest_renewal"):
                from scopelens.checks.retest_binding import renewal_binding_valid

                binding_ok = renewal_binding_valid(session, source_scan, scan)
            source_row = session.scalar(
                select(CheckOutcomeRow).where(
                    CheckOutcomeRow.scan_id == original.scan_id,
                    CheckOutcomeRow.check_id == original.check_id,
                )
            )
            source_outcome = (
                ControlOutcome.model_validate(source_row.payload) if source_row else None
            )
            # Expanded instances are case/task IDs, rather than URLs. Retest the same
            # frozen denominator, including proof and verified cleanup for every case.
            coverage_ok = bool(
                binding_ok
                and outcome
                and source_outcome
                and outcome.canonical_control == source_outcome.canonical_control
                and outcome.status == OutcomeStatus.PASS
                and outcome.is_fully_assessed
                and source_outcome.required_instances
                and set(source_outcome.required_instances) == set(outcome.required_instances)
                and outcome.proof
                and outcome.proof.satisfied
                and outcome.proof.evidence_refs
            )
        current = session.scalars(
            select(FindingRow).where(
                FindingRow.scan_id == scan.id, FindingRow.check_id == original.check_id
            )
        ).all()
        still_present = any(loc["route"] in routes for row in current for loc in row.locations)
        state = "incomplete"
        if binding_ok and scan.status in {"completed", "completed_partial"} and still_present:
            state = "still_present"
            original.status = "open"
        elif coverage_ok and (
            scan.status == "completed" or (expanded and scan.status == "completed_partial")
        ):
            state = "fixed"
            original.status = "resolved"
        original.retest_state = state
        record_audit(
            session,
            actor="retest",
            action="retest.complete",
            subject_type="scan",
            subject_id=str(scan.id),
            outcome=state,
            detail={
                "scan_id": str(scan.id),
                "finding_id": str(original.id),
                "evidence_refs": list(outcome.proof.evidence_refs)
                if outcome and outcome.proof
                else [],
            },
        )
    session.flush()
