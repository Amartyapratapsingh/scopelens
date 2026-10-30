"""Per-case restoration history independent of the current resource admission fence."""

from sqlalchemy import select

from scopelens.persistence.models import AuditEventRow, CleanupRow


def cleanup_states_for_scan(session, scan):
    """Read only control-admitted transitions bound to this scan's frozen configuration.

    The resource row remains the admission fence. Its next clean claim can change its
    recipe or scan, so it cannot be the sole historical proof of earlier restoration.
    A new pending/failed claim for the same recipe supersedes that recipe's clean event.
    """
    frozen = scan.assessment_plan or {}
    configured = frozen.get("expansion_config", {})
    recipes = {
        recipe["id"]: recipe["resource_id"]
        for recipe in (*configured.get("workflows", []), *configured.get("browser_workflows", []))
    }
    rows = list(session.scalars(select(CleanupRow).where(CleanupRow.scan_id == scan.id)))
    states = {}
    last_event_at = {}
    events = session.scalars(
        select(AuditEventRow)
        .where(
            AuditEventRow.actor == "assessment-control",
            AuditEventRow.action == "workflow.cleanup_transition",
            AuditEventRow.subject_type == "scan",
            AuditEventRow.subject_id == str(scan.id),
        )
        .order_by(AuditEventRow.seq)
    )
    for event in events:
        detail = event.detail
        if (
            detail.get("scope_version_id") == str(scan.scope_version_id)
            and detail.get("configuration_hash") == frozen.get("configuration_hash")
            and detail.get("recipe_id") in recipes
            and recipes.get(detail.get("recipe_id")) == detail.get("resource_id")
            and event.outcome in {"pending", "mutation_sent", "clean", "cleanup_failed"}
        ):
            states[detail["recipe_id"]] = event.outcome
            last_event_at[detail["recipe_id"]] = event.occurred_at
    for row in rows:
        # A separately authorized recovery updates the current fence after its
        # original pending event; credit that verified recovery without rewriting
        # historical events or granting the old worker fresh mutation authority.
        if (
            row.recipe_id in recipes
            and recipes[row.recipe_id] == row.resource_id
            and (
                row.recipe_id not in last_event_at or row.updated_at >= last_event_at[row.recipe_id]
            )
        ):
            states[row.recipe_id] = row.state
    return states
