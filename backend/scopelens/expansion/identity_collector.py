"""Fixed collector with a separate evidence stream for each frozen rule or recipe."""

from scopelens.domain.identity import PermissionMatrix
from scopelens.identities.assessment import run_access_comparisons
from scopelens.identities.lifecycle import check_session_policy
from scopelens.identities.proof import select_identity_response
from scopelens.identities.readiness import collect_identity_readiness
from scopelens.identities.sessions import IdentitySessions
from scopelens.workflows.assessment import run_read_probe, run_workflow


def collect_identity_assessments(
    configuration, control, client_factory, emit, *, cancelled, configuration_binding=None
):
    collect_identity_readiness(
        configuration,
        control.secret,
        client_factory,
        emit,
        cancelled=cancelled,
        configuration_binding=configuration_binding,
    )
    binding = {}
    matrix = configuration.permission_matrix or PermissionMatrix(
        version="session-probes-v1", objects=(), rules=()
    )

    def observe(identity, request, response):
        record = select_identity_response(
            identity,
            request,
            response,
            configuration.identities,
            matrix,
            evidence_ref="pending-intake",
        )
        emit("identity_response", {**record.model_dump(mode="json"), **binding})

    def capture(data):
        emit("identity_observation", {**data, **binding})
        return "pending-intake"

    with (
        IdentitySessions(
            configuration.identities,
            control.secret,
            client_factory,
            cancelled=cancelled,
            response_observer=observe,
        ) as sessions,
        IdentitySessions(
            configuration.identities,
            control.secret,
            client_factory,
            response_observer=observe,
        ) as cleanup_sessions,
    ):
        for rule in matrix.rules:
            binding = {"proof_type": "access", "proof_id": rule.id}
            run_access_comparisons(matrix.model_copy(update={"rules": (rule,)}), sessions, capture)
        for recipe in (*configuration.read_probes, *configuration.workflows):
            binding = {"proof_type": "workflow", "proof_id": recipe.id}
            if recipe in configuration.read_probes:
                result = run_read_probe(
                    recipe, sessions, capture, admit=lambda r: bool(r.action_grant_id)
                )
            else:
                result = run_workflow(
                    recipe,
                    sessions,
                    cleanup_sessions,
                    control,
                    capture,
                    admit=lambda r: bool(r.action_grant_id),
                )
            emit("workflow_capture", {**result.model_dump(mode="json"), **binding})
        for policy in configuration.session_policies:
            binding = {"proof_type": "session", "proof_id": policy.identity_id}
            for result in check_session_policy(policy, sessions, capture):
                emit("session_observation", {**result.model_dump(mode="json"), **binding})
