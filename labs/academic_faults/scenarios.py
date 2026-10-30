"""Exact .24 binding, using the existing academic identities and workflow models."""

from labs.academic_workflows.scenarios import identities, write_recipe

from scopelens.domain.expansion import AssessmentConfiguration

SERVICE = "labs-academic-faults"
ORIGIN = "http://172.28.0.24:8080"


def configuration(scope, reference, field=None):
    if (scope.get("lab_binding") or {}).get("service") != SERVICE or scope["origin"] != ORIGIN:
        raise ValueError("academic fault gate requires its exact owned lab binding")
    # Build through the shared academic model at a permitted development origin,
    # then replace each request URL with this separately admitted exact lab origin.
    development = "http://127.0.0.1:8080"
    profiles = [
        p.model_dump(mode="json") for p in identities(development, credential_reference=reference)
    ]
    workflows = [] if field is None else [write_recipe(development, field).model_dump(mode="json")]

    def bind(value):
        if isinstance(value, dict):
            return {k: bind(v) for k, v in value.items()}
        if isinstance(value, list):
            return [bind(v) for v in value]
        if isinstance(value, str) and value.startswith(development + "/"):
            return ORIGIN + value[len(development) :]
        return value

    return AssessmentConfiguration.model_validate(
        {
            "scope_version_id": scope["id"],
            "identities": bind(profiles),
            "workflows": bind(workflows),
        }
    ).model_dump(mode="json")
