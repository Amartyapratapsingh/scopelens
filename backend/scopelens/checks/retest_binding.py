"""Renew authority for an unchanged declared assessment, without rewriting its history."""

from copy import deepcopy

from sqlalchemy import select

from scopelens.domain.capabilities import canonical_sha256
from scopelens.persistence.models import AssessmentConfigurationRow


def case_contract(configuration):
    value = deepcopy(configuration)
    value.pop("scope_version_id", None)
    for identity in value.get("identities", []):
        identity.pop("expires_at", None)

    def walk(node):
        if isinstance(node, dict):
            result = {}
            for key, item in node.items():
                if key == "secret_ref":
                    result[key] = "renewed-credential-reference"
                elif key in {"secret_fields", "secret_headers", "supplied_headers"} and isinstance(
                    item, dict
                ):
                    result[key] = {name: "renewed-credential-reference" for name in item}
                else:
                    result[key] = walk(item)
            return result
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return canonical_sha256(walk(value))


def renewal_binding_valid(session, source, fresh):
    original, renewed = source.assessment_plan or {}, fresh.assessment_plan or {}
    renewal = renewed.get("retest_renewal", {})
    if not (
        source.operator_id == fresh.operator_id
        and source.target_origin == fresh.target_origin
        and source.profile == fresh.profile
        and source.scope_version.authority_domain == fresh.scope_version.authority_domain
        and renewal.get("source_scan_id") == str(source.id)
        and renewal.get("source_configuration_hash") == original.get("configuration_hash")
    ):
        return False
    for scan, plan in ((source, original), (fresh, renewed)):
        row = session.scalar(
            select(AssessmentConfigurationRow).where(
                AssessmentConfigurationRow.id == plan.get("configuration_id"),
                AssessmentConfigurationRow.operator_id == scan.operator_id,
                AssessmentConfigurationRow.scope_version_id == scan.scope_version_id,
            )
        )
        if (
            not row
            or row.content_hash != plan.get("configuration_hash")
            or row.configuration != plan.get("expansion_config")
            or canonical_sha256(row.configuration) != row.content_hash
        ):
            return False
    return bool(
        case_contract(original["expansion_config"])
        == case_contract(renewed["expansion_config"])
        == renewal.get("case_contract_hash")
    )
