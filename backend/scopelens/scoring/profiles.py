"""Versioned expansion pilot rubrics. Weights are policy, not measured risk probabilities."""

from dataclasses import dataclass

from scopelens.domain.enums import Category, ProfileName


@dataclass(frozen=True)
class PilotRubric:
    version: str
    weights: tuple[tuple[Category, int], ...]
    label: str


def rubric_for(profile: ProfileName) -> PilotRubric:
    """Return an explicit rubric for an expanded profile only."""
    weights = {
        ProfileName.EXTERNAL_DISCOVERY_V2: (15, 15, 20, 15, 15, 10, 10),
        ProfileName.EXTERNAL_ACTIVE_V2: (15, 15, 20, 15, 15, 10, 10),
        ProfileName.AUTHENTICATED_API_V1: (10, 10, 15, 10, 10, 5, 10, 15, 15),
        ProfileName.STAGING_STATEFUL_V1: (8, 8, 12, 8, 8, 4, 8, 12, 14, 8, 10),
    }[profile]
    return PilotRubric(
        version={
            ProfileName.EXTERNAL_DISCOVERY_V2: "score-discovery-v2-pilot-1",
            ProfileName.EXTERNAL_ACTIVE_V2: "score-active-v2-pilot-1",
            ProfileName.AUTHENTICATED_API_V1: "score-auth-api-v1-pilot-1",
            ProfileName.STAGING_STATEFUL_V1: "score-stateful-v1-pilot-1",
        }[profile],
        weights=tuple(zip(tuple(Category), weights, strict=False)),
        label=(
            f"{profile.report_title} pilot score — uncalibrated. "
            "Not a whole-website security rating. Different profiles or rubric versions "
            "are not directly comparable; coverage measures planned controls, not the "
            "percentage of all vulnerabilities found."
        ),
    )
