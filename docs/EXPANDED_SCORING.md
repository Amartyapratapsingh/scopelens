# Expanded scoring pilot rubrics

The expansion proposal requires a separate version for changed categories and denominators.
It does not prescribe new category weights. The following explicit pilot weights are an
implementation policy, **uncalibrated** and not a measured distribution of website risk.
The legacy `score-v1.0` arithmetic and API defaults remain unchanged.

| Profile | Rubric version | Category weights, C01 onward | Excluded categories |
|---|---|---|---|
| external-discovery-v2 | score-discovery-v2-pilot-1 | 15, 15, 20, 15, 15, 10, 10 | C03 (active pack disabled), C08–C12 |
| external-active-v2 | score-active-v2-pilot-1 | 15, 15, 20, 15, 15, 10, 10 | C08–C12 |
| authenticated-api-v1 | score-auth-api-v1-pilot-1 | 10, 10, 15, 10, 10, 5, 10, 15, 15 | C10–C12 |
| staging-stateful-v1 | score-stateful-v1-pilot-1 | 8, 8, 12, 8, 8, 4, 8, 12, 14, 8, 10 | C12 |

The configured weights sum to 100 before profile exclusions. Evidence-backed fully N/A
categories and declared profile exclusions are removed before renormalization. An included
category with no planned controls is a coverage gap, not evidence of inapplicability.

## Caller contract

Call `scoring.score.score` with the existing arguments plus:

```python
profile=profile,
planned_controls={entry.id: entry.category for entry in frozen_registry.for_profile(profile)},
```

The frozen registry includes experimental and unsupported controls: only selecting enabled,
finished or successful checks would shrink the denominator. Pass mandatory IDs and coverage
weights from that same frozen registry. The existing engine validates proof and keeps an
experimental check without sufficient coverage as unassessed; scoring does not qualify a
capability or trust scanner/model verdicts.

Expanded profiles reject absent or empty planned-control maps. Missing planned results become
`not_tested`, including missing nonmandatory controls. Duplicate outcomes, unplanned outcomes,
category changes, mandatory IDs outside the map and nonpositive/nonfinite weights reject the
calculation explicitly. Findings from unmapped checks still participate in the existing global
High/Critical cap and serious-candidate hold, even though they cannot earn coverage.

An outcome counts as fully assessed only after every required endpoint/input/role instance is
complete and no incomplete reason remains. Unresolved cleanup therefore remains a coverage gap.
Hardening observations, candidate findings and confirmed vulnerabilities remain distinct outcome
and finding records; only confirmed deduplicated findings produce severity deductions. A
Potential High/Critical holds the overall score regardless of its category.

The ≥80% category coverage gate, all-mandatory-controls gate, deductions, severity caps,
interrupted-scan hold and display-only rounding are inherited from the original rubric. An
all-N/A category never scores 100. A missing applicable category blocks the overall number.

## Reporting and comparison

Persist `snapshot.score_version` and `snapshot.overall.label`; do not hardcode the old label.
The expanded label names the profile, marks it uncalibrated, explains that profile/rubric
versions are not directly comparable, and says coverage is planned-control completion rather
than the proportion of all website vulnerabilities found. Qualification remains a separate
release gate; these rubrics do not claim new families have passed held-out evaluation.

A historical comparison must show profile, rubric version, planned controls and control
weights. Rescoring old evidence under a new rubric is a separately labeled calculation.

## Verification

`pytest tests/unit/test_scoring.py tests/unit/test_m2_scoring_regressions.py tests/unit/test_expanded_scoring.py -q`

52 tests passed, including legacy worked examples, expanded category boundaries, missing
control/role/cleanup coverage, evidence-backed N/A, caps, serious candidates and invalid inputs.
