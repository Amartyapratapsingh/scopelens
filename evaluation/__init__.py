"""ScopeLens evaluation harness (schema and labels).

Deliberately a sibling of the ``scopelens`` application package rather than part of it.
Evaluation labels are an answer key, and Build Plan §7 requires that ground-truth and
answer-key interfaces are never reachable by scanner workers or model context. A
package boundary is easier to enforce — and to test — than a convention.

Nothing here runs in M0.
"""

from evaluation.manifest import (
    CaseOutcome,
    CaseRecord,
    EvaluationManifest,
    EvaluationManifestError,
    EvaluationRecord,
    ExpectedLabel,
    FixtureCase,
    Lifecycle,
    Partition,
    Proof,
    RunRecord,
    Split,
    TargetBuild,
    load_manifest,
)

__all__ = [
    "CaseOutcome",
    "CaseRecord",
    "EvaluationManifest",
    "EvaluationManifestError",
    "EvaluationRecord",
    "ExpectedLabel",
    "FixtureCase",
    "Lifecycle",
    "Partition",
    "Proof",
    "RunRecord",
    "Split",
    "TargetBuild",
    "load_manifest",
]
