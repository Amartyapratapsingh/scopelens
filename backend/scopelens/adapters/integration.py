"""Retain scanner provenance without granting tool output confirmation authority."""

from dataclasses import replace
from urllib.parse import urlsplit

from scopelens.adapters.scanners import ScannerResult
from scopelens.scoring.score import CategoryState


def integrate(artifacts, findings, snapshot):
    results = []
    pending = []
    for artifact in artifacts:
        if artifact.get("kind") != "scanner_result":
            continue
        try:
            result = ScannerResult.model_validate(artifact["data"])
        except ValueError:
            continue
        for item in result.observations:
            ref = artifact.get("evidence_ref")
            if ref:
                item.evidence_refs.append(ref)
            # Match only a registered control and an overlapping affected route.
            routes = {urlsplit(url).path or "/" for url in item.locations}
            match = next(
                (
                    f
                    for f in findings
                    if f.check_id == item.mapped_control
                    and routes.intersection(loc.route for loc in f.locations)
                ),
                None,
            )
            if match:
                item.finding_id = match.id
            # A tool report never settles its own serious candidate.
            if item.serious and not (match and match.is_confirmed):
                pending.append(f"{item.tool}:{item.rule_id}")
        results.append(result.model_dump())
    if pending:
        snapshot = replace(
            snapshot,
            verdict="Verification pending",
            overall=replace(
                snapshot.overall,
                state=CategoryState.VERIFICATION_PENDING,
                score=None,
                raw_score=None,
                reason="Unresolved scanner candidates: " + ", ".join(sorted(set(pending))),
            ),
        )
    return results, snapshot
