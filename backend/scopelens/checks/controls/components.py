"""Component candidates from a frozen advisory bundle; banners never confirm CVEs."""

from scopelens.checks.advisories import affected_version
from scopelens.checks.engine import CheckContext
from scopelens.domain.check import ControlOutcome, Location, ProofResult, potential
from scopelens.domain.enums import Category, EvidenceStatus, Severity
from scopelens.domain.enums import ControlOutcome as Outcome


def evaluate_component_versions(ctx: CheckContext) -> ControlOutcome:
    check = dict(
        check_id="SL-C06-COMPONENT-01",
        canonical_control="components.version_disclosure",
        category=Category.C06_COMPONENTS,
    )
    snapshot = ctx.advisory_snapshot
    bundle = snapshot.get("bundle", {})
    if not bundle:
        return ControlOutcome(
            **check,
            status=Outcome.INCONCLUSIVE,
            summary="No versioned advisory bundle configured; CVE applicability unassessed",
        )
    reasons, locations, gaps = [], [], []
    severity = Severity.INFORMATIONAL
    considered = 0
    for fingerprint in ctx.surface.tech:
        key = bundle["packages"].get(fingerprint.name.lower())
        if key is None:
            # Passive discovery also produces non-component notes. Those are inventory.
            if fingerprint.source == "header" or fingerprint.version:
                gaps.append(f"No advisory mapping for {fingerprint.name}")
            continue
        considered += 1
        if not fingerprint.version:
            gaps.append(f"Exact {fingerprint.name} version not observed")
            continue
        relevant = 0
        for record in bundle["records"]:
            if record.get("withdrawn"):
                continue
            for affected in record["affected"]:
                package = affected.get("package", {})
                if f"{package.get('ecosystem')}:{package.get('name')}" != key:
                    continue
                relevant += 1
                matches = affected_version(fingerprint.version, affected)
                if matches is None:
                    gaps.append(f"Unsupported version range for {record['id']}")
                elif matches:
                    name = str(
                        record.get("database_specific", {}).get("severity", "medium")
                    ).lower()
                    risk = {"moderate": Severity.MEDIUM}.get(name)
                    if risk is None:
                        risk = (
                            Severity(name)
                            if name in {s.value for s in Severity}
                            else Severity.MEDIUM
                        )
                    severity = max(severity, risk, key=lambda s: s.deduction)
                    reasons.append(
                        f"{record['id']} ({record['modified']}) matches {fingerprint.name} {fingerprint.version}; "
                        f"observed via {fingerprint.source}; exact build and vendor backports remain unverified"
                    )
                    locations.append(
                        Location(
                            route="/",
                            detail=f"{fingerprint.name} {fingerprint.version}: {record['id']}",
                        )
                    )
        if not relevant:
            gaps.append(f"No advisory records cover the declared package {key}")
    provenance = f"Advisory snapshot {bundle['version']}, source {bundle['source']}, sha256 {snapshot['sha256']}"
    if locations:
        proof = ProofResult(
            satisfied=False,
            status=EvidenceStatus.POTENTIAL,
            reasons=(*reasons, provenance),
            evidence_refs=tuple(
                r for r in (ctx.evidence_ref("crawl"), ctx.evidence_ref("advisories")) if r
            ),
        )
        return potential(
            **check,
            summary="; ".join(reasons),
            proof=proof,
            locations=tuple(locations),
            severity=severity,
        )
    if not considered:
        gaps.append("No component matched the snapshot's declared package corpus")
    return ControlOutcome(
        **check,
        status=Outcome.INCONCLUSIVE if gaps else Outcome.PASS,
        summary="; ".join(gaps) or f"No matches within the declared package corpus. {provenance}",
        incomplete_reasons=tuple(gaps),
    )
