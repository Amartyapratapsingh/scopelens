"""Scanner output contracts. Tool observations never set product confirmation or scores."""

import hashlib
import json
from copy import deepcopy
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from scopelens.security.redaction import redact


class ScannerObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str
    tool_version: str
    rule_id: str
    title: str
    reported_severity: str
    reported_confidence: str | None = None
    locations: list[str] = Field(default_factory=list)
    evidence: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    status: Literal["potential"] = "potential"
    mapped_control: str | None = None
    finding_id: str | None = None
    output_hash: str

    @property
    def serious(self):
        return self.reported_severity.lower() in {"high", "critical"} and bool(
            self.evidence or self.evidence_refs
        )


class ProfileOmittedControl(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    check_id: str
    state: Literal["not_in_profile"] = "not_in_profile"
    reason: Literal["Not in profile"] = "Not in profile"


class ScannerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str
    version: str
    state: Literal["completed", "partial", "error", "timeout", "cancelled", "not_tested"]
    observations: list[ScannerObservation] = Field(default_factory=list)
    assessed_rule_ids: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    output_hash: str = ""
    template_hash: str | None = None
    not_in_profile_controls: list[ProfileOmittedControl] = Field(default_factory=list)


def omitted_active_controls(profile: str) -> list[dict]:
    """Presentation metadata only; these are never scoring outcomes or N/A claims."""
    if profile != "external-configuration":
        return []
    return [
        ProfileOmittedControl(check_id=check_id).model_dump()
        for check_id in (
            "SL-C03-XSS-01",
            "SL-C03-HTML-01",
            "SL-C03-SQL-01",
            "SL-C04-REDIRECT-01",
            "SL-C04-CORS-01",
        )
    ]


def scanner_profile_view(results: list[dict], profile: str) -> list[dict]:
    """Describe a deliberate profile exclusion without hiding an actual failure.

    The trusted scan profile, not a worker claim, determines the exclusion. Original
    artifact/plan data is untouched; active-profile missing approval remains a gap.
    """
    public = deepcopy(results)
    for result in public:
        # Profile exclusions are derived from the trusted scan, never a worker label.
        result.pop("not_in_profile_controls", None)
    omitted = omitted_active_controls(profile)
    if not omitted:
        return public
    for result in public:
        if (
            result.get("tool") == "conditional-config"
            and result.get("state") == "not_tested"
            and not result.get("observations")
            and not result.get("assessed_rule_ids")
            and result.get("errors", [])
            in ([], ["No reviewed endpoints enabled for this profile and origin"])
        ):
            result["errors"] = []
            result["not_in_profile_controls"] = omitted
    return public


ZAP_MAPPING = {
    "10038": "SL-C04-CSP-01",
    "10020": "SL-C04-FRAME-01",
    "10035": "SL-C01-HSTS-01",
    "10021": "SL-C04-XCTO-01",
}
NUCLEI_MAPPING = {"scopelens-csp-observation": "SL-C04-CSP-01"}


def parse_output(
    tool: str,
    version: str,
    raw: str,
    *,
    exit_code: int | None = 0,
    truncated=False,
    timed_out=False,
    cancelled=False,
) -> ScannerResult:
    digest = hashlib.sha256(raw.encode()).hexdigest()
    results = []
    assessed = []
    errors = []

    def add(rule, title, severity, locations, evidence="", confidence=None, mapped=None):
        results.append(
            ScannerObservation(
                tool=tool,
                tool_version=version,
                rule_id=str(rule),
                title=str(title),
                reported_severity=str(severity),
                reported_confidence=str(confidence) if confidence is not None else None,
                locations=[str(u) for u in locations],
                evidence=str(evidence)[:2000],
                mapped_control=mapped,
                output_hash=digest,
            )
        )

    try:
        if tool == "zap":
            data = json.loads(raw)
            if not isinstance(data, dict) or not isinstance(data.get("site"), list):
                raise ValueError("expected ZAP site array")
            for site in data["site"]:
                for alert in site.get("alerts", []):
                    rule = str(alert["pluginid"])
                    risk = str(alert.get("riskcode", "unknown"))
                    add(
                        rule,
                        alert["name"],
                        {"0": "informational", "1": "low", "2": "medium", "3": "high"}.get(
                            risk, risk
                        ),
                        [i["uri"] for i in alert.get("instances", [])],
                        "; ".join(str(i.get("evidence", "")) for i in alert.get("instances", [])),
                        alert.get("confidence"),
                        ZAP_MAPPING.get(rule),
                    )
        elif tool == "nuclei":
            if not raw.strip() and exit_code != 0:
                raise ValueError("empty failed Nuclei output")
            for line in raw.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                rule = item["template-id"]
                info = item["info"]
                add(
                    rule,
                    info["name"],
                    info["severity"],
                    [item.get("matched-at", item.get("host", ""))],
                    item.get("response") or json.dumps(item.get("extracted-results", [])),
                    mapped=NUCLEI_MAPPING.get(rule),
                )
        elif tool == "testssl":
            data = json.loads(raw)
            if not isinstance(data, list):
                raise ValueError("expected flat testssl JSON array")
            for item in data:
                severity = str(item["severity"]).lower()
                if severity in {"warn", "fatal"}:
                    errors.append(str(item.get("finding", "scanner diagnostic")))
                    continue
                assessed.append(str(item["id"]))
                if severity in {"ok", "info", "informational"}:
                    continue
                add(
                    item["id"],
                    item["id"],
                    severity,
                    [f"{item.get('ip', '')}:{item.get('port', '')}"],
                    item.get("finding", ""),
                )
        else:
            raise ValueError("unsupported scanner")
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        errors.append(f"malformed {tool} output: {type(exc).__name__}")
    if truncated:
        errors.append("output truncated")
    if exit_code != 0:
        errors.append(f"process exit {exit_code}")
    state = (
        "cancelled"
        if cancelled
        else "timeout"
        if timed_out
        else "partial"
        if errors and (results or assessed)
        else "error"
        if errors
        else "completed"
    )
    return ScannerResult.model_validate(
        redact(
            ScannerResult(
                tool=tool,
                version=version,
                state=state,
                observations=results,
                assessed_rule_ids=assessed,
                errors=errors,
                output_hash=digest,
            ).model_dump()
        )
    )
