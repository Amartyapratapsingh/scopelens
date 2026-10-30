"""Reviewed SSRF/XXE callback probes with two independent nonces and inert controls.

These prove an unexpected HTTP interaction with the explicitly registered canary only.
They do not claim metadata access, local-file reads, command execution or data extraction.
No-callback results stay inconclusive because target egress restrictions can hide behavior.
"""

import time
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.sax.saxutils import escape, quoteattr

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from scopelens.callbacks.service import CallbackService
from scopelens.domain.callback import CallbackAssessment


class CallbackProbeRecipe(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    family: str
    target_url: str
    method: str = "GET"
    parameter: str | None = None
    callback_origin: str
    expected_target_peers: frozenset[str]
    scanner_peers: frozenset[str]
    approved_staging: bool = False
    unexpected_external_fetch: bool = False
    xml_root: str = "request"
    max_wait_seconds: float = Field(default=3, ge=0, le=20)

    @model_validator(mode="after")
    def validate_recipe(self):
        p = urlsplit(self.target_url)
        if (
            p.scheme not in {"http", "https"}
            or not p.hostname
            or p.username
            or p.password
            or p.fragment
        ):
            raise ValueError("exact approved HTTP target required")
        if not self.approved_staging or not self.unexpected_external_fetch:
            raise ValueError("staging approval and policy forbidding external fetch are required")
        if self.family == "ssrf":
            if (
                self.method != "GET"
                or not self.parameter
                or len(
                    [
                        k
                        for k, _ in parse_qsl(p.query, keep_blank_values=True)
                        if k == self.parameter
                    ]
                )
                != 1
            ):
                raise ValueError("SSRF requires one reviewed GET query parameter")
        elif self.family == "xxe":
            if (
                self.method != "POST"
                or self.parameter is not None
                or not self.xml_root.isidentifier()
                or len(self.xml_root) > 64
            ):
                raise ValueError("XXE requires approved POST XML endpoint and simple root name")
        else:
            raise ValueError("unreviewed callback family")
        return self


def run_callback_probe(
    client,
    service: CallbackService,
    recipe: CallbackProbeRecipe,
    *,
    owner_id: str,
    scan_id: str,
    task_id: str,
    cancelled: Callable[[], bool] = lambda: False,
) -> CallbackAssessment:
    assessment = CallbackAssessment(
        family=recipe.family,
        state="inconclusive",
        reason="No paired HTTP callback proof",
        target_route=urlsplit(recipe.target_url).path or "/",
    )
    nonces = []
    try:
        for purpose in ("negative", "positive", "positive"):
            if cancelled():
                assessment.state, assessment.reason = (
                    "cancelled",
                    "Cancelled before next canary request",
                )
                return assessment
            nonce = service.issue(
                owner_id=owner_id,
                scan_id=scan_id,
                task_id=task_id,
                family=recipe.family,
                purpose=purpose,
                callback_origin=recipe.callback_origin,
                expected_target_peers=set(recipe.expected_target_peers),
                scanner_peers=set(recipe.scanner_peers),
                ttl_seconds=60,
            )
            nonces.append(nonce)
            assessment.nonce_ids.append(nonce.id)
            if recipe.family == "ssrf":
                p = urlsplit(recipe.target_url)
                payload = (
                    nonce.url
                    if purpose == "positive"
                    else nonce.url.replace("http", "scopelens-inert", 1)
                )
                params = [
                    (k, payload if k == recipe.parameter else v)
                    for k, v in parse_qsl(p.query, keep_blank_values=True)
                ]
                url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(params), ""))
                kwargs = {}
            else:
                url = recipe.target_url
                root = recipe.xml_root
                if purpose == "negative":
                    body = f'<?xml version="1.0"?><{root}>{escape(nonce.url)}</{root}>'
                else:
                    body = f'<?xml version="1.0"?><!DOCTYPE {root} [<!ENTITY scopelens SYSTEM {quoteattr(nonce.url)}>]><{root}>&scopelens;</{root}>'
                kwargs = {"content": body.encode(), "headers": {"Content-Type": "application/xml"}}
            assessment.requests += 1
            with client.stream(recipe.method, url, follow_redirects=False, **kwargs) as response:
                # Read a bounded result to distinguish transport failure from accepted probe;
                # response content is unnecessary for callback proof and is never retained.
                if response.status_code >= 500 or response.status_code in {401, 403, 429}:
                    assessment.reason = (
                        "Endpoint blocked or failed the probe; callback assessment incomplete"
                    )
                    return assessment
                for _, _chunk in zip(range(16), response.iter_bytes(chunk_size=4096), strict=False):
                    if cancelled():
                        assessment.state, assessment.reason = (
                            "cancelled",
                            "Cancelled during probe response",
                        )
                        return assessment
        deadline = time.monotonic() + recipe.max_wait_seconds
        while True:
            if cancelled():
                assessment.state, assessment.reason = (
                    "cancelled",
                    "Cancelled while awaiting receipts",
                )
                return assessment
            records = {
                n.id: service.receipts(n.id, owner_id=owner_id, scan_id=scan_id, task_id=task_id)
                for n in nonces
            }
            assessment.receipts = [r for rows in records.values() for r in rows]
            if any(not service.verify(r) for r in assessment.receipts):
                assessment.reason = "Callback receipt signature failed"
                return assessment
            negative = records[nonces[0].id]
            if any(r.source == "target" for r in negative):
                assessment.reason = "Target also contacted negative control; family-specific behavior not established"
                return assessment
            positives = [
                any(
                    r.protocol == "http" and r.source == "target" and r.method in {"GET", "HEAD"}
                    for r in records[n.id]
                )
                for n in nonces[1:]
            ]
            if all(positives) and time.monotonic() >= deadline:
                assessment.state = "confirmed"
                assessment.reason = "Two independent scoped canary HTTP interactions from declared target egress; inert control had no target interaction. No file or metadata access inferred."
                return assessment
            if time.monotonic() >= deadline:
                assessment.reason = "Expected paired target HTTP interactions not observed; blocked egress and unsupported parser behavior remain alternatives"
                return assessment
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    except (httpx.HTTPError, OSError, ValueError):
        assessment.state, assessment.reason = (
            "blocked",
            "Callback prerequisites or broker-bound request failed",
        )
        return assessment
    finally:
        for nonce in nonces:
            service.revoke_nonce(nonce.id, owner_id=owner_id)


def evaluate_callback_assessment(assessment: CallbackAssessment, evidence_ref: str | None):
    """Convert trusted callback-pack capture to existing findings; scope is canary interaction."""
    from scopelens.domain.check import ControlOutcome, Location, ProofResult
    from scopelens.domain.enums import Category, EvidenceStatus, Severity
    from scopelens.domain.enums import ControlOutcome as Outcome

    confirmed = assessment.state == "confirmed" and bool(evidence_ref)
    family = assessment.family
    return ControlOutcome(
        check_id="SL-C07-SSRF-02" if family == "ssrf" else "SL-C03-XXE-02",
        canonical_control="api.unexpected_server_fetch"
        if family == "ssrf"
        else "input.external_xml_entity",
        category=Category.C07_API if family == "ssrf" else Category.C03_INJECTION,
        status=Outcome.CONFIRMED_ISSUE
        if confirmed
        else Outcome.BLOCKED
        if assessment.state == "blocked"
        else Outcome.INCONCLUSIVE,
        summary=assessment.reason,
        locations=(
            Location(route=assessment.target_route, detail="Correlated canary HTTP interaction"),
        )
        if confirmed
        else (),
        proposed_severity=Severity.MEDIUM if confirmed else None,
        proof=ProofResult(
            satisfied=confirmed,
            status=EvidenceStatus.CONFIRMED if confirmed else EvidenceStatus.INCONCLUSIVE,
            reasons=(
                assessment.reason,
                "Proof is limited to controlled HTTP canary interaction; no internal-data or local-file access claim",
            ),
            evidence_refs=(evidence_ref,) if evidence_ref else (),
        ),
        required_instances=tuple(assessment.nonce_ids),
        completed_instances=tuple(assessment.nonce_ids) if confirmed else (),
        incomplete_reasons=() if confirmed else (assessment.reason,),
    )
