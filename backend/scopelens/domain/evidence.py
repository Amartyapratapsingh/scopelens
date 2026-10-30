"""Evidence records (Build Plan §5.5).

Evidence is the only thing a finding may be based on, so its provenance is part of the
record rather than a convention: who captured it, for which run and task, under which
scope, at what time, and what it hashes to.

Two rules from §5.5 are structural here:

* **Only trusted writers may create evidence.** :class:`EvidenceOrigin` names them. A
  script's stdout is an ``UNTRUSTED_OBSERVATION`` and cannot be promoted by relabelling
  it — the verifier reads this field.
* **Raw observations are stored separately from interpretations.** An
  ``UNTRUSTED_OBSERVATION`` may inform a hypothesis; it may never be the artifact a
  proof rule is evaluated against.
"""

from __future__ import annotations

import enum
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EvidenceOrigin(enum.StrEnum):
    """Who wrote this evidence, and therefore how far it may be trusted."""

    #: Written by the policy broker from the request it actually admitted and observed.
    BROKER = "broker"
    #: Written by the supervisor from a worker's declared artifact.
    SUPERVISOR = "supervisor"
    #: Written by the TLS measurement lane from a real handshake.
    TLS_LANE = "tls_lane"
    #: A script or tool's own output. Informative, never proof.
    UNTRUSTED_OBSERVATION = "untrusted_observation"

    @property
    def is_trusted(self) -> bool:
        """Whether a proof rule may be evaluated against this record.

        Build Plan §5.14: a script printing ``confirmed=true`` is not evidence. Only the
        three trusted writers above may back a confirmation.
        """
        return self is not EvidenceOrigin.UNTRUSTED_OBSERVATION


class RedactionState(enum.StrEnum):
    #: Content was scanned for secrets/PII and rewritten where found.
    REDACTED = "redacted"
    #: Content was scanned and nothing sensitive matched.
    CLEAN = "clean"
    #: Content was not scanned. Only possible for content that never leaves the
    #: control plane; anything reaching a model or a report must be REDACTED or CLEAN.
    UNSCANNED = "unscanned"


class EvidenceRecord(BaseModel):
    """One capped artifact with provenance and an integrity hash.

    ``content_hash`` detects later modification. Build Plan §5.14 is explicit that it
    does **not** prove the claim true — it proves the bytes did not change after capture.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    scan_id: str
    task_id: str | None = None
    run_id: str | None = None

    origin: EvidenceOrigin
    #: What produced this: an adapter name, ``broker``, ``tls_lane``. Free-form but
    #: never model- or target-supplied.
    producer: str = Field(min_length=1)
    #: Hash of the script/tool that produced the content, when one was involved.
    producer_hash: str | None = None
    tool_version: str | None = None

    #: Scope + role the capture happened under. Without this an artifact cannot be tied
    #: to the authorization that permitted it.
    scope_version_id: str
    scope_content_hash: str
    role: str = "unauthenticated"

    captured_at: datetime
    content_hash: str
    content_bytes: int = Field(ge=0)
    content_ref: str = Field(min_length=1)
    truncated: bool = False
    redaction_state: RedactionState

    content_type: str | None = None
    #: Human-readable summary. Kept separate from the raw content so an interpretation
    #: can never be mistaken for the artifact.
    summary: str = ""

    @property
    def is_trusted(self) -> bool:
        return self.origin.is_trusted
