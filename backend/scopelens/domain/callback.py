"""Typed callback correlation contracts. Receipt signatures authenticate the collector."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CallbackNonce(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    scan_id: str
    task_id: str
    family: Literal["ssrf", "xxe"]
    purpose: Literal["positive", "negative"]
    url: str
    expires_at: float


class CallbackReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    nonce_id: str
    scan_id: str
    task_id: str
    at: float
    protocol: Literal["http", "dns"]
    peer: str
    source: Literal["target", "scanner", "unknown"]
    method: str
    signature: str


class CallbackAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    family: Literal["ssrf", "xxe"]
    state: Literal["confirmed", "inconclusive", "blocked", "cancelled", "pass"]
    reason: str
    nonce_ids: list[str] = Field(default_factory=list)
    receipts: list[CallbackReceipt] = Field(default_factory=list)
    requests: int = 0
    target_route: str = "/"
