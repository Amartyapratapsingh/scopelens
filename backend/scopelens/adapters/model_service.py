"""Internal provider gateway; the policy service retains its control-only network."""

import hmac
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from scopelens.adapters.circuit import shared_circuit
from scopelens.adapters.roles import complete
from scopelens.api.deps import AppSettings

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


class CompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["planner", "verification", "report_writer", "script", "browser"]
    payload: dict[str, Any]
    remaining_cost: float = Field(gt=0, le=100)


@app.post("/complete")
def completion(
    payload: CompletionRequest, settings: AppSettings, authorization: str = Header(default="")
):
    expected = settings.session_secret.get_secret_value() if settings.session_secret else ""
    if not expected or not hmac.compare_digest(authorization, "Bearer " + expected):
        raise HTTPException(403, "provider gateway denied")
    name = "planner" if payload.role == "script" else payload.role
    role = getattr(settings, name + "_model")
    return complete(
        role,
        payload.role,
        payload.payload,
        approved=settings.approved_model_base_urls,
        remaining_cost=payload.remaining_cost,
        circuit=shared_circuit(settings.redis_url),
    )
