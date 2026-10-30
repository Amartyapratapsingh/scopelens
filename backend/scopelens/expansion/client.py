"""Worker's narrow control client. Uses proxy-local RPC, never direct control-plane access."""

import os

import httpx
from pydantic import SecretStr


class AssessmentControlClient:
    def __init__(self, http):
        self.http = http
        self.capability = os.environ["SCOPELENS_EXPANSION_CAPABILITY"]

    def call(self, operation, **fields):
        try:
            response = self.http.post(
                "http://scopelens-broker.invalid/assessment",
                json={"operation": operation, "capability": self.capability, **fields},
            )
            response.raise_for_status()
            result = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # Match the workflow cleanup contract, which preserves partial evidence
            # on PermissionError. Never include credentials or the reply body.
            raise PermissionError("assessment_control_unavailable") from exc
        if not isinstance(result, dict):
            raise PermissionError("assessment_control_invalid_reply")
        if not result.get("allowed"):
            raise PermissionError(result.get("reason", "assessment_control_denied"))
        return result

    def secret(self, reference):
        return SecretStr(self.call("credential", reference=reference)["value"])

    def claim(self, recipe_id, resource_id):
        try:
            self.call("cleanup_claim", recipe_id=recipe_id, resource_id=resource_id)
            return True
        except PermissionError:
            return False

    def mark(self, recipe_id, resource_id, state):
        self.call("cleanup_mark", recipe_id=recipe_id, resource_id=resource_id, state=state)

    def state(self, recipe_id, resource_id):
        return self.call("cleanup_state", recipe_id=recipe_id, resource_id=resource_id)["state"]

    def callback_rpc(self, payload):
        """Narrow adapter for CallbackControlClient; no worker ownership/peer fields."""
        allowed = {"operation", "recipe_id", "purpose", "nonce_id", "receipt_id"}
        if set(payload) - allowed or payload.get("operation") not in {
            "issue",
            "query",
            "revoke",
            "verify",
        }:
            raise ValueError("unreviewed callback RPC fields")
        return self.call(
            "callback_" + payload["operation"],
            callback_recipe_id=payload.get("recipe_id"),
            callback_purpose=payload.get("purpose"),
            callback_nonce_id=payload.get("nonce_id"),
            callback_receipt_id=payload.get("receipt_id"),
        )
