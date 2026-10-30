"""Worker callback RPC facade: no signing key, database access or direct collector client."""

from __future__ import annotations

import hashlib
import json
from contextlib import suppress

from scopelens.callbacks.probes import run_callback_probe
from scopelens.domain.callback import CallbackAssessment, CallbackNonce, CallbackReceipt


class CallbackControlClient:
    """`rpc(payload)` uses the existing broker-local authenticated control channel."""

    def __init__(self, rpc, task):
        self.rpc, self.task = rpc, task
        self.failed = False
        self.nonces = {}
        self.cached_receipts = {}

    def _call(self, operation, **fields):
        try:
            value = self.rpc({"operation": operation, "recipe_id": self.task.recipe_id, **fields})
            if not value.get("allowed"):
                raise PermissionError("callback RPC denied")
            return value
        except Exception as exc:
            self.failed = True
            raise OSError("callback control unavailable") from exc

    def issue(self, **kwargs):
        task = self.task
        recipe = task.recipe
        expected = dict(
            owner_id=task.owner_id,
            scan_id=task.scan_id,
            task_id=task.task_id,
            family=recipe.family,
            callback_origin=recipe.callback_origin,
            expected_target_peers=set(recipe.expected_target_peers),
            scanner_peers=set(recipe.scanner_peers),
            ttl_seconds=60,
        )
        if any(kwargs.get(key) != value for key, value in expected.items()):
            raise ValueError("callback client recipe mismatch")
        nonce = CallbackNonce.model_validate(
            self._call("issue", purpose=kwargs["purpose"])["nonce"]
        )
        if (nonce.scan_id, nonce.task_id, nonce.family, nonce.purpose) != (
            task.scan_id,
            task.task_id,
            recipe.family,
            kwargs["purpose"],
        ):
            raise ValueError("callback nonce response binding mismatch")
        self.nonces[nonce.id] = nonce
        return nonce

    def receipts(self, nonce_id, **kwargs):
        if nonce_id not in self.nonces or kwargs != dict(
            owner_id=self.task.owner_id, scan_id=self.task.scan_id, task_id=self.task.task_id
        ):
            raise ValueError("callback receipt query binding mismatch")
        values = [
            CallbackReceipt.model_validate(r)
            for r in self._call("query", nonce_id=nonce_id)["receipts"]
        ]
        for receipt in values:
            if (receipt.nonce_id, receipt.scan_id, receipt.task_id) != (
                nonce_id,
                self.task.scan_id,
                self.task.task_id,
            ):
                raise ValueError("callback receipt response binding mismatch")
            self.cached_receipts[receipt.id] = receipt
        return values

    def verify(self, receipt):
        value = self._call("verify", nonce_id=receipt.nonce_id, receipt_id=receipt.id)
        digest = hashlib.sha256(
            json.dumps(receipt.model_dump(), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return value.get("valid") is True and value.get("receipt_digest") == digest

    def revoke_nonce(self, nonce_id, *, owner_id):
        if nonce_id not in self.nonces or owner_id != self.task.owner_id:
            self.failed = True
            return
        # Existing collector revokes in finally. Failed RPC must not erase evidence;
        # the nonce TTL still applies and the supervisor revokes on recovery.
        with suppress(OSError):
            self._call("revoke", nonce_id=nonce_id)


def collect_remote_callback(client, control: CallbackControlClient, *, cancelled=lambda: False):
    """Return evidence-bearing partial results even if query/revocation RPC fails."""
    task = control.task
    try:
        result = run_callback_probe(
            client,
            control,
            task.recipe,
            owner_id=task.owner_id,
            scan_id=task.scan_id,
            task_id=task.task_id,
            cancelled=cancelled,
        )
    except (OSError, ValueError, PermissionError):
        result = CallbackAssessment(
            family=task.recipe.family, state="blocked", reason="Callback control unavailable"
        )
    result.nonce_ids = list(dict.fromkeys([*result.nonce_ids, *control.nonces]))
    receipts = {r.id: r for r in result.receipts}
    receipts.update(control.cached_receipts)
    result.receipts = list(receipts.values())
    if control.failed:
        result.state, result.reason = (
            "blocked",
            "Callback control unavailable; partial evidence retained",
        )
    return result
