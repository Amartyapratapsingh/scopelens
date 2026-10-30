"""Leave the shared stack available between completed benchmark trials."""

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

INTER_TRIAL_GAP_SECONDS = 60
LOCK_OWNER = Path("/tmp/scopelens-stack.lock/owner")


def inter_trial_gap(output):
    """Observe lock handoffs without acquiring, changing or releasing the lock."""
    started = time.monotonic()
    receipt = {
        "started_at": datetime.now(UTC).isoformat(),
        "minimum_seconds": INTER_TRIAL_GAP_SECONDS,
        "observed_lock_tokens": [],
        "observation_errors": [],
        "complete": False,
    }
    last_token = None
    print("Trial released its lock; waiting 60 seconds before the next trial.", flush=True)
    try:
        while True:
            elapsed = time.monotonic() - started
            try:
                token = LOCK_OWNER.read_text().strip()
            except FileNotFoundError:
                token = None
            except OSError as error:
                token = None
                receipt["observation_errors"].append(type(error).__name__)
            if token and token != last_token:
                receipt["observed_lock_tokens"].append({"elapsed_seconds": elapsed, "token": token})
            last_token = token
            remaining = INTER_TRIAL_GAP_SECONDS - elapsed
            if remaining <= 0:
                receipt["complete"] = True
                break
            time.sleep(min(5, remaining))
    finally:
        receipt["ended_at"] = datetime.now(UTC).isoformat()
        receipt["elapsed_seconds"] = time.monotonic() - started
        with output.open("x") as stream:
            os.chmod(output, 0o600)
            json.dump(receipt, stream, indent=2)
            stream.write("\n")


def run_schedule(output, plan, candidate_commit, run_trial):
    """Run in the frozen order, with no automatic continuation after an error."""
    for index, (repeat, mode) in enumerate(plan):
        run_trial(output / f"repeat-{repeat}-{mode}", repeat, mode, candidate_commit)
        if index + 1 < len(plan):
            inter_trial_gap(output / f"gap-after-repeat-{repeat}-{mode}.json")
