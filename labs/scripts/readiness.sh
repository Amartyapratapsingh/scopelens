#!/usr/bin/env sh
# Wait for both lab fixtures to report ready.
#
# Readiness is asserted over HTTP and HTTPS on loopback. A fixture that is up but not
# serving is not ready, and a measured run must never start against it.
#
# NOTE: this is operator-side fixture tooling. It is not scanner code and is never
# imported by the backend (see docs/OPEN_QUESTIONS.md Q-3).
set -eu

TIMEOUT_SECONDS=${LABS_READY_TIMEOUT:-60}

wait_for() {
    url="$1"
    name="$2"
    insecure="$3"
    deadline=$(( $(date +%s) + TIMEOUT_SECONDS ))
    # Always make the first probe, even if computing the deadline crosses a second.
    while :; do
        if curl $insecure -fsS -o /dev/null --max-time 3 "$url" 2>/dev/null; then
            echo "ready: $name ($url)"
            return 0
        fi
        [ "$(date +%s)" -lt "$deadline" ] || break
        sleep 1
        [ "$(date +%s)" -lt "$deadline" ] || break
    done
    echo "readiness: ERROR $name did not become ready within ${TIMEOUT_SECONDS}s ($url)" >&2
    return 1
}

wait_for "http://127.0.0.1:8081/healthz"  "labs-bad  http " ""
wait_for "https://127.0.0.1:8443/healthz" "labs-bad  https" "-k"
wait_for "http://127.0.0.1:8082/healthz"  "labs-good http " ""
wait_for "https://127.0.0.1:8444/healthz" "labs-good https" "-k"

# The nginx health endpoints do not check the dynamic service behind /active/.
# A stopped fixture must fail readiness before any measured input probes run.
wait_for "http://127.0.0.1:8081/active/xss?q=scopelens" "labs-bad dynamic fixture" ""
wait_for "http://127.0.0.1:8082/active/xss?q=scopelens" "labs-good dynamic fixture" ""

echo "readiness: all fixtures ready"
