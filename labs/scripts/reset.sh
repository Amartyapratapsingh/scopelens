#!/usr/bin/env sh
# Reset the lab fixtures to a known state.
#
# This is the "reset fixtures between runs" step that Build Plan §7 and Project
# Specification §15.3 require before a measured run: tear the stack down, discard its
# volumes, regenerate the certificate, then bring it back up and wait for readiness.
#
# A run that skips this is not comparable to one that did not.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
labs_dir=$(cd "$here/.." && pwd)

compose() {
    docker compose -f "$labs_dir/docker-compose.yml" "$@"
}

echo "reset: tearing down the lab stack and discarding volumes"
compose down -v --remove-orphans

echo "reset: discarding the generated fixture certificate"
rm -f "$labs_dir/fixtures/certs/labs.crt" "$labs_dir/fixtures/certs/labs.key"

sh "$here/seed.sh"

echo "reset: starting the lab stack"
compose up -d --wait

sh "$here/readiness.sh"

echo "reset: complete"
