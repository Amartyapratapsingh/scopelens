#!/usr/bin/env sh
# Seed the lab fixtures.
#
# Generates the certificates the fixtures serve over HTTPS. No synthetic data is generated:
# the fixture content is committed under fixtures/*/html so that a given revision always
# serves exactly the same bytes.
#
# TWO CERTIFICATES, ON PURPOSE
#
# The vulnerable and fixed fixtures need a real, verifiable difference in their certificate
# **shape**, not only in their headers, or the TLS control's fixture pair would be untested:
#
#   labs-bad   a self-signed certificate — issuer equals subject, which browsers reject
#   labs-good  a certificate signed by a fixture-local CA — issuer differs from subject
#
# Note what this does *not* establish: neither chain is in a system trust store, so the fixed
# fixture is "not self-signed", not "trusted". The TLS control's claim is deliberately that
# narrow, and `docs/MILESTONES.md` records the trust-store limitation.
#
# Idempotent: existing certificates are left alone. `make labs-reset` removes them first,
# which is what makes a reset a genuine reset.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
labs_dir=$(cd "$here/.." && pwd)
certs="$labs_dir/fixtures/certs"

mkdir -p "$certs"

if [ -f "$certs/labs-bad.crt" ] && [ -f "$certs/labs-good.crt" ] && [ -f "$certs/ca.crt" ]; then
    echo "seed: certificates already present, leaving them in place"
else
    command -v openssl >/dev/null 2>&1 || {
        echo "seed: ERROR openssl is required to generate the fixture certificates" >&2
        exit 1
    }
    echo "seed: generating fixture certificates"

    # The fixture CA. Its only purpose is to sign one leaf so that leaf is not self-signed.
    openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
        -keyout "$certs/ca.key" \
        -out "$certs/ca.crt" \
        -subj "/C=XX/O=ScopeLens Lab Fixtures/CN=ScopeLens Fixture CA" \
        >/dev/null 2>&1

    # labs-bad: self-signed, so subject == issuer and a browser rejects the chain.
    openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
        -keyout "$certs/labs-bad.key" \
        -out "$certs/labs-bad.crt" \
        -subj "/C=XX/O=ScopeLens Lab Fixtures/CN=labs-bad" \
        -addext "subjectAltName=IP:172.28.0.11,IP:127.0.0.1,DNS:labs-bad,DNS:localhost" \
        >/dev/null 2>&1

    # labs-good: signed by the fixture CA, so subject != issuer.
    openssl req -newkey rsa:2048 -sha256 -nodes \
        -keyout "$certs/labs-good.key" \
        -out "$certs/labs-good.csr" \
        -subj "/C=XX/O=ScopeLens Lab Fixtures/CN=labs-good" \
        >/dev/null 2>&1
    printf 'subjectAltName=IP:172.28.0.12,IP:127.0.0.1,DNS:labs-good,DNS:localhost\n' \
        > "$certs/labs-good.ext"
    openssl x509 -req -in "$certs/labs-good.csr" \
        -CA "$certs/ca.crt" -CAkey "$certs/ca.key" -CAcreateserial \
        -out "$certs/labs-good.crt" -days 365 -sha256 \
        -extfile "$certs/labs-good.ext" \
        >/dev/null 2>&1
    rm -f "$certs/labs-good.csr" "$certs/labs-good.ext" "$certs/ca.srl"

    chmod 600 "$certs/ca.key" "$certs/labs-bad.key" "$certs/labs-good.key"
    chmod 644 "$certs/ca.crt" "$certs/labs-bad.crt" "$certs/labs-good.crt"
    echo "seed: wrote labs-bad (self-signed), labs-good (CA-signed) and the CA"
fi

# The fixture files the controls depend on. Named so no gitignore rule can hide them; nginx
# serves them at the realistic paths. Fail loudly rather than serving a fixture that silently
# lost its point.
for required in \
    "$labs_dir/fixtures/bad/html/fixture-files/synthetic-dotenv.txt" \
    "$labs_dir/fixtures/bad/html/fixture-files/synthetic-backup.sql" \
    "$labs_dir/fixtures/bad/html/fixture-files/synthetic-git-config.txt" \
    "$labs_dir/fixtures/bad/html/fixture-files/app-secrets.js" \
    "$labs_dir/fixtures/bad/html/files/notes.txt" \
    "$labs_dir/fixtures/bad/html/error-debug.html" \
    "$labs_dir/fixtures/good/html/index.html" \
    "$labs_dir/fixtures/good/html/app-config.js"
do
    [ -f "$required" ] || {
        echo "seed: ERROR missing fixture file: $required" >&2
        exit 1
    }
done

echo "seed: fixture content verified present"
