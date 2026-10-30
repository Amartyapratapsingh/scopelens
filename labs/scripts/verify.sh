#!/usr/bin/env sh
# Independently verify that the fixtures really differ as designed.
#
# Build Plan §7: "verify positive/negative behaviour independently before a measured run".
# Build Plan §0.3: never fake a result. This script exists so that a fixture pair is
# *demonstrated* to differ rather than assumed to — if a fixture silently loses a
# misconfiguration, this fails loudly instead of letting a later scan look clean.
#
# Every assertion below is a claim one of the registered controls depends on. When a control
# is added, its fixture difference is added here first.
#
# NOTE: operator-side fixture tooling. Not scanner code; never imported by the backend
# (see docs/OPEN_QUESTIONS.md Q-3).
set -u

BAD_HTTP="http://127.0.0.1:8081"
BAD_HTTPS="https://127.0.0.1:8443"
GOOD_HTTP="http://127.0.0.1:8082"
GOOD_HTTPS="https://127.0.0.1:8444"

failures=0

# header <url> <header-name> -> the header value, or "" if absent
header() {
    curl -sk -D - -o /dev/null --max-time 5 "$1" 2>/dev/null \
        | tr -d '\r' \
        | awk -v want="$(printf '%s' "$2" | tr 'A-Z' 'a-z')" \
            'BEGIN{IGNORECASE=1} { if (tolower($0) ~ "^" want ":") { sub(/^[^:]*:[ ]*/, ""); print; exit } }'
}

status() { curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$1" 2>/dev/null; }
body()   { curl -sk --max-time 5 "$1" 2>/dev/null; }

check_present() {
    label="$1"; actual="$2"
    if [ -n "$actual" ]; then printf '  ok    %s\n' "$label"
    else printf '  FAIL  %s (expected a value, got nothing)\n' "$label"; failures=$((failures + 1)); fi
}

check_absent() {
    label="$1"; actual="$2"
    if [ -z "$actual" ]; then printf '  ok    %s\n' "$label"
    else printf '  FAIL  %s (expected absent, got %s)\n' "$label" "$actual"; failures=$((failures + 1)); fi
}

check_equals() {
    label="$1"; expected="$2"; actual="$3"
    if [ "$expected" = "$actual" ]; then printf '  ok    %s\n' "$label"
    else printf '  FAIL  %s (expected %s, got %s)\n' "$label" "$expected" "$actual"; failures=$((failures + 1)); fi
}

check_contains() {
    label="$1"; haystack="$2"; needle="$3"
    case "$haystack" in
        *"$needle"*) printf '  ok    %s\n' "$label" ;;
        *) printf '  FAIL  %s (did not contain %s)\n' "$label" "$needle"; failures=$((failures + 1)) ;;
    esac
}

echo "verify: C01 — TLS certificate shape"
# The property that matters is issuer == subject, not a particular string order in the DN.
bad_issuer=$(echo | openssl s_client -connect 127.0.0.1:8443 -servername labs-bad 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
bad_subject=$(echo | openssl s_client -connect 127.0.0.1:8443 -servername labs-bad 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
good_issuer=$(echo | openssl s_client -connect 127.0.0.1:8444 -servername labs-good 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
good_subject=$(echo | openssl s_client -connect 127.0.0.1:8444 -servername labs-good 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)

# openssl prefixes each line with "issuer=" / "subject="; strip those before comparing.
check_equals "labs-bad  is self-signed (issuer equals subject)" \
    "${bad_subject#subject=}" "${bad_issuer#issuer=}"
if [ "$good_issuer" = "$good_subject" ]; then
    printf '  FAIL  labs-good is self-signed, so the TLS fixtures do not differ\n'
    failures=$((failures + 1))
else
    printf '  ok    labs-good is CA-signed (issuer differs from subject)\n'
fi
check_contains "labs-good issuer is the fixture CA" "$good_issuer" "CN=ScopeLens Fixture CA"

echo "verify: C01 — HSTS"
check_absent  "labs-bad  HTTPS has no Strict-Transport-Security" "$(header "$BAD_HTTPS/healthz" strict-transport-security)"
check_present "labs-good HTTPS has Strict-Transport-Security"    "$(header "$GOOD_HTTPS/healthz" strict-transport-security)"

echo "verify: C01 — cleartext behaviour"
check_equals  "labs-bad  serves content over cleartext HTTP"     "200" "$(status "$BAD_HTTP/")"
check_equals  "labs-good redirects cleartext HTTP to HTTPS"     "301" "$(status "$GOOD_HTTP/")"

echo "verify: C01 — mixed content"
check_contains "labs-bad  debug page references a cleartext script" "$(body "$BAD_HTTPS/error-debug.html")" 'src="http://'
check_equals   "labs-good has no debug page"                       "404" "$(status "$GOOD_HTTPS/error-debug.html")"

echo "verify: C02 — session cookie flags"
bad_cookie=$(header "$BAD_HTTPS/healthz" set-cookie)
good_cookie=$(header "$GOOD_HTTPS/healthz" set-cookie)
check_present "labs-bad  sets a session cookie" "$bad_cookie"
case "$bad_cookie" in
    *Secure*|*HttpOnly*|*SameSite*)
        printf '  FAIL  labs-bad cookie unexpectedly carries a protective flag (%s)\n' "$bad_cookie"
        failures=$((failures + 1)) ;;
    *) printf '  ok    labs-bad cookie has no Secure/HttpOnly/SameSite\n' ;;
esac
case "$good_cookie" in
    *Secure*HttpOnly*SameSite*) printf '  ok    labs-good cookie is Secure, HttpOnly, SameSite\n' ;;
    *) printf '  FAIL  labs-good cookie is missing flags (%s)\n' "$good_cookie"
       failures=$((failures + 1)) ;;
esac

echo "verify: C02 — session cookie scope"
check_contains "labs-bad  cookie sets an explicit Domain"  "$bad_cookie"  "Domain="
case "$good_cookie" in
    *Domain=*) printf '  FAIL  labs-good cookie sets a Domain attribute (%s)\n' "$good_cookie"
               failures=$((failures + 1)) ;;
    *) printf '  ok    labs-good cookie sets no Domain (host-only)\n' ;;
esac

echo "verify: C04 — browser policy headers"
check_absent   "labs-bad  has no X-Content-Type-Options" "$(header "$BAD_HTTPS/" x-content-type-options)"
check_equals   "labs-good sets X-Content-Type-Options: nosniff" "nosniff" "$(header "$GOOD_HTTPS/healthz" x-content-type-options)"
check_absent   "labs-bad  has no Content-Security-Policy" "$(header "$BAD_HTTPS/" content-security-policy)"
check_contains "labs-good CSP enforces default-src" "$(header "$GOOD_HTTPS/healthz" content-security-policy)" "default-src"
check_absent   "labs-bad  has no X-Frame-Options" "$(header "$BAD_HTTPS/" x-frame-options)"
check_contains "labs-good CSP sets frame-ancestors" "$(header "$GOOD_HTTPS/healthz" content-security-policy)" "frame-ancestors"
check_absent   "labs-bad  has no Referrer-Policy" "$(header "$BAD_HTTPS/" referrer-policy)"
check_equals   "labs-good sets Referrer-Policy: no-referrer" "no-referrer" "$(header "$GOOD_HTTPS/healthz" referrer-policy)"

echo "verify: C05 and C06 — disclosure"
bad_server=$(header "$BAD_HTTP/" server)
good_server=$(header "$GOOD_HTTPS/healthz" server)
case "$bad_server" in
    *nginx/*) printf '  ok    labs-bad Server header discloses the version (%s)\n' "$bad_server" ;;
    *) printf '  FAIL  labs-bad Server header does not disclose a version (%s)\n' "$bad_server"
       failures=$((failures + 1)) ;;
esac
case "$good_server" in
    *nginx/*) printf '  FAIL  labs-good Server header discloses the version (%s)\n' "$good_server"
              failures=$((failures + 1)) ;;
    *) printf '  ok    labs-good Server header discloses no version (%s)\n' "$good_server" ;;
esac

check_equals "labs-bad  serves /.env"                 "200" "$(status "$BAD_HTTP/.env")"
check_equals "labs-good does not serve /.env"         "404" "$(status "$GOOD_HTTPS/.env")"
check_equals "labs-bad  serves /backup.sql"           "200" "$(status "$BAD_HTTP/backup.sql")"
check_equals "labs-good does not serve /backup.sql"   "404" "$(status "$GOOD_HTTPS/backup.sql")"
check_equals "labs-bad  serves /.git/config"          "200" "$(status "$BAD_HTTP/.git/config")"
check_equals "labs-good does not serve /.git/config"  "404" "$(status "$GOOD_HTTPS/.git/config")"

if body "$BAD_HTTP/files/" | grep -qi 'Index of'; then
    printf '  ok    labs-bad directory listing is enabled\n'
else
    printf '  FAIL  labs-bad /files/ is not showing a directory index\n'; failures=$((failures + 1))
fi
if body "$GOOD_HTTPS/files/" | grep -qi 'Index of'; then
    printf '  FAIL  labs-good /files/ is showing a directory index\n'; failures=$((failures + 1))
else
    printf '  ok    labs-good directory listing is disabled\n'
fi

check_contains "labs-bad  debug page renders a traceback" "$(body "$BAD_HTTPS/error-debug.html")" "Traceback (most recent call last)"
check_equals   "labs-good has no debug page"              "404" "$(status "$GOOD_HTTPS/error-debug.html")"

check_contains "labs-bad  delivers a private-shaped key"   "$(body "$BAD_HTTPS/fixture-files/app-secrets.js")" "sk-fixture"
good_js=$(body "$GOOD_HTTPS/app-config.js")
check_contains "labs-good delivers only a publishable key" "$good_js" "pk_test_"
case "$good_js" in
    *sk-*) printf '  FAIL  labs-good delivers a private-shaped key\n'; failures=$((failures + 1)) ;;
    *) printf '  ok    labs-good delivers no private-shaped key\n' ;;
esac

echo "verify: C07 — method exposure and API inventory"
check_contains "labs-bad  advertises PUT" "$(header "$BAD_HTTP/" allow)" "PUT"
case "$(header "$GOOD_HTTPS/healthz" allow)" in
    *PUT*|*DELETE*) printf '  FAIL  labs-good advertises a method it does not serve\n'
                    failures=$((failures + 1)) ;;
    *) printf '  ok    labs-good advertises no unusual method\n' ;;
esac
check_equals "labs-bad  serves /api"  "200" "$(status "$BAD_HTTP/api")"
check_equals "labs-good serves /api"  "200" "$(status "$GOOD_HTTPS/api")"

echo
if [ "$failures" -eq 0 ]; then
    echo "verify: PASS — fixtures differ as designed"
    exit 0
fi
echo "verify: FAIL — $failures assertion(s) failed; do not run a measured scan against these fixtures" >&2
exit 1
