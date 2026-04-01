#!/bin/bash
# test-file-cache.sh — Manual acceptance tests for the -file-cache feature.
#
# Run on a macOS device with the Apple Kerberos SSO Extension and valid
# credentials. Requires an upstream proxy that accepts SPNEGO authentication.
#
# Usage:
#   ./scripts/test-file-cache.sh <upstream-proxy:port> [target-url]
#
# Example:
#   ./scripts/test-file-cache.sh proxy.corp.example.com:8080
#   ./scripts/test-file-cache.sh proxy.corp.example.com:8080 http://intranet.example.com

set -euo pipefail

UPSTREAM="${1:?Usage: $0 <upstream-proxy:port> [target-url]}"
TARGET="${2:-http://example.com}"
BINARY="./spnego-proxy"
BIND="127.0.0.1:19876"
PASS=0
FAIL=0
SKIP=0

pass() { PASS=$((PASS + 1)); printf "  PASS: %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  FAIL: %s\n" "$1"; }
skip() { SKIP=$((SKIP + 1)); printf "  SKIP: %s\n" "$1"; }
section() { printf "\n=== %s ===\n" "$1"; }

cleanup() {
    if [ -n "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null
        wait "$PROXY_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# --- Preflight ---
section "Preflight"

if [ "$(uname)" != "Darwin" ]; then
    echo "ABORT: must run on macOS"; exit 1
fi

if [ ! -x "$BINARY" ]; then
    echo "ABORT: $BINARY not found; run 'CGO_ENABLED=1 go build -o spnego-proxy .' first"; exit 1
fi

if ! klist -s 2>/dev/null; then
    echo "ABORT: no valid Kerberos tickets (klist -s failed)"; exit 1
fi
pass "preflight checks"

# --- Test 1: flag mutual exclusion ---
section "1. Flag mutual exclusion"

if "$BINARY" -proxy "$UPSTREAM" -file-cache -user foo 2>&1 | grep -qi "mutually exclusive\|cannot.*together\|incompatible"; then
    pass "-file-cache and -user rejected"
else
    fail "-file-cache and -user should be rejected"
fi

# --- Test 2: startup with -file-cache ---
section "2. Startup with -file-cache"

LOG=$(mktemp /tmp/spnego-proxy-test.XXXXXX)
"$BINARY" -addr "$BIND" -proxy "$UPSTREAM" -file-cache -debug 2>"$LOG" &
PROXY_PID=$!
sleep 1

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    fail "proxy did not start"
    cat "$LOG"
    exit 1
fi

if grep -q "using macOS GSS-API with file cache workaround" "$LOG"; then
    pass "file-cache mode logged"
else
    fail "expected 'file cache workaround' in log"
fi

# --- Test 3: temp directory and cache file ---
section "3. Temp directory and cache file"

TMPDIR_MATCH=$(find /tmp -maxdepth 1 -name "spnego-proxy-*" -type d -user "$(whoami)" 2>/dev/null | head -1)
if [ -n "$TMPDIR_MATCH" ]; then
    PERMS=$(stat -f "%Lp" "$TMPDIR_MATCH")
    if [ "$PERMS" = "700" ]; then
        pass "temp dir exists with 0700 perms"
    else
        fail "temp dir perms=$PERMS, want 700"
    fi

    CACHE_FILE="$TMPDIR_MATCH/krb5cc"
    if [ -f "$CACHE_FILE" ]; then
        FPERMS=$(stat -f "%Lp" "$CACHE_FILE")
        if [ "$FPERMS" = "600" ]; then
            pass "cache file exists with 0600 perms"
        else
            fail "cache file perms=$FPERMS, want 600"
        fi
    else
        # Cache may not exist yet if no request has been made
        skip "cache file not yet created (no request made)"
    fi
else
    fail "no spnego-proxy-* temp dir found"
fi

# --- Test 4: HTTP request through proxy ---
section "4. HTTP request (GET)"

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x "http://$BIND" "$TARGET" --max-time 10 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    pass "GET returned 200"
elif [ "$HTTP_CODE" = "000" ]; then
    fail "GET failed (connection error)"
else
    fail "GET returned $HTTP_CODE, want 200"
fi

# --- Test 4b: cache file contains valid credentials ---
section "4b. Cache file validation"

if [ -n "${CACHE_FILE:-}" ] && [ -f "$CACHE_FILE" ]; then
    if klist -c "$CACHE_FILE" >/dev/null 2>&1; then
        pass "cache file contains valid credentials"
    else
        fail "cache file exists but klist cannot read it"
    fi
else
    skip "cache file not available for validation"
fi

# --- Test 4c: copy method detection ---
section "4c. Copy method"

if grep -q '"method":"krb5_direct"' "$LOG"; then
    pass "used krb5 direct copy fallback (SSO Extension environment)"
elif grep -q '"method":"gss"' "$LOG"; then
    pass "used GSS credential copy"
else
    fail "no copy method logged"
fi

# --- Test 5: CONNECT tunnel (HTTPS) ---
section "5. CONNECT tunnel (HTTPS)"

HTTPS_TARGET="${TARGET/#http:/https:}"
if [ "$HTTPS_TARGET" = "$TARGET" ] && ! echo "$TARGET" | grep -q "^https"; then
    HTTPS_TARGET="https://example.com"
fi
HTTPS_CODE=$(curl -s -o /dev/null -w "%{http_code}" -x "http://$BIND" "$HTTPS_TARGET" --max-time 10 2>/dev/null || echo "000")
if [ "$HTTPS_CODE" = "200" ]; then
    pass "CONNECT tunnel returned 200"
elif [ "$HTTPS_CODE" = "000" ]; then
    fail "CONNECT tunnel failed (connection error)"
else
    fail "CONNECT tunnel returned $HTTPS_CODE, want 200"
fi

# --- Test 6: concurrent requests ---
section "6. Concurrent requests (10 parallel)"

CONC_PASS=0
CONC_FAIL=0
PIDS=""
TMPRESULTS=$(mktemp /tmp/spnego-proxy-conc.XXXXXX)
for i in $(seq 1 10); do
    (curl -s -o /dev/null -w "%{http_code}" -x "http://$BIND" "$TARGET" --max-time 15 2>/dev/null || echo "000") >> "$TMPRESULTS" &
    PIDS="$PIDS $!"
done
for pid in $PIDS; do wait "$pid" 2>/dev/null || true; done

while IFS= read -r code; do
    if [ "$code" = "200" ]; then
        CONC_PASS=$((CONC_PASS + 1))
    else
        CONC_FAIL=$((CONC_FAIL + 1))
    fi
done < "$TMPRESULTS"
rm -f "$TMPRESULTS"

if [ "$CONC_FAIL" -eq 0 ]; then
    pass "all 10 concurrent requests returned 200"
else
    fail "$CONC_FAIL/10 concurrent requests failed"
fi

# --- Test 7: graceful shutdown and cleanup ---
section "7. Graceful shutdown and cleanup"

TMPDIR_BEFORE="$TMPDIR_MATCH"
kill "$PROXY_PID" 2>/dev/null
wait "$PROXY_PID" 2>/dev/null || true
unset PROXY_PID
sleep 1

if [ -n "$TMPDIR_BEFORE" ] && [ ! -d "$TMPDIR_BEFORE" ]; then
    pass "temp dir removed on shutdown"
else
    fail "temp dir $TMPDIR_BEFORE still exists after shutdown"
fi

# --- Test 8: stale cache cleanup on restart ---
section "8. Stale cache cleanup"

STALE_DIR=$(mktemp -d /tmp/spnego-proxy-XXXXXX)
echo "stale-credential-data" > "$STALE_DIR/krb5cc"

LOG2=$(mktemp /tmp/spnego-proxy-test.XXXXXX)
"$BINARY" -addr "$BIND" -proxy "$UPSTREAM" -file-cache -debug 2>"$LOG2" &
PROXY_PID=$!
sleep 1

if [ ! -d "$STALE_DIR" ]; then
    pass "stale cache dir removed on startup"
else
    fail "stale cache dir $STALE_DIR still exists"
    rm -rf "$STALE_DIR"
fi

if grep -q "removed stale cache directory" "$LOG2"; then
    pass "stale cleanup logged"
else
    fail "expected 'removed stale cache directory' in log"
fi

kill "$PROXY_PID" 2>/dev/null
wait "$PROXY_PID" 2>/dev/null || true
unset PROXY_PID
rm -f "$LOG" "$LOG2"

# --- Test 9: without -file-cache (regression) ---
section "9. Without -file-cache (regression check)"

LOG3=$(mktemp /tmp/spnego-proxy-test.XXXXXX)
"$BINARY" -addr "$BIND" -proxy "$UPSTREAM" -debug 2>"$LOG3" &
PROXY_PID=$!
sleep 1

if kill -0 "$PROXY_PID" 2>/dev/null; then
    if grep -q "using macOS GSS-API" "$LOG3" && ! grep -q "file cache" "$LOG3"; then
        pass "non-file-cache mode logged correctly"
    else
        fail "log should say 'using macOS GSS-API' without 'file cache'"
    fi
else
    fail "proxy did not start without -file-cache"
fi

kill "$PROXY_PID" 2>/dev/null
wait "$PROXY_PID" 2>/dev/null || true
unset PROXY_PID
rm -f "$LOG3"

# --- Summary ---
section "Summary"
TOTAL=$((PASS + FAIL + SKIP))
printf "  %d passed, %d failed, %d skipped (of %d)\n" "$PASS" "$FAIL" "$SKIP" "$TOTAL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
