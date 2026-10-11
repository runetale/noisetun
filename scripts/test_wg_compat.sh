#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# wg command compatibility test.
#
# Verifies that wireguard-tools' `wg` command can fully configure
# and query the wg-c daemon via its UAPI socket.
#
# Requirements: root, wg-c binary, wg command
# Usage: sudo env PATH="$PATH" bash scripts/test_wg_compat.sh [path-to-wg-c]

set -euo pipefail

WGC="${1:-./build/tools/wg-c}"
NS="wgcompat_ns"
WG_IFACE="wg0"
TMPDIR_KEYS=$(mktemp -d)

PASS=0
FAIL=0

log()  { echo "==> $*"; }
pass() { log "PASS: $*"; PASS=$((PASS + 1)); }
fail() { log "FAIL: $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    rm -rf "$TMPDIR_KEYS"
}

trap cleanup EXIT

# ──────────────────────────────────────
# Preflight
# ──────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be root" >&2; exit 1
fi
[ -x "$WGC" ] || { echo "Error: $WGC not found" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg not found" >&2; exit 1; }

log "Starting wg command compatibility test..."

# ──────────────────────────────────────
# Setup: namespace + daemon
# ──────────────────────────────────────

ip netns del "$NS" 2>/dev/null || true
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up

ip netns exec "$NS" "$WGC" -f "$WG_IFACE" &
PID=$!
sleep 1

if ! kill -0 "$PID" 2>/dev/null; then
    fail "daemon start"
    exit 1
fi
pass "daemon started"

# ──────────────────────────────────────
# Test 1: wg genkey / pubkey
# ──────────────────────────────────────

PRIV=$(wg genkey)
PUB=$(echo "$PRIV" | wg pubkey)
PEER_PRIV=$(wg genkey)
PEER_PUB=$(echo "$PEER_PRIV" | wg pubkey)
PSK=$(wg genpsk)

# Write keys to temp files (process substitution doesn't work across namespaces)
echo "$PRIV" > "$TMPDIR_KEYS/priv"
echo "$PSK" > "$TMPDIR_KEYS/psk"
chmod 600 "$TMPDIR_KEYS/priv" "$TMPDIR_KEYS/psk"
pass "key generation"

# ──────────────────────────────────────
# Test 2: wg set - private key + listen port
# ──────────────────────────────────────

ip netns exec "$NS" wg set "$WG_IFACE" \
    private-key "$TMPDIR_KEYS/priv" \
    listen-port 51820
pass "wg set: private-key + listen-port"

# ──────────────────────────────────────
# Test 3: wg show - verify basic config
# ──────────────────────────────────────

SHOW=$(ip netns exec "$NS" wg show "$WG_IFACE" 2>&1) || true

if echo "$SHOW" | grep -q "listening port: 51820"; then
    pass "wg show: listen-port"
else
    fail "wg show: listen-port"
    echo "$SHOW"
fi

if echo "$SHOW" | grep -q "public key: $PUB"; then
    pass "wg show: public-key matches"
else
    fail "wg show: public-key"
    echo "$SHOW"
fi

# ──────────────────────────────────────
# Test 4: wg set - add peer with full config
# ──────────────────────────────────────

ip netns exec "$NS" wg set "$WG_IFACE" \
    peer "$PEER_PUB" \
    preshared-key "$TMPDIR_KEYS/psk" \
    endpoint "1.2.3.4:9999" \
    allowed-ips "10.0.0.0/24,fd00::/64" \
    persistent-keepalive 25
pass "wg set: add peer with full config"

# ──────────────────────────────────────
# Test 5: wg show - verify peer details
# ──────────────────────────────────────

SHOW=$(ip netns exec "$NS" wg show "$WG_IFACE" 2>&1) || true

if echo "$SHOW" | grep -q "peer: $PEER_PUB"; then
    pass "wg show: peer listed"
else
    fail "wg show: peer listed"
    echo "$SHOW"
fi

if echo "$SHOW" | grep -q "endpoint: 1.2.3.4:9999"; then
    pass "wg show: endpoint"
else
    fail "wg show: endpoint"
fi

if echo "$SHOW" | grep -q "10.0.0.0/24"; then
    pass "wg show: allowed-ips (IPv4)"
else
    fail "wg show: allowed-ips (IPv4)"
fi

if echo "$SHOW" | grep -q "fd00::/64"; then
    pass "wg show: allowed-ips (IPv6)"
else
    fail "wg show: allowed-ips (IPv6)"
fi

if echo "$SHOW" | grep -q "persistent keepalive: every 25 seconds"; then
    pass "wg show: persistent-keepalive"
else
    fail "wg show: persistent-keepalive"
fi

# ──────────────────────────────────────
# Test 6: wg set - change listen port
# ──────────────────────────────────────

ip netns exec "$NS" wg set "$WG_IFACE" listen-port 12345
SHOW=$(ip netns exec "$NS" wg show "$WG_IFACE" 2>&1) || true

if echo "$SHOW" | grep -q "listening port: 12345"; then
    pass "wg set: change listen-port"
else
    fail "wg set: change listen-port"
fi

# ──────────────────────────────────────
# Test 7: wg showconf
# ──────────────────────────────────────

CONF=$(ip netns exec "$NS" wg showconf "$WG_IFACE" 2>&1) || true

if echo "$CONF" | grep -q "\\[Interface\\]"; then
    pass "wg showconf: [Interface] section"
else
    fail "wg showconf: [Interface] section"
fi

if echo "$CONF" | grep -q "\\[Peer\\]"; then
    pass "wg showconf: [Peer] section"
else
    fail "wg showconf: [Peer] section"
fi

if echo "$CONF" | grep -q "ListenPort = 12345"; then
    pass "wg showconf: ListenPort"
else
    fail "wg showconf: ListenPort"
fi

# ──────────────────────────────────────
# Test 8: wg set - remove peer
# ──────────────────────────────────────

ip netns exec "$NS" wg set "$WG_IFACE" peer "$PEER_PUB" remove
SHOW=$(ip netns exec "$NS" wg show "$WG_IFACE" 2>&1) || true

if ! echo "$SHOW" | grep -q "peer:"; then
    pass "wg set: remove peer"
else
    fail "wg set: remove peer"
fi

# ──────────────────────────────────────
# Test 9: wg set - fwmark
# ──────────────────────────────────────

ip netns exec "$NS" wg set "$WG_IFACE" fwmark 42
SHOW=$(ip netns exec "$NS" wg show "$WG_IFACE" 2>&1) || true

if echo "$SHOW" | grep -q "fwmark: 0x2a"; then
    pass "wg set: fwmark"
else
    fail "wg set: fwmark"
    echo "$SHOW"
fi

# ──────────────────────────────────────
# Summary
# ──────────────────────────────────────

echo ""
echo "════════════════════════════════════"
echo "  wg Compat Test Results"
echo "  PASS: $PASS  FAIL: $FAIL"
echo "════════════════════════════════════"

[ "$FAIL" -gt 0 ] && exit 1
exit 0
