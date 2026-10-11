#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# wireguard-go interop test.
#
# Creates one wg-c device and one wireguard-go device in separate
# network namespaces, configures them as peers, and verifies
# bidirectional data transfer.
#
# Requirements: root, wg-c, wireguard-go, wg, ip
# Usage: sudo scripts/test_interop_wg_go.sh [path-to-wg-c]

set -euo pipefail

WGC="${1:-./build/tools/wg-c}"
NS_C="interop_c"
NS_GO="interop_go"
VETH_C="veth_c"
VETH_GO="veth_go"
WG_IFACE_C="wg0"
WG_IFACE_GO="wg1"
PORT_C=51820
PORT_GO=51821

VETH_IP_C="192.168.200.1/24"
VETH_IP_GO="192.168.200.2/24"
VETH_ADDR_C="192.168.200.1"
VETH_ADDR_GO="192.168.200.2"

WG_IP_C="10.10.0.1/24"
WG_IP_GO="10.10.0.2/24"
WG_ADDR_C="10.10.0.1"
WG_ADDR_GO="10.10.0.2"

PASS=0
FAIL=0

log()  { echo "==> $*"; }
pass() { log "PASS: $*"; PASS=$((PASS + 1)); }
fail() { log "FAIL: $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    [ -n "${PID_C:-}" ] && kill "$PID_C" 2>/dev/null && wait "$PID_C" 2>/dev/null || true
    [ -n "${PID_GO:-}" ] && kill "$PID_GO" 2>/dev/null && wait "$PID_GO" 2>/dev/null || true
    ip netns del "$NS_C" 2>/dev/null || true
    ip netns del "$NS_GO" 2>/dev/null || true
    rm -rf "${TMPDIR_KEYS:-}" 2>/dev/null || true
}

trap cleanup EXIT

# ──────────────────────────────────────
# Preflight
# ──────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be root" >&2; exit 1
fi
[ -x "$WGC" ] || { echo "Error: $WGC not found" >&2; exit 1; }
command -v wireguard-go &>/dev/null || { echo "Error: wireguard-go not found" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg not found" >&2; exit 1; }

log "Starting wireguard-go interop test..."
log "wg-c: $WGC"
log "wireguard-go: $(which wireguard-go)"

# ──────────────────────────────────────
# Setup namespaces + veth
# ──────────────────────────────────────

ip netns add "$NS_C"
ip netns add "$NS_GO"

ip link add "$VETH_C" type veth peer name "$VETH_GO"
ip link set "$VETH_C" netns "$NS_C"
ip link set "$VETH_GO" netns "$NS_GO"

ip netns exec "$NS_C" ip addr add "$VETH_IP_C" dev "$VETH_C"
ip netns exec "$NS_C" ip link set "$VETH_C" up
ip netns exec "$NS_C" ip link set lo up

ip netns exec "$NS_GO" ip addr add "$VETH_IP_GO" dev "$VETH_GO"
ip netns exec "$NS_GO" ip link set "$VETH_GO" up
ip netns exec "$NS_GO" ip link set lo up

if ip netns exec "$NS_C" ping -c 1 -W 2 "$VETH_ADDR_GO" &>/dev/null; then
    pass "veth connectivity"
else
    fail "veth connectivity"; exit 1
fi

# ──────────────────────────────────────
# Generate keys
# ──────────────────────────────────────

TMPDIR_KEYS=$(mktemp -d)
KEY_C_PRIV=$(wg genkey)
KEY_C_PUB=$(echo "$KEY_C_PRIV" | wg pubkey)
KEY_GO_PRIV=$(wg genkey)
KEY_GO_PUB=$(echo "$KEY_GO_PRIV" | wg pubkey)
echo "$KEY_C_PRIV" > "$TMPDIR_KEYS/key_c"
echo "$KEY_GO_PRIV" > "$TMPDIR_KEYS/key_go"
chmod 600 "$TMPDIR_KEYS/key_c" "$TMPDIR_KEYS/key_go"

# ──────────────────────────────────────
# Start wg-c daemon
# ──────────────────────────────────────

log "Starting wg-c..."
ip netns exec "$NS_C" env WG_PROCESS_FOREGROUND=1 "$WGC" -f "$WG_IFACE_C" &
PID_C=$!
sleep 1

if kill -0 "$PID_C" 2>/dev/null; then
    pass "wg-c started"
else
    fail "wg-c start"; exit 1
fi

# ──────────────────────────────────────
# Start wireguard-go daemon
# ──────────────────────────────────────

log "Starting wireguard-go..."
ip netns exec "$NS_GO" env WG_PROCESS_FOREGROUND=1 wireguard-go -f "$WG_IFACE_GO" &
PID_GO=$!
sleep 1

if kill -0 "$PID_GO" 2>/dev/null; then
    pass "wireguard-go started"
else
    fail "wireguard-go start"; exit 1
fi

# ──────────────────────────────────────
# Configure peers
# ──────────────────────────────────────

log "Configuring wg-c..."
ip netns exec "$NS_C" wg set "$WG_IFACE_C" \
    private-key "$TMPDIR_KEYS/key_c" \
    listen-port "$PORT_C" \
    peer "$KEY_GO_PUB" \
    endpoint "${VETH_ADDR_GO}:${PORT_GO}" \
    allowed-ips "$WG_ADDR_GO/32"

log "Configuring wireguard-go..."
ip netns exec "$NS_GO" wg set "$WG_IFACE_GO" \
    private-key "$TMPDIR_KEYS/key_go" \
    listen-port "$PORT_GO" \
    peer "$KEY_C_PUB" \
    endpoint "${VETH_ADDR_C}:${PORT_C}" \
    allowed-ips "$WG_ADDR_C/32"

# ──────────────────────────────────────
# Assign IPs and bring up interfaces
# ──────────────────────────────────────

ip netns exec "$NS_C" ip addr add "$WG_IP_C" dev "$WG_IFACE_C"
ip netns exec "$NS_C" ip link set "$WG_IFACE_C" up

ip netns exec "$NS_GO" ip addr add "$WG_IP_GO" dev "$WG_IFACE_GO"
ip netns exec "$NS_GO" ip link set "$WG_IFACE_GO" up

# ──────────────────────────────────────
# Test: wg-c -> wireguard-go
# ──────────────────────────────────────

log "Testing wg-c -> wireguard-go ping..."
if ip netns exec "$NS_C" ping -c 5 -W 10 "$WG_ADDR_GO"; then
    pass "wg-c -> wireguard-go ping"
else
    fail "wg-c -> wireguard-go ping"
fi

# ──────────────────────────────────────
# Test: wireguard-go -> wg-c
# ──────────────────────────────────────

log "Testing wireguard-go -> wg-c ping..."
if ip netns exec "$NS_GO" ping -c 5 -W 10 "$WG_ADDR_C"; then
    pass "wireguard-go -> wg-c ping"
else
    fail "wireguard-go -> wg-c ping"
fi

# ──────────────────────────────────────
# Verify handshake on both sides
# ──────────────────────────────────────

SHOW_C=$(ip netns exec "$NS_C" wg show "$WG_IFACE_C" 2>&1) || true
SHOW_GO=$(ip netns exec "$NS_GO" wg show "$WG_IFACE_GO" 2>&1) || true

if echo "$SHOW_C" | grep -q "latest handshake"; then
    pass "wg-c: handshake completed"
else
    fail "wg-c: handshake not completed"
fi

if echo "$SHOW_GO" | grep -q "latest handshake"; then
    pass "wireguard-go: handshake completed"
else
    fail "wireguard-go: handshake not completed"
fi

# ──────────────────────────────────────
# Summary
# ──────────────────────────────────────

echo ""
echo "════════════════════════════════════"
echo "  wireguard-go Interop Test Results"
echo "  PASS: $PASS  FAIL: $FAIL"
echo "════════════════════════════════════"

[ "$FAIL" -gt 0 ] && exit 1
exit 0
