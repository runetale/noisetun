#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Integration test: two wg-c daemons in Linux network namespaces.
#
# Creates two network namespaces connected by a veth pair, starts
# a wg-c daemon in each, configures them as peers via `wg`, and
# verifies bidirectional data transfer with ping.
#
# Requirements: root, wg-c binary, wg command, ip command
# Usage: sudo scripts/test_integration.sh [path-to-wg-c]

set -euo pipefail

# ──────────────────────────────────────
# Configuration
# ──────────────────────────────────────

WGC="${1:-./build/tools/wg-c}"
NS_A="wgtest_a"
NS_B="wgtest_b"
VETH_A="veth_a"
VETH_B="veth_b"
WG_IFACE_A="wg0"
WG_IFACE_B="wg1"
PORT_A=51820
PORT_B=51821
# Underlay IPs (veth pair)
VETH_IP_A="192.168.100.1/24"
VETH_IP_B="192.168.100.2/24"
VETH_ADDR_A="192.168.100.1"
VETH_ADDR_B="192.168.100.2"
# Overlay IPs (WireGuard tunnel)
WG_IP_A="10.0.0.1/24"
WG_IP_B="10.0.0.2/24"
WG_ADDR_A="10.0.0.1"
WG_ADDR_B="10.0.0.2"

TMPDIR_KEYS=$(mktemp -d)
PASS=0
FAIL=0

# ──────────────────────────────────────
# Helpers
# ──────────────────────────────────────

log()  { echo "==> $*"; }
pass() { log "PASS: $*"; PASS=$((PASS + 1)); }
fail() { log "FAIL: $*"; FAIL=$((FAIL + 1)); }

cleanup() {
    log "Cleaning up..."
    # Kill daemons
    [ -n "${PID_A:-}" ] && kill "$PID_A" 2>/dev/null && wait "$PID_A" 2>/dev/null || true
    [ -n "${PID_B:-}" ] && kill "$PID_B" 2>/dev/null && wait "$PID_B" 2>/dev/null || true
    # Remove namespaces (also removes veth pairs)
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    # Remove UAPI sockets and temp keys
    rm -f "/var/run/wireguard/${WG_IFACE_A}.sock" 2>/dev/null || true
    rm -f "/var/run/wireguard/${WG_IFACE_B}.sock" 2>/dev/null || true
    rm -rf "$TMPDIR_KEYS"
}

trap cleanup EXIT

# ──────────────────────────────────────
# Preflight checks
# ──────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root" >&2
    exit 1
fi

if [ ! -x "$WGC" ]; then
    echo "Error: wg-c binary not found at $WGC" >&2
    echo "Build with: cmake -B build -DWG_BUILD_TOOLS=ON && cmake --build build" >&2
    exit 1
fi

if ! command -v wg &>/dev/null; then
    echo "Error: 'wg' command not found. Install wireguard-tools." >&2
    exit 1
fi

if ! command -v ip &>/dev/null; then
    echo "Error: 'ip' command not found. Install iproute2." >&2
    exit 1
fi

log "wg-c binary: $WGC"
log "Starting integration test..."

# ──────────────────────────────────────
# Step 1: Create network namespaces + veth pair
# ──────────────────────────────────────

log "Creating network namespaces..."
ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true
ip netns add "$NS_A"
ip netns add "$NS_B"

log "Creating veth pair..."
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

ip netns exec "$NS_A" ip addr add "$VETH_IP_A" dev "$VETH_A"
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_A" ip link set lo up

ip netns exec "$NS_B" ip addr add "$VETH_IP_B" dev "$VETH_B"
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_B" ip link set lo up

# Verify veth connectivity
if ip netns exec "$NS_A" ping -c 1 -W 2 "$VETH_ADDR_B" &>/dev/null; then
    pass "veth pair connectivity"
else
    fail "veth pair connectivity"
    exit 1
fi

# ──────────────────────────────────────
# Step 2: Generate WireGuard keys
# ──────────────────────────────────────

log "Generating WireGuard keys..."
KEY_A_PRIV=$(wg genkey)
KEY_A_PUB=$(echo "$KEY_A_PRIV" | wg pubkey)
KEY_B_PRIV=$(wg genkey)
KEY_B_PUB=$(echo "$KEY_B_PRIV" | wg pubkey)
echo "$KEY_A_PRIV" > "$TMPDIR_KEYS/key_a"
echo "$KEY_B_PRIV" > "$TMPDIR_KEYS/key_b"
chmod 600 "$TMPDIR_KEYS/key_a" "$TMPDIR_KEYS/key_b"

# ──────────────────────────────────────
# Step 3: Start wg-c daemons
# ──────────────────────────────────────

log "Starting wg-c in namespace A..."
ip netns exec "$NS_A" "$WGC" -f "$WG_IFACE_A" &
PID_A=$!
sleep 1

log "Starting wg-c in namespace B..."
ip netns exec "$NS_B" "$WGC" -f "$WG_IFACE_B" &
PID_B=$!
sleep 1

# Verify daemons are running
if kill -0 "$PID_A" 2>/dev/null; then
    pass "wg-c daemon A started (pid=$PID_A)"
else
    fail "wg-c daemon A failed to start"
    exit 1
fi

if kill -0 "$PID_B" 2>/dev/null; then
    pass "wg-c daemon B started (pid=$PID_B)"
else
    fail "wg-c daemon B failed to start"
    exit 1
fi

# ──────────────────────────────────────
# Step 4: Configure WireGuard via `wg` command
# ──────────────────────────────────────

log "Configuring WireGuard peers..."

ip netns exec "$NS_A" wg set "$WG_IFACE_A" \
    private-key "$TMPDIR_KEYS/key_a" \
    listen-port "$PORT_A" \
    peer "$KEY_B_PUB" \
    endpoint "${VETH_ADDR_B}:${PORT_B}" \
    allowed-ips "$WG_ADDR_B/32"

ip netns exec "$NS_B" wg set "$WG_IFACE_B" \
    private-key "$TMPDIR_KEYS/key_b" \
    listen-port "$PORT_B" \
    peer "$KEY_A_PUB" \
    endpoint "${VETH_ADDR_A}:${PORT_A}" \
    allowed-ips "$WG_ADDR_A/32"

# ──────────────────────────────────────
# Step 5: Assign overlay IPs and bring interfaces up
# ──────────────────────────────────────

log "Configuring overlay network..."

ip netns exec "$NS_A" ip addr add "$WG_IP_A" dev "$WG_IFACE_A"
ip netns exec "$NS_A" ip link set "$WG_IFACE_A" up

ip netns exec "$NS_B" ip addr add "$WG_IP_B" dev "$WG_IFACE_B"
ip netns exec "$NS_B" ip link set "$WG_IFACE_B" up

# ──────────────────────────────────────
# Step 6: Verify `wg show`
# ──────────────────────────────────────

log "Verifying wg show..."

WG_SHOW_A=$(ip netns exec "$NS_A" wg show "$WG_IFACE_A" 2>&1) || true
WG_SHOW_B=$(ip netns exec "$NS_B" wg show "$WG_IFACE_B" 2>&1) || true

if echo "$WG_SHOW_A" | grep -q "listening port: $PORT_A"; then
    pass "wg show A: listen port"
else
    fail "wg show A: listen port"
    echo "$WG_SHOW_A"
fi

if echo "$WG_SHOW_B" | grep -q "listening port: $PORT_B"; then
    pass "wg show B: listen port"
else
    fail "wg show B: listen port"
    echo "$WG_SHOW_B"
fi

if echo "$WG_SHOW_A" | grep -q "$KEY_B_PUB"; then
    pass "wg show A: peer public key"
else
    fail "wg show A: peer public key"
fi

# ──────────────────────────────────────
# Step 7: Test data transfer (ping)
# ──────────────────────────────────────

log "Testing A -> B ping..."
if ip netns exec "$NS_A" ping -c 5 -W 10 "$WG_ADDR_B"; then
    pass "A -> B ping"
else
    fail "A -> B ping"
fi

log "Testing B -> A ping..."
if ip netns exec "$NS_B" ping -c 5 -W 10 "$WG_ADDR_A"; then
    pass "B -> A ping"
else
    fail "B -> A ping"
fi

# ──────────────────────────────────────
# Step 8: Check traffic stats
# ──────────────────────────────────────

log "Checking traffic stats..."
WG_SHOW_A=$(ip netns exec "$NS_A" wg show "$WG_IFACE_A" 2>&1) || true

if echo "$WG_SHOW_A" | grep -q "latest handshake"; then
    pass "handshake completed (A)"
else
    fail "handshake completed (A)"
fi

if echo "$WG_SHOW_A" | grep -q "transfer:"; then
    pass "traffic stats visible (A)"
else
    fail "traffic stats visible (A)"
fi

# ──────────────────────────────────────
# Summary
# ──────────────────────────────────────

echo ""
echo "════════════════════════════════════"
echo "  Integration Test Results"
echo "  PASS: $PASS  FAIL: $FAIL"
echo "════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
