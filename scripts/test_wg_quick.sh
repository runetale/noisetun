#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Functional test for wg-quick-c (Linux)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WGC_BIN="${WGC_BIN:-${SCRIPT_DIR}/../build-release/tools/wg-c}"
WGQC_BIN="${WGQC_BIN:-${SCRIPT_DIR}/../build-release/tools/wg-quick-c}"

if [[ $EUID -ne 0 ]]; then echo "ERROR: must run as root"; exit 1; fi
[[ -x "$WGC_BIN" ]] || { echo "ERROR: wg-c not found"; exit 1; }
[[ -x "$WGQC_BIN" ]] || { echo "ERROR: wg-quick-c not found"; exit 1; }

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# Cleanup
pkill -f "wg-c.*wgq_" 2>/dev/null || true
sleep 0.3
ip netns del ns_wgq_a 2>/dev/null || true
ip netns del ns_wgq_b 2>/dev/null || true
rm -f /var/run/wireguard/wgq_*.sock /var/run/wireguard/wgq_*.pid /var/run/wireguard/wgq_*.conf
sleep 0.3

# Generate keys
KEY_A_PRIV=$(wg genkey); KEY_A_PUB=$(echo "$KEY_A_PRIV" | wg pubkey)
KEY_B_PRIV=$(wg genkey); KEY_B_PUB=$(echo "$KEY_B_PRIV" | wg pubkey)

echo "=== wg-quick-c Functional Test ==="

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    pkill -f "wg-c.*wgq_" 2>/dev/null || true
    sleep 0.5
    ip netns del ns_wgq_a 2>/dev/null || true
    ip netns del ns_wgq_b 2>/dev/null || true
    rm -f /var/run/wireguard/wgq_*.sock /var/run/wireguard/wgq_*.pid /var/run/wireguard/wgq_*.conf
    rm -f /tmp/wgq_a.conf /tmp/wgq_b.conf
}
trap cleanup EXIT

# Create network namespaces with veth pair
ip netns add ns_wgq_a
ip netns add ns_wgq_b
ip link add veth_wgq_a type veth peer name veth_wgq_b
ip link set veth_wgq_a netns ns_wgq_a
ip link set veth_wgq_b netns ns_wgq_b
ip netns exec ns_wgq_a ip addr add 10.5.0.1/24 dev veth_wgq_a
ip netns exec ns_wgq_a ip link set veth_wgq_a up
ip netns exec ns_wgq_a ip link set lo up
ip netns exec ns_wgq_b ip addr add 10.5.0.2/24 dev veth_wgq_b
ip netns exec ns_wgq_b ip link set veth_wgq_b up
ip netns exec ns_wgq_b ip link set lo up

mkdir -p /var/run/wireguard

# Write config files
cat > /tmp/wgq_a.conf <<EOF
[Interface]
PrivateKey = $KEY_A_PRIV
ListenPort = 51820
Address = 10.99.0.1/24
MTU = 1420

[Peer]
PublicKey = $KEY_B_PUB
Endpoint = 10.5.0.2:51821
AllowedIPs = 10.99.0.2/32
PersistentKeepalive = 25
EOF

cat > /tmp/wgq_b.conf <<EOF
[Interface]
PrivateKey = $KEY_B_PRIV
ListenPort = 51821
Address = 10.99.0.2/24
MTU = 1420
PostUp = echo "PostUp executed for %i" > /tmp/wgq_hook_test

[Peer]
PublicKey = $KEY_A_PUB
Endpoint = 10.5.0.1:51820
AllowedIPs = 10.99.0.1/32
EOF

# === TEST 1: wg-quick-c up (side A) ===
echo ""
echo "--- [1] wg-quick-c up (side A) ---"

export WGC_BIN="$WGC_BIN"
ip netns exec ns_wgq_a "$WGQC_BIN" up /tmp/wgq_a.conf 2>&1

# Verify interface exists
if ip netns exec ns_wgq_a ip link show wgq_a >/dev/null 2>&1; then
    pass "Interface wgq_a created"
else
    fail "Interface wgq_a not created"
fi

# Verify address
if ip netns exec ns_wgq_a ip addr show wgq_a | grep -q "10.99.0.1"; then
    pass "Address 10.99.0.1 assigned"
else
    fail "Address not assigned"
fi

# === TEST 2: wg-quick-c up (side B, with PostUp hook) ===
echo ""
echo "--- [2] wg-quick-c up (side B + PostUp) ---"

rm -f /tmp/wgq_hook_test
ip netns exec ns_wgq_b "$WGQC_BIN" up /tmp/wgq_b.conf 2>&1

if ip netns exec ns_wgq_b ip link show wgq_b >/dev/null 2>&1; then
    pass "Interface wgq_b created"
else
    fail "Interface wgq_b not created"
fi

if [[ -f /tmp/wgq_hook_test ]]; then
    pass "PostUp hook executed"
else
    fail "PostUp hook not executed"
fi

# === TEST 3: Bidirectional ping ===
echo ""
echo "--- [3] Bidirectional ping ---"
sleep 1

if ip netns exec ns_wgq_a ping -c 3 -W 3 10.99.0.2 >/dev/null 2>&1; then
    pass "A → B ping"
else
    fail "A → B ping"
fi

if ip netns exec ns_wgq_b ping -c 3 -W 3 10.99.0.1 >/dev/null 2>&1; then
    pass "B → A ping"
else
    fail "B → A ping"
fi

# === TEST 4: wg show works ===
echo ""
echo "--- [4] wg show ---"

WG_OUT=$(ip netns exec ns_wgq_a wg show wgq_a 2>&1)
if echo "$WG_OUT" | grep -q "peer:"; then
    pass "wg show displays peer"
else
    fail "wg show broken"
fi

# === TEST 5: wg-quick-c down ===
echo ""
echo "--- [5] wg-quick-c down ---"

ip netns exec ns_wgq_b "$WGQC_BIN" down wgq_b 2>&1

sleep 1
if ! ip netns exec ns_wgq_b ip link show wgq_b >/dev/null 2>&1; then
    pass "Interface wgq_b removed"
else
    fail "Interface wgq_b still exists"
fi

# Check daemon is dead
if ! pgrep -f "wg-c.*wgq_b" >/dev/null 2>&1; then
    pass "wg-c daemon stopped"
else
    fail "wg-c daemon still running"
fi

# Summary
echo ""
echo "==============================="
echo "  PASS: $PASS  FAIL: $FAIL"
echo "==============================="

[[ $FAIL -gt 0 ]] && exit 1
exit 0
