#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Roaming (endpoint auto-update) verification test
# Uses two network namespaces with veth pairs to simulate roaming.
#
# Scenario:
#   1. Peer A (ns_a) and Peer B (ns_b) establish tunnel via wg-c
#   2. Verify initial connectivity (ping through tunnel)
#   3. Kill Peer B, restart on a different UDP port (51821 → 51822)
#   4. Peer B pings Peer A → A should auto-update B's endpoint to new port
#
# Requirements: root, wg-c binary in $WGC_BIN (default: ./build-release/tools/wg-c)
#               wg (wireguard-tools) installed

set -euo pipefail

WGC_BIN="${WGC_BIN:-./build-release/tools/wg-c}"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root"
    exit 1
fi

if [[ ! -x "$WGC_BIN" ]]; then
    echo "ERROR: wg-c binary not found at $WGC_BIN"
    exit 1
fi

if ! command -v wg &>/dev/null; then
    echo "ERROR: wg (wireguard-tools) not found"
    exit 1
fi

# Generate keys
KEY_A_PRIV=$(wg genkey)
KEY_A_PUB=$(echo "$KEY_A_PRIV" | wg pubkey)
KEY_B_PRIV=$(wg genkey)
KEY_B_PUB=$(echo "$KEY_B_PRIV" | wg pubkey)

echo "=== Roaming Test ==="
echo "Peer A pub: $KEY_A_PUB"
echo "Peer B pub: $KEY_B_PUB"

PID_A=""
PID_B=""

cleanup() {
    echo "--- Cleanup ---"
    [[ -n "$PID_A" ]] && kill "$PID_A" 2>/dev/null || true
    [[ -n "$PID_B" ]] && kill "$PID_B" 2>/dev/null || true
    sleep 0.5
    ip netns del ns_a 2>/dev/null || true
    ip netns del ns_b 2>/dev/null || true
    rm -f /tmp/key_a_priv /tmp/key_b_priv
}
trap cleanup EXIT

# Write private keys to temp files (wg set requires file path)
echo "$KEY_A_PRIV" > /tmp/key_a_priv
echo "$KEY_B_PRIV" > /tmp/key_b_priv
chmod 600 /tmp/key_a_priv /tmp/key_b_priv

# Create namespaces and veth pair
ip netns add ns_a
ip netns add ns_b
ip link add veth_a type veth peer name veth_b
ip link set veth_a netns ns_a
ip link set veth_b netns ns_b

# Configure veth addresses
ip netns exec ns_a ip addr add 10.0.0.1/24 dev veth_a
ip netns exec ns_a ip link set veth_a up
ip netns exec ns_a ip link set lo up

ip netns exec ns_b ip addr add 10.0.0.2/24 dev veth_b
ip netns exec ns_b ip link set veth_b up
ip netns exec ns_b ip link set lo up

# Ensure /var/run/wireguard exists
mkdir -p /var/run/wireguard

# Verify veth connectivity
echo "--- Verify veth connectivity ---"
ip netns exec ns_a ping -c 1 -W 1 10.0.0.2 >/dev/null
echo "OK: veth pair connected"

# Start Peer A (wg-c creates TUN "wg_a" in ns_a)
echo "--- Start Peer A (port 51820) ---"
ip netns exec ns_a "$WGC_BIN" -f wg_a &
PID_A=$!
sleep 1

# Configure Peer A via wg tool
ip netns exec ns_a wg set wg_a \
    private-key /tmp/key_a_priv \
    listen-port 51820 \
    peer "$KEY_B_PUB" \
        endpoint 10.0.0.2:51821 \
        allowed-ips 10.99.0.2/32

ip netns exec ns_a ip addr add 10.99.0.1/24 dev wg_a
ip netns exec ns_a ip link set wg_a up

# Start Peer B (listen port 51821)
echo "--- Start Peer B (port 51821) ---"
ip netns exec ns_b "$WGC_BIN" -f wg_b &
PID_B=$!
sleep 1

ip netns exec ns_b wg set wg_b \
    private-key /tmp/key_b_priv \
    listen-port 51821 \
    peer "$KEY_A_PUB" \
        endpoint 10.0.0.1:51820 \
        allowed-ips 10.99.0.1/32

ip netns exec ns_b ip addr add 10.99.0.2/24 dev wg_b
ip netns exec ns_b ip link set wg_b up

# Verify initial tunnel connectivity
echo "--- Verify initial tunnel connectivity ---"
sleep 1
if ip netns exec ns_a ping -c 3 -W 2 10.99.0.2 >/dev/null 2>&1; then
    echo "OK: Initial tunnel working (A → B)"
else
    echo "FAIL: Initial tunnel not working"
    # Show debug info
    echo "--- Debug: wg show on A ---"
    ip netns exec ns_a wg show wg_a || true
    echo "--- Debug: wg show on B ---"
    ip netns exec ns_b wg show wg_b || true
    exit 1
fi

# Check initial endpoint on A
echo "--- Initial endpoint on A ---"
ENDPOINT_BEFORE=$(ip netns exec ns_a wg show wg_a endpoints | grep "$KEY_B_PUB" | awk '{print $2}')
echo "Peer B endpoint (before roaming): $ENDPOINT_BEFORE"

if [[ "$ENDPOINT_BEFORE" != "10.0.0.2:51821" ]]; then
    echo "WARNING: unexpected initial endpoint: $ENDPOINT_BEFORE"
fi

# === ROAMING EVENT ===
echo ""
echo "=== ROAMING: Kill Peer B, restart on port 51822 ==="
kill "$PID_B" 2>/dev/null || true
wait "$PID_B" 2>/dev/null || true
PID_B=""
sleep 1

# Start Peer B on new port (51822)
ip netns exec ns_b "$WGC_BIN" -f wg_b &
PID_B=$!
sleep 1

ip netns exec ns_b wg set wg_b \
    private-key /tmp/key_b_priv \
    listen-port 51822 \
    peer "$KEY_A_PUB" \
        endpoint 10.0.0.1:51820 \
        allowed-ips 10.99.0.1/32

ip netns exec ns_b ip addr add 10.99.0.2/24 dev wg_b 2>/dev/null || true
ip netns exec ns_b ip link set wg_b up

# Peer B sends traffic to A (triggers roaming detection on A)
echo "--- Peer B (new port 51822) pings Peer A ---"
sleep 1
if ip netns exec ns_b ping -c 5 -W 3 10.99.0.1 >/dev/null 2>&1; then
    echo "OK: Tunnel still works after roaming (B → A)"
else
    echo "WARN: ping from B failed, trying reverse direction..."
    # Try A → B to trigger handshake
    ip netns exec ns_a ping -c 3 -W 3 10.99.0.2 >/dev/null 2>&1 || true
    sleep 2
    if ip netns exec ns_b ping -c 5 -W 3 10.99.0.1 >/dev/null 2>&1; then
        echo "OK: Tunnel works after re-handshake (B → A)"
    else
        echo "FAIL: Tunnel broken after roaming"
        echo "--- Debug: wg show on A ---"
        ip netns exec ns_a wg show wg_a || true
        echo "--- Debug: wg show on B ---"
        ip netns exec ns_b wg show wg_b || true
        exit 1
    fi
fi

# Check endpoint on A — should be updated to port 51822
echo "--- Endpoint on A after roaming ---"
ENDPOINT_AFTER=$(ip netns exec ns_a wg show wg_a endpoints | grep "$KEY_B_PUB" | awk '{print $2}')
echo "Peer B endpoint (after roaming): $ENDPOINT_AFTER"

if [[ "$ENDPOINT_AFTER" == "10.0.0.2:51822" ]]; then
    echo ""
    echo "=== PASS: Roaming verified! Endpoint updated 51821 → 51822 ==="
    exit 0
elif [[ "$ENDPOINT_AFTER" == "10.0.0.2:51821" ]]; then
    echo ""
    echo "=== FAIL: Endpoint NOT updated (still 51821) — roaming broken ==="
    exit 1
else
    echo ""
    echo "=== UNEXPECTED: Endpoint is $ENDPOINT_AFTER ==="
    exit 1
fi
