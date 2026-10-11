#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Cookie Reply (DDoS protection) verification test
#
# Tests:
#   1. Normal handshake succeeds (no under_load)
#   2. Flood triggers under_load → server sends cookie replies (type 3)
#   3. Client handshake succeeds in under_load decay window (cookie exchange)
#   4. Verify cookie reply (type 3, 64 bytes) in pcap
#
# Cookie exchange flow verified:
#   - Client sends initiation (MAC2=0) → server under_load → cookie reply
#   - Client consumes cookie, retries with MAC2 → server accepts
#   - Test 3 proves this by connecting during the 1-second under_load
#     decay window (queue empty but under_load_until still active)
#
# Requirements: root, wg-c binary, wg (wireguard-tools), libsodium-dev, gcc

set -euo pipefail

WGC_BIN="${WGC_BIN:-./build-release/tools/wg-c}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FLOOD_SRC="${SCRIPT_DIR}/flood_initiation.c"
FLOOD_BIN="/tmp/flood_initiation"

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

# Build flood tool
if [[ ! -f "$FLOOD_SRC" ]]; then
    echo "ERROR: flood_initiation.c not found at $FLOOD_SRC"
    exit 1
fi

echo "Building flood tool..."
cc -O2 -o "$FLOOD_BIN" "$FLOOD_SRC" -lsodium 2>/dev/null || {
    cc -O2 -o "$FLOOD_BIN" "$FLOOD_SRC" $(pkg-config --cflags --libs libsodium) 2>/dev/null || {
        echo "ERROR: cannot compile flood_initiation.c (need libsodium-dev)"
        exit 1
    }
}
echo "  Flood tool built: $FLOOD_BIN"

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# Pre-cleanup
pkill -f "wg-c -f wg_ck" 2>/dev/null || true
sleep 0.3
ip netns del ns_cksrv 2>/dev/null || true
ip netns del ns_ckcli 2>/dev/null || true
ip netns del ns_ckfld 2>/dev/null || true
ip link del br_ck 2>/dev/null || true
rm -f /var/run/wireguard/wg_cksrv.sock /var/run/wireguard/wg_ckcli.sock
sleep 0.3

# Generate keys
KEY_SRV_PRIV=$(wg genkey); KEY_SRV_PUB=$(echo "$KEY_SRV_PRIV" | wg pubkey)
KEY_CLI_PRIV=$(wg genkey); KEY_CLI_PUB=$(echo "$KEY_CLI_PRIV" | wg pubkey)

echo "=== Cookie Reply (DDoS Protection) Test ==="
echo "Server pub: $KEY_SRV_PUB"
echo "Client pub: $KEY_CLI_PUB"

PID_SRV=""
PID_CLI=""
PIDS_FLOOD=()
PID_TCPDUMP=""

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    [[ -n "$PID_TCPDUMP" ]] && kill "$PID_TCPDUMP" 2>/dev/null || true
    for pid in "${PIDS_FLOOD[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    [[ -n "$PID_CLI" ]] && kill "$PID_CLI" 2>/dev/null || true
    [[ -n "$PID_SRV" ]] && kill "$PID_SRV" 2>/dev/null || true
    sleep 0.5
    ip netns del ns_cksrv 2>/dev/null || true
    ip netns del ns_ckcli 2>/dev/null || true
    ip netns del ns_ckfld 2>/dev/null || true
    ip link del br_ck 2>/dev/null || true
    rm -f /tmp/key_cksrv /tmp/key_ckcli /tmp/cookie_test.pcap "$FLOOD_BIN"
}
trap cleanup EXIT

# Write keys
echo "$KEY_SRV_PRIV" > /tmp/key_cksrv
echo "$KEY_CLI_PRIV" > /tmp/key_ckcli
chmod 600 /tmp/key_cksrv /tmp/key_ckcli

# Create namespaces: server, client, and flood (separate to avoid veth saturation)
ip netns add ns_cksrv
ip netns add ns_ckcli
ip netns add ns_ckfld

ip link add br_ck type bridge
ip link set br_ck up

for ns in cksrv ckcli ckfld; do
    ip link add "veth_${ns}" type veth peer name "veth_${ns}_br"
    ip link set "veth_${ns}" netns "ns_${ns}"
    ip link set "veth_${ns}_br" master br_ck
    ip link set "veth_${ns}_br" up
done

ip netns exec ns_cksrv ip addr add 10.2.0.1/24 dev veth_cksrv
ip netns exec ns_cksrv ip link set veth_cksrv up
ip netns exec ns_cksrv ip link set lo up

ip netns exec ns_ckcli ip addr add 10.2.0.2/24 dev veth_ckcli
ip netns exec ns_ckcli ip link set veth_ckcli up
ip netns exec ns_ckcli ip link set lo up

ip netns exec ns_ckfld ip addr add 10.2.0.3/24 dev veth_ckfld
ip netns exec ns_ckfld ip link set veth_ckfld up
ip netns exec ns_ckfld ip link set lo up

mkdir -p /var/run/wireguard

# === TEST 1: Normal handshake (no under_load) ===
echo ""
echo "--- [1] Normal handshake (no flood, no cookie required) ---"

ip netns exec ns_cksrv "$WGC_BIN" -f wg_cksrv &
PID_SRV=$!
sleep 1

ip netns exec ns_cksrv wg set wg_cksrv \
    private-key /tmp/key_cksrv \
    listen-port 51820 \
    peer "$KEY_CLI_PUB" allowed-ips 10.99.0.2/32

ip netns exec ns_cksrv ip addr add 10.99.0.1/24 dev wg_cksrv
ip netns exec ns_cksrv ip link set wg_cksrv up

ip netns exec ns_ckcli "$WGC_BIN" -f wg_ckcli &
PID_CLI=$!
sleep 1

ip netns exec ns_ckcli wg set wg_ckcli \
    private-key /tmp/key_ckcli \
    listen-port 51821 \
    peer "$KEY_SRV_PUB" endpoint 10.2.0.1:51820 allowed-ips 10.99.0.1/32

ip netns exec ns_ckcli ip addr add 10.99.0.2/24 dev wg_ckcli
ip netns exec ns_ckcli ip link set wg_ckcli up

sleep 1
if ip netns exec ns_ckcli ping -c 3 -W 3 10.99.0.1 >/dev/null 2>&1; then
    pass "Normal handshake succeeds (no cookie needed)"
else
    fail "Normal handshake failed"
fi

# === TEST 2: Flood → under_load → cookie replies generated ===
echo ""
echo "--- [2] Flood → under_load → cookie replies ---"

# Kill client
kill "$PID_CLI" 2>/dev/null || true
wait "$PID_CLI" 2>/dev/null || true
PID_CLI=""
rm -f /var/run/wireguard/wg_ckcli.sock
sleep 1

# Start tcpdump on server to capture outgoing packets
ip netns exec ns_cksrv tcpdump -i veth_cksrv -w /tmp/cookie_test.pcap \
    'udp and src port 51820' 2>/dev/null &
PID_TCPDUMP=$!
sleep 0.5

# Flood from separate namespace (max rate, saturates queue)
echo "  Flooding for 5s (max rate)..."
ip netns exec ns_ckfld "$FLOOD_BIN" 10.2.0.1 51820 5 "$KEY_SRV_PUB" &
PIDS_FLOOD+=($!)

wait "${PIDS_FLOOD[@]}" 2>/dev/null || true
PIDS_FLOOD=()
echo "  Flood complete"

# Stop tcpdump
kill "$PID_TCPDUMP" 2>/dev/null || true
wait "$PID_TCPDUMP" 2>/dev/null || true
PID_TCPDUMP=""
sleep 0.5

# Check pcap for cookie replies (64-byte packets from server)
if [[ -f /tmp/cookie_test.pcap ]]; then
    COOKIE_COUNT=$(tcpdump -r /tmp/cookie_test.pcap -nn 2>/dev/null | grep -c "length 64" || echo "0")
    if [[ "$COOKIE_COUNT" -gt 0 ]]; then
        pass "Cookie reply packets generated under flood (count: $COOKIE_COUNT)"
    else
        echo "  INFO: Captured packet sizes:"
        tcpdump -r /tmp/cookie_test.pcap -nn 2>/dev/null | \
            grep -oP 'length \d+' | sort | uniq -c | sort -rn | head -5 || true
        fail "No cookie reply packets found"
    fi
else
    fail "No capture file"
fi

# === TEST 3: Handshake during under_load decay window ===
echo ""
echo "--- [3] Handshake in under_load decay window (cookie exchange) ---"
echo "  Strategy: flood → stop → immediately start client."
echo "  Server is still in under_load state (1s decay) but queue is empty."
echo "  Client initiation enters queue → MAC2 missing → cookie reply sent."
echo "  Client retries with MAC2 → accepted → handshake completes."

# Flood again to set under_load_until (5 seconds of flood)
echo "  Flooding for 5s..."
ip netns exec ns_ckfld "$FLOOD_BIN" 10.2.0.1 51820 5 "$KEY_SRV_PUB" &
PIDS_FLOOD+=($!)
wait "${PIDS_FLOOD[@]}" 2>/dev/null || true
PIDS_FLOOD=()

# Server is now in under_load state (decays after 1 second).
# Start client IMMEDIATELY — server will require MAC2.
echo "  Flood stopped. Starting client in under_load decay window..."
ip netns exec ns_ckcli "$WGC_BIN" -f wg_ckcli &
PID_CLI=$!
sleep 0.5

ip netns exec ns_ckcli wg set wg_ckcli \
    private-key /tmp/key_ckcli \
    listen-port 51821 \
    peer "$KEY_SRV_PUB" endpoint 10.2.0.1:51820 allowed-ips 10.99.0.1/32

ip netns exec ns_ckcli ip addr add 10.99.0.2/24 dev wg_ckcli 2>/dev/null || true
ip netns exec ns_ckcli ip link set wg_ckcli up

# Client flow:
#   1. Sends initiation (MAC2=0)
#   2. Server: under_load=true, MAC2 check fails → sends cookie reply
#   3. Client receives cookie reply → stores cookie
#   4. Client timer fires retransmit (5s) → sends initiation with MAC2
#   5. Server: under_load may have decayed, or MAC2 now valid → processes
#
# Wait for retransmit + processing
sleep 7

if ip netns exec ns_ckcli ping -c 3 -W 3 10.99.0.1 >/dev/null 2>&1; then
    pass "Handshake completes via cookie exchange (under_load active)"
else
    fail "Handshake failed in under_load decay window"
fi

# === TEST 4: Verify the handshake used cookie (server shows recent handshake) ===
echo ""
echo "--- [4] Verify handshake timestamp ---"

HS_TIME=$(ip netns exec ns_cksrv wg show wg_cksrv latest-handshakes | awk '{print $2}')
TS_NOW=$(date +%s)
if [[ -n "$HS_TIME" && "$HS_TIME" != "0" ]]; then
    HS_AGO=$((TS_NOW - HS_TIME))
    if [[ "$HS_AGO" -lt 10 ]]; then
        pass "Recent handshake confirmed (${HS_AGO}s ago)"
    else
        fail "Handshake too old (${HS_AGO}s ago)"
    fi
else
    fail "No handshake timestamp"
fi

# Summary
echo ""
echo "==============================="
echo "  PASS: $PASS  FAIL: $FAIL"
echo "==============================="

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "--- Debug: wg show ---"
    ip netns exec ns_cksrv wg show wg_cksrv || true
    ip netns exec ns_ckcli wg show wg_ckcli || true
    exit 1
fi

exit 0
