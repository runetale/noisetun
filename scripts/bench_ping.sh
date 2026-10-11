#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Ping latency comparison: wg-c vs wireguard-go
#
# Requirements: root, wg-c, wireguard-go (optional), wg, ip
# Usage: sudo scripts/bench_ping.sh [path-to-wg-c] [count]

set -euo pipefail

WGC="${1:-./build/tools/wg-c}"
COUNT="${2:-100}"
WG_IFACE="wg0"

cleanup() {
    for pid in ${PIDS:-}; do
        kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    done
    for ns in wgping_a wgping_b; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

trap cleanup EXIT
PIDS=""

log() { echo "==> $*"; }

[ "$(id -u)" -eq 0 ] || { echo "Error: must be root" >&2; exit 1; }
[ -x "$WGC" ] || { echo "Error: $WGC not found" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg not found" >&2; exit 1; }

HAS_WG_GO=true
command -v wireguard-go &>/dev/null || HAS_WG_GO=false

setup_tunnel() {
    local daemon_a="$1"
    local daemon_b="$2"
    local label="$3"

    log "Setting up $label tunnel..."

    ip netns add wgping_a
    ip netns add wgping_b

    ip link add veth_a type veth peer name veth_b
    ip link set veth_a netns wgping_a
    ip link set veth_b netns wgping_b

    ip netns exec wgping_a ip addr add 192.168.60.1/24 dev veth_a
    ip netns exec wgping_a ip link set veth_a up
    ip netns exec wgping_a ip link set lo up

    ip netns exec wgping_b ip addr add 192.168.60.2/24 dev veth_b
    ip netns exec wgping_b ip link set veth_b up
    ip netns exec wgping_b ip link set lo up

    local key_a_priv key_a_pub key_b_priv key_b_pub
    local tmpkeys
    tmpkeys=$(mktemp -d)
    key_a_priv=$(wg genkey)
    key_a_pub=$(echo "$key_a_priv" | wg pubkey)
    key_b_priv=$(wg genkey)
    key_b_pub=$(echo "$key_b_priv" | wg pubkey)
    echo "$key_a_priv" > "$tmpkeys/a"
    echo "$key_b_priv" > "$tmpkeys/b"
    chmod 600 "$tmpkeys/a" "$tmpkeys/b"

    ip netns exec wgping_a env WG_PROCESS_FOREGROUND=1 $daemon_a &
    PIDS="$PIDS $!"
    ip netns exec wgping_b env WG_PROCESS_FOREGROUND=1 $daemon_b &
    PIDS="$PIDS $!"
    sleep 2

    ip netns exec wgping_a wg set "$WG_IFACE" \
        private-key "$tmpkeys/a" listen-port 51820 \
        peer "$key_b_pub" endpoint 192.168.60.2:51821 allowed-ips 10.88.0.0/24

    ip netns exec wgping_b wg set "$WG_IFACE" \
        private-key "$tmpkeys/b" listen-port 51821 \
        peer "$key_a_pub" endpoint 192.168.60.1:51820 allowed-ips 10.88.0.0/24

    rm -rf "$tmpkeys"

    ip netns exec wgping_a ip addr add 10.88.0.1/24 dev "$WG_IFACE"
    ip netns exec wgping_a ip link set "$WG_IFACE" up

    ip netns exec wgping_b ip addr add 10.88.0.2/24 dev "$WG_IFACE"
    ip netns exec wgping_b ip link set "$WG_IFACE" up

    sleep 1
    ip netns exec wgping_a ping -c 1 -W 5 10.88.0.2 >/dev/null 2>&1 || true
    sleep 1
}

teardown_tunnel() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    done
    PIDS=""
    ip netns del wgping_a 2>/dev/null || true
    ip netns del wgping_b 2>/dev/null || true
    sleep 1
}

run_ping_bench() {
    local label="$1"
    log "Running ping ($label, $COUNT packets)..."

    local result
    result=$(ip netns exec wgping_a ping -c "$COUNT" -i 0.01 10.88.0.2 2>&1) || true

    # Extract stats line: rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms
    local stats
    stats=$(echo "$result" | grep "rtt\|round-trip" || echo "N/A")
    echo "  $label: $stats"
}

# ──────────────────────────────────────
# Run
# ──────────────────────────────────────

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║    Ping Latency Comparison                 ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

setup_tunnel "$WGC -f $WG_IFACE" "$WGC -f $WG_IFACE" "wg-c"
run_ping_bench "wg-c"
teardown_tunnel

if $HAS_WG_GO; then
    setup_tunnel "wireguard-go -f $WG_IFACE" "wireguard-go -f $WG_IFACE" "wireguard-go"
    run_ping_bench "wireguard-go"
    teardown_tunnel
fi

echo ""
echo "Done."
