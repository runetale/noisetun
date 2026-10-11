#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# iperf3 throughput comparison: wg-c vs wireguard-go
#
# Sets up WireGuard tunnels using both implementations and runs
# iperf3 through each for a side-by-side throughput comparison.
#
# Requirements: root, wg-c, wireguard-go, wg, ip, iperf3
# Usage: sudo scripts/bench_iperf3.sh [path-to-wg-c] [duration]

set -euo pipefail

WGC="${1:-./build/tools/wg-c}"
DURATION="${2:-10}"
WG_IFACE="wg0"

cleanup() {
    for pid in ${PIDS:-}; do
        kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    done
    for ns in wgbench_a wgbench_b; do
        ip netns del "$ns" 2>/dev/null || true
    done
}

trap cleanup EXIT
PIDS=""

log() { echo "==> $*"; }

# ──────────────────────────────────────
# Preflight
# ──────────────────────────────────────

[ "$(id -u)" -eq 0 ] || { echo "Error: must be root" >&2; exit 1; }
[ -x "$WGC" ] || { echo "Error: $WGC not found" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg not found" >&2; exit 1; }
command -v iperf3 &>/dev/null || { echo "Error: iperf3 not found" >&2; exit 1; }

HAS_WG_GO=true
command -v wireguard-go &>/dev/null || HAS_WG_GO=false

# ──────────────────────────────────────
# Helper: setup tunnel pair in namespaces
# ──────────────────────────────────────

setup_tunnel() {
    local daemon_a="$1"  # command to start daemon in NS A
    local daemon_b="$2"  # command to start daemon in NS B
    local label="$3"

    log "Setting up $label tunnel..."

    ip netns add wgbench_a
    ip netns add wgbench_b

    ip link add veth_a type veth peer name veth_b
    ip link set veth_a netns wgbench_a
    ip link set veth_b netns wgbench_b

    ip netns exec wgbench_a ip addr add 192.168.50.1/24 dev veth_a
    ip netns exec wgbench_a ip link set veth_a up
    ip netns exec wgbench_a ip link set lo up

    ip netns exec wgbench_b ip addr add 192.168.50.2/24 dev veth_b
    ip netns exec wgbench_b ip link set veth_b up
    ip netns exec wgbench_b ip link set lo up

    # Generate keys
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

    # Start daemons
    ip netns exec wgbench_a env WG_PROCESS_FOREGROUND=1 $daemon_a &
    PIDS="$PIDS $!"
    ip netns exec wgbench_b env WG_PROCESS_FOREGROUND=1 $daemon_b &
    PIDS="$PIDS $!"
    sleep 2

    # Configure
    ip netns exec wgbench_a wg set "$WG_IFACE" \
        private-key "$tmpkeys/a" listen-port 51820 \
        peer "$key_b_pub" endpoint 192.168.50.2:51821 allowed-ips 10.99.0.0/24

    ip netns exec wgbench_b wg set "$WG_IFACE" \
        private-key "$tmpkeys/b" listen-port 51821 \
        peer "$key_a_pub" endpoint 192.168.50.1:51820 allowed-ips 10.99.0.0/24

    rm -rf "$tmpkeys"

    ip netns exec wgbench_a ip addr add 10.99.0.1/24 dev "$WG_IFACE"
    ip netns exec wgbench_a ip link set "$WG_IFACE" up

    ip netns exec wgbench_b ip addr add 10.99.0.2/24 dev "$WG_IFACE"
    ip netns exec wgbench_b ip link set "$WG_IFACE" up

    # Wait for handshake
    sleep 1
    ip netns exec wgbench_a ping -c 1 -W 5 10.99.0.2 >/dev/null 2>&1 || true
    sleep 1
}

teardown_tunnel() {
    for pid in $PIDS; do
        kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    done
    PIDS=""
    ip netns del wgbench_a 2>/dev/null || true
    ip netns del wgbench_b 2>/dev/null || true
    sleep 1
}

run_iperf3() {
    local label="$1"
    log "Running iperf3 ($label, ${DURATION}s)..."

    # Start server in NS B
    ip netns exec wgbench_b iperf3 -s -1 -D
    sleep 1

    # Run client from NS A
    local result
    result=$(ip netns exec wgbench_a iperf3 -c 10.99.0.2 -t "$DURATION" -P 4 -J 2>&1) || true

    # Extract throughput from JSON
    local bps
    bps=$(echo "$result" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    bps = d['end']['sum_received']['bits_per_second']
    print(f'{bps / 1e9:.2f}')
except:
    print('N/A')
" 2>/dev/null) || bps="N/A"

    echo "  $label: $bps Gbps"
    eval "${label}_RESULT=$bps"
}

# ──────────────────────────────────────
# Run benchmarks
# ──────────────────────────────────────

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║    iperf3 Throughput Comparison            ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# wg-c vs wg-c
setup_tunnel "$WGC -f $WG_IFACE" "$WGC -f $WG_IFACE" "wg-c"
run_iperf3 "wg_c"
teardown_tunnel

# wireguard-go vs wireguard-go
if $HAS_WG_GO; then
    setup_tunnel "wireguard-go -f $WG_IFACE" "wireguard-go -f $WG_IFACE" "wireguard-go"
    run_iperf3 "wg_go"
    teardown_tunnel
fi

# ──────────────────────────────────────
# Summary
# ──────────────────────────────────────

echo ""
echo "  ┌─────────────────────────────────────────┐"
echo "  │  Throughput Comparison (iperf3)          │"
echo "  ├─────────────────────────────────────────┤"
echo "  │  wg-c:          ${wg_c_RESULT:-N/A} Gbps                │"
if $HAS_WG_GO; then
echo "  │  wireguard-go:  ${wg_go_RESULT:-N/A} Gbps                │"
else
echo "  │  wireguard-go:  (not installed)          │"
fi
echo "  └─────────────────────────────────────────┘"
