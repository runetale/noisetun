#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Profile wg-c receiver with perf during iperf3 benchmark.
# Usage: sudo env PATH=$PATH bash scripts/perf_profile.sh ./build-release/tools/wg-c [duration]

set -euo pipefail

WGC="${1:-./build-release/tools/wg-c}"
DURATION="${2:-10}"
PERF_DATA="/tmp/wg_perf"

WG_IFACE_A="wga"
WG_IFACE_B="wgb"

cleanup() {
    for pid in ${PIDS:-}; do
        kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    done
    for ns in wgbench_a wgbench_b; do
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -f "/var/run/wireguard/${WG_IFACE_A}.sock" "/var/run/wireguard/${WG_IFACE_B}.sock" 2>/dev/null || true
}
trap cleanup EXIT
PIDS=""

log() { echo "==> $*"; }

[ "$(id -u)" -eq 0 ] || { echo "Error: must be root" >&2; exit 1; }
[ -x "$WGC" ] || { echo "Error: $WGC not found" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg not found" >&2; exit 1; }
command -v iperf3 &>/dev/null || { echo "Error: iperf3 not found" >&2; exit 1; }
command -v perf &>/dev/null || { echo "Error: perf not found" >&2; exit 1; }

mkdir -p /var/run/wireguard

# ── Setup namespaces ──
log "Setting up namespaces..."
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

# ── Generate keys ──
tmpkeys=$(mktemp -d)
key_a_priv=$(wg genkey)
key_a_pub=$(echo "$key_a_priv" | wg pubkey)
key_b_priv=$(wg genkey)
key_b_pub=$(echo "$key_b_priv" | wg pubkey)
echo "$key_a_priv" > "$tmpkeys/a"
echo "$key_b_priv" > "$tmpkeys/b"
chmod 600 "$tmpkeys/a" "$tmpkeys/b"

# ── Start wg-c daemons ──
log "Starting wg-c daemons..."
ip netns exec wgbench_a env WG_PROCESS_FOREGROUND=1 "$WGC" -f "$WG_IFACE_A" &
PID_A=$!
PIDS="$PID_A"

ip netns exec wgbench_b env WG_PROCESS_FOREGROUND=1 "$WGC" -f "$WG_IFACE_B" &
PID_B=$!
PIDS="$PIDS $PID_B"

sleep 2

# ── Configure ──
log "Configuring WireGuard..."
wg set "$WG_IFACE_A" \
    private-key "$tmpkeys/a" listen-port 51820 \
    peer "$key_b_pub" endpoint 192.168.50.2:51821 allowed-ips 10.99.0.0/24

wg set "$WG_IFACE_B" \
    private-key "$tmpkeys/b" listen-port 51821 \
    peer "$key_a_pub" endpoint 192.168.50.1:51820 allowed-ips 10.99.0.0/24

rm -rf "$tmpkeys"

ip netns exec wgbench_a ip addr add 10.99.0.1/24 dev "$WG_IFACE_A"
ip netns exec wgbench_a ip link set "$WG_IFACE_A" up
ip netns exec wgbench_b ip addr add 10.99.0.2/24 dev "$WG_IFACE_B"
ip netns exec wgbench_b ip link set "$WG_IFACE_B" up

# Wait for handshake
sleep 1
ip netns exec wgbench_a ping -c 1 -W 5 10.99.0.2 >/dev/null 2>&1 || true
sleep 1

log "wg-c sender PID=$PID_A (wga), receiver PID=$PID_B (wgb)"

# ── Get thread info ──
log "Thread layout (receiver PID=$PID_B):"
ps -T -p "$PID_B" -o tid,comm 2>/dev/null || true

# ── Start perf on RECEIVER (wgb) ──
# Profile all threads of the receiver process
log "Starting perf record on receiver (PID=$PID_B) for $((DURATION + 4))s..."
perf record -g --call-graph dwarf -p "$PID_B" -o "${PERF_DATA}_recv.data" -- sleep $((DURATION + 4)) &
PID_PERF_RECV=$!

# Also perf stat on receiver for overview
perf stat -e task-clock,context-switches,cpu-migrations,cycles,instructions,cache-misses,L1-dcache-load-misses -p "$PID_B" -o "${PERF_DATA}_recv_stat.txt" -- sleep $((DURATION + 4)) &
PID_PERF_STAT=$!

# Also perf stat on sender
perf stat -e task-clock,context-switches,cpu-migrations,cycles,instructions,cache-misses,L1-dcache-load-misses -p "$PID_A" -o "${PERF_DATA}_send_stat.txt" -- sleep $((DURATION + 4)) &
PID_PERF_STAT2=$!

sleep 1

# ── Run iperf3 ──
log "Running iperf3 (${DURATION}s, 4 parallel streams)..."
ip netns exec wgbench_b iperf3 -s -1 -D
sleep 1

result=$(ip netns exec wgbench_a iperf3 -c 10.99.0.2 -t "$DURATION" -P 4 -J 2>&1) || true

bps=$(echo "$result" | jq -r '.end.sum_received.bits_per_second / 1e9 | . * 100 | floor / 100 | tostring' 2>/dev/null) || bps="N/A"
[ -z "$bps" ] && bps="N/A"

echo ""
echo "  Throughput: $bps Gbps"

# Wait for perf to finish
log "Waiting for perf to complete..."
wait "$PID_PERF_RECV" 2>/dev/null || true
wait "$PID_PERF_STAT" 2>/dev/null || true
wait "$PID_PERF_STAT2" 2>/dev/null || true

# ── Show results ──
echo ""
echo "=== SENDER (wga) perf stat ==="
cat "${PERF_DATA}_send_stat.txt" 2>/dev/null || true

echo ""
echo "=== RECEIVER (wgb) perf stat ==="
cat "${PERF_DATA}_recv_stat.txt" 2>/dev/null || true

echo ""
echo "=== RECEIVER (wgb) perf report (top 30 functions) ==="
perf report -i "${PERF_DATA}_recv.data" --stdio --no-children -g none --percent-limit 1.0 2>/dev/null | head -60 || true

echo ""
echo "=== RECEIVER (wgb) perf report by thread ==="
perf report -i "${PERF_DATA}_recv.data" --stdio --no-children -g none --sort comm,dso,symbol --percent-limit 2.0 2>/dev/null | head -80 || true

log "Raw perf data at ${PERF_DATA}_recv.data"
log "Done."
