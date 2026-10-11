#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Rigorous A/B benchmark: wg-c vs wireguard-go
#
# Fair comparison methodology:
#   - iperf3 --omit 3: skip TCP slow start for both
#   - 10 runs each, alternating (wg-c, wg-go, wg-c, wg-go, ...)
#   - Cold start: process restart before each run
#   - CPU usage measured via mpstat during each run
#   - Retransmissions recorded from iperf3 JSON output
#   - All results in JSON for analysis
#
# Usage: sudo scripts/bench_rigorous.sh <wg-c-path> <wg-go-path> [runs] [duration]
#
# Ubuntu 26.04+: the AppArmor profile for wg(8) only reads /etc/wireguard/**
# and does not allow connecting to the UAPI socket. Allow the socket and
# keep the keys under /etc/wireguard (see performance-analysis.md #44):
#   echo '/run/wireguard/*.sock rw,' | sudo tee -a /etc/apparmor.d/local/wg
#   sudo apparmor_parser -r /etc/apparmor.d/wg
#   sudo TMPDIR=/etc/wireguard scripts/bench_rigorous.sh ...

set -euo pipefail

WGC="${1:?Usage: $0 <wg-c-path> <wg-go-path> [runs] [duration]}"
WG_GO="${2:?Usage: $0 <wg-c-path> <wg-go-path> [runs] [duration]}"
RUNS="${3:-10}"
DURATION="${4:-30}"
OMIT=3

NS_A="bench_a"
NS_B="bench_b"
VETH_A="veth_a"
VETH_B="veth_b"
WG_IFACE_A="wg0"
WG_IFACE_B="wg1"
PORT_A=51820
PORT_B=51821

VETH_IP_A="192.168.200.1/24"
VETH_IP_B="192.168.200.2/24"
VETH_ADDR_A="192.168.200.1"
VETH_ADDR_B="192.168.200.2"

WG_IP_A="10.10.0.1/24"
WG_IP_B="10.10.0.2/24"
WG_ADDR_A="10.10.0.1"
WG_ADDR_B="10.10.0.2"

RESULTS_DIR="/tmp/bench_rigorous_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

cleanup_ns() {
    # Kill any leftover iperf3 in namespaces
    ip netns exec "$NS_A" killall -9 iperf3 2>/dev/null || true
    ip netns exec "$NS_B" killall -9 iperf3 2>/dev/null || true
    # Kill wg-c processes
    ip netns exec "$NS_A" killall -9 wg-c 2>/dev/null || true
    ip netns exec "$NS_B" killall -9 wg-c 2>/dev/null || true
    # Remove wg interfaces (kills wireguard-go)
    ip netns exec "$NS_A" ip link del "$WG_IFACE_A" 2>/dev/null || true
    ip netns exec "$NS_B" ip link del "$WG_IFACE_B" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    rm -rf "${TMPDIR_KEYS:-}" 2>/dev/null || true
}

cleanup_all() {
    cleanup_ns
    # Kill background mpstat if running
    [ -n "${MPSTAT_PID:-}" ] && kill "$MPSTAT_PID" 2>/dev/null || true
}

trap cleanup_all EXIT

# ── Preflight ──
[ "$(id -u)" -eq 0 ] || { echo "Error: must be root" >&2; exit 1; }
[ -x "$WGC" ] || { echo "Error: $WGC not found" >&2; exit 1; }
command -v "$WG_GO" &>/dev/null || [ -x "$WG_GO" ] || { echo "Error: $WG_GO not found" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg not found" >&2; exit 1; }
command -v iperf3 &>/dev/null || { echo "Error: iperf3 not found" >&2; exit 1; }
command -v jq &>/dev/null || { echo "Error: jq not found" >&2; exit 1; }

# ── Setup network namespaces + veth ──
setup_namespaces() {
    ip netns add "$NS_A"
    ip netns add "$NS_B"

    ip link add "$VETH_A" type veth peer name "$VETH_B"
    ip link set "$VETH_A" netns "$NS_A"
    ip link set "$VETH_B" netns "$NS_B"

    ip netns exec "$NS_A" ip link set "$VETH_A" mtu 1500 txqueuelen 10000
    ip netns exec "$NS_B" ip link set "$VETH_B" mtu 1500 txqueuelen 10000

    ip netns exec "$NS_A" ip addr add "$VETH_IP_A" dev "$VETH_A"
    ip netns exec "$NS_A" ip link set "$VETH_A" up
    ip netns exec "$NS_A" ip link set lo up

    ip netns exec "$NS_B" ip addr add "$VETH_IP_B" dev "$VETH_B"
    ip netns exec "$NS_B" ip link set "$VETH_B" up
    ip netns exec "$NS_B" ip link set lo up
}

# ── Generate WireGuard keys ──
generate_keys() {
    TMPDIR_KEYS=$(mktemp -d)
    KEY_A_PRIV=$(wg genkey)
    KEY_A_PUB=$(echo "$KEY_A_PRIV" | wg pubkey)
    KEY_B_PRIV=$(wg genkey)
    KEY_B_PUB=$(echo "$KEY_B_PRIV" | wg pubkey)
    echo "$KEY_A_PRIV" > "$TMPDIR_KEYS/key_a"
    echo "$KEY_B_PRIV" > "$TMPDIR_KEYS/key_b"
    chmod 600 "$TMPDIR_KEYS/key_a" "$TMPDIR_KEYS/key_b"
}

# ── Start wg-c and configure ──
start_wgc() {
    ip netns exec "$NS_A" env WG_PROCESS_FOREGROUND=1 "$WGC" -f "$WG_IFACE_A" &
    PID_WGC_A=$!
    sleep 1
    kill -0 "$PID_WGC_A" 2>/dev/null || { log "wg-c A failed"; return 1; }

    ip netns exec "$NS_B" env WG_PROCESS_FOREGROUND=1 "$WGC" -f "$WG_IFACE_B" &
    PID_WGC_B=$!
    sleep 1
    kill -0 "$PID_WGC_B" 2>/dev/null || { log "wg-c B failed"; return 1; }

    configure_peers
}

# ── Start wireguard-go and configure ──
start_wg_go() {
    ip netns exec "$NS_A" env WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 "$WG_GO" "$WG_IFACE_A"
    sleep 1
    ip netns exec "$NS_B" env WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 "$WG_GO" "$WG_IFACE_B"
    sleep 1

    configure_peers
}

# ── Configure WireGuard peers (common) ──
configure_peers() {
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

    ip netns exec "$NS_A" ip addr add "$WG_IP_A" dev "$WG_IFACE_A"
    ip netns exec "$NS_A" ip link set "$WG_IFACE_A" up

    ip netns exec "$NS_B" ip addr add "$WG_IP_B" dev "$WG_IFACE_B"
    ip netns exec "$NS_B" ip link set "$WG_IFACE_B" up

    # Verify connectivity
    ip netns exec "$NS_A" ping -c 2 -W 5 "$WG_ADDR_B" > /dev/null || { log "Ping failed"; return 1; }
}

# ── Stop wg-c ──
stop_wgc() {
    kill "$PID_WGC_A" 2>/dev/null && wait "$PID_WGC_A" 2>/dev/null || true
    kill "$PID_WGC_B" 2>/dev/null && wait "$PID_WGC_B" 2>/dev/null || true
    # Interfaces disappear when wg-c exits
    sleep 0.5
}

# ── Stop wireguard-go ──
stop_wg_go() {
    ip netns exec "$NS_A" ip link del "$WG_IFACE_A" 2>/dev/null || true
    ip netns exec "$NS_B" ip link del "$WG_IFACE_B" 2>/dev/null || true
    sleep 0.5
}

# ── Run single iperf3 test with CPU measurement ──
# Args: $1=impl_name $2=run_number
run_single_test() {
    local impl="$1"
    local run="$2"
    local result_file="$RESULTS_DIR/${impl}_run${run}.json"
    local cpu_file="$RESULTS_DIR/${impl}_run${run}_cpu.txt"

    # Start mpstat in background (1-second intervals for the duration)
    mpstat -P ALL 1 $((DURATION + OMIT + 2)) > "$cpu_file" 2>/dev/null &
    MPSTAT_PID=$!

    # Start iperf3 server
    ip netns exec "$NS_B" iperf3 -s -D -1
    sleep 1

    # Run iperf3 client with --omit and JSON output
    ip netns exec "$NS_A" iperf3 -c "$WG_ADDR_B" \
        -t "$DURATION" --omit "$OMIT" -P 1 -J \
        > "$result_file" 2>/dev/null || true

    # Stop mpstat
    kill "$MPSTAT_PID" 2>/dev/null || true
    wait "$MPSTAT_PID" 2>/dev/null || true
    unset MPSTAT_PID

    # Kill iperf3 server
    ip netns exec "$NS_B" killall -9 iperf3 2>/dev/null || true

    # Extract results
    if [ -f "$result_file" ] && jq -e '.end' "$result_file" > /dev/null 2>&1; then
        local bps=$(jq '.end.sum_sent.bits_per_second' "$result_file")
        local gbps=$(echo "scale=3; $bps / 1000000000" | bc)
        local retrans=$(jq '.end.sum_sent.retransmits // 0' "$result_file")
        local avg_cpu_total=$(jq '(.end.cpu_utilization_percent.host_total // 0)' "$result_file")

        # Get mpstat average CPU (all cores)
        local mpstat_avg=""
        if [ -f "$cpu_file" ]; then
            mpstat_avg=$(grep "Average.*all" "$cpu_file" | awk '{print 100.0 - $NF}' 2>/dev/null || echo "N/A")
        fi

        log "  $impl run $run: ${gbps} Gbps, retrans=$retrans, cpu_iperf=${avg_cpu_total}%, cpu_mpstat=${mpstat_avg}%"
        echo "${gbps}" >> "$RESULTS_DIR/${impl}_gbps.txt"
        echo "${retrans}" >> "$RESULTS_DIR/${impl}_retrans.txt"
    else
        log "  $impl run $run: FAILED (no valid JSON output)"
        echo "0" >> "$RESULTS_DIR/${impl}_gbps.txt"
        echo "-1" >> "$RESULTS_DIR/${impl}_retrans.txt"
    fi
}

# ════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════

log "╔══════════════════════════════════════════╗"
log "║   Rigorous Benchmark: wg-c vs wg-go     ║"
log "╠══════════════════════════════════════════╣"
log "║  wg-c:     $WGC"
log "║  wg-go:    $WG_GO"
log "║  Runs:     $RUNS each"
log "║  Duration: ${DURATION}s (--omit ${OMIT}s)"
log "║  Results:  $RESULTS_DIR"
log "╚══════════════════════════════════════════╝"
echo ""

# Initialize result files
> "$RESULTS_DIR/wgc_gbps.txt"
> "$RESULTS_DIR/wgc_retrans.txt"
> "$RESULTS_DIR/wggo_gbps.txt"
> "$RESULTS_DIR/wggo_retrans.txt"

for i in $(seq 1 "$RUNS"); do
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "Round $i / $RUNS"
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # ── wg-c (cold start) ──
    log "  [wg-c] Setting up..."
    setup_namespaces
    generate_keys
    start_wgc
    log "  [wg-c] Running iperf3..."
    run_single_test "wgc" "$i"
    stop_wgc
    cleanup_ns
    sleep 2

    # ── wg-go (cold start) ──
    log "  [wg-go] Setting up..."
    setup_namespaces
    generate_keys
    start_wg_go
    log "  [wg-go] Running iperf3..."
    run_single_test "wggo" "$i"
    stop_wg_go
    cleanup_ns
    sleep 2
done

# ════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════
echo ""
log "╔══════════════════════════════════════════╗"
log "║              RESULTS                     ║"
log "╚══════════════════════════════════════════╝"
echo ""

echo "=== wg-c Throughput (Gbps) ==="
cat "$RESULTS_DIR/wgc_gbps.txt" | nl
echo ""

echo "=== wg-go Throughput (Gbps) ==="
cat "$RESULTS_DIR/wggo_gbps.txt" | nl
echo ""

echo "=== wg-c Retransmissions ==="
cat "$RESULTS_DIR/wgc_retrans.txt" | nl
echo ""

echo "=== wg-go Retransmissions ==="
cat "$RESULTS_DIR/wggo_retrans.txt" | nl
echo ""

# Calculate statistics
calc_stats() {
    local file="$1"
    local label="$2"
    local values=$(cat "$file" | grep -v "^0$" || true)
    if [ -z "$values" ]; then
        echo "$label: NO VALID RESULTS"
        return
    fi
    local count=$(echo "$values" | wc -l)
    local sum=$(echo "$values" | paste -sd+ | bc)
    local avg=$(echo "scale=3; $sum / $count" | bc)
    local min=$(echo "$values" | sort -n | head -1)
    local max=$(echo "$values" | sort -n | tail -1)
    # Median
    local mid=$(( (count + 1) / 2 ))
    local median=$(echo "$values" | sort -n | sed -n "${mid}p")
    # Stddev
    local sumsq=$(echo "$values" | awk -v avg="$avg" '{s += ($1-avg)^2} END {print s}')
    local stddev=$(echo "scale=3; sqrt($sumsq / $count)" | bc)

    echo "$label:"
    echo "  Count:  $count"
    echo "  Mean:   $avg Gbps"
    echo "  Median: $median Gbps"
    echo "  Min:    $min Gbps"
    echo "  Max:    $max Gbps"
    echo "  Stddev: $stddev Gbps"
}

echo "=== STATISTICS ==="
echo ""
calc_stats "$RESULTS_DIR/wgc_gbps.txt" "wg-c"
echo ""
calc_stats "$RESULTS_DIR/wggo_gbps.txt" "wg-go"
echo ""

# Comparison
WGC_AVG=$(cat "$RESULTS_DIR/wgc_gbps.txt" | grep -v "^0$" | paste -sd+ | bc)
WGC_COUNT=$(cat "$RESULTS_DIR/wgc_gbps.txt" | grep -v "^0$" | wc -l)
WGGO_AVG=$(cat "$RESULTS_DIR/wggo_gbps.txt" | grep -v "^0$" | paste -sd+ | bc)
WGGO_COUNT=$(cat "$RESULTS_DIR/wggo_gbps.txt" | grep -v "^0$" | wc -l)

if [ "$WGC_COUNT" -gt 0 ] && [ "$WGGO_COUNT" -gt 0 ]; then
    WGC_MEAN=$(echo "scale=3; $WGC_AVG / $WGC_COUNT" | bc)
    WGGO_MEAN=$(echo "scale=3; $WGGO_AVG / $WGGO_COUNT" | bc)
    RATIO=$(echo "scale=1; $WGC_MEAN * 100 / $WGGO_MEAN" | bc)
    echo "=== COMPARISON ==="
    echo "  wg-c mean:   $WGC_MEAN Gbps"
    echo "  wg-go mean:  $WGGO_MEAN Gbps"
    echo "  Ratio:       ${RATIO}% (wg-c / wg-go)"
    echo ""

    WGC_RETRANS_SUM=$(cat "$RESULTS_DIR/wgc_retrans.txt" | grep -v "^-1$" | paste -sd+ | bc 2>/dev/null || echo 0)
    WGGO_RETRANS_SUM=$(cat "$RESULTS_DIR/wggo_retrans.txt" | grep -v "^-1$" | paste -sd+ | bc 2>/dev/null || echo 0)
    echo "  wg-c total retrans:   $WGC_RETRANS_SUM"
    echo "  wg-go total retrans:  $WGGO_RETRANS_SUM"
fi

echo ""
log "Raw results saved to: $RESULTS_DIR"
log "Done."
