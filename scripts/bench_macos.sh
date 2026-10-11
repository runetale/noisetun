#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# macOS benchmark: wg-c (and optionally wireguard-go) via utun + loopback
#
# macOS has no network namespaces or veth, so we run two WireGuard instances
# on the same host using loopback (127.0.0.1) with different UDP ports.
#
#   utun_a (10.10.0.1) ←→ UDP 127.0.0.1:51820 ←→ UDP 127.0.0.1:51821 ←→ utun_b (10.10.0.2)
#
# Usage:
#   sudo scripts/bench_macos.sh <wg-c-path> [wg-go-path] [runs] [duration]
#
# Examples:
#   sudo scripts/bench_macos.sh ./build-release/tools/wg-c                    # wg-c only, 5 runs
#   sudo scripts/bench_macos.sh ./build-release/tools/wg-c wireguard-go 5 30  # A/B comparison

set -euo pipefail

WGC="${1:?Usage: $0 <wg-c-path> [wg-go-path] [runs] [duration]}"
WG_GO="${2:-}"
RUNS="${3:-5}"
DURATION="${4:-10}"
OMIT=3

UTUN_A="utun98"
UTUN_B="utun99"
PORT_A=51820
PORT_B=51821

WG_IP_A="10.10.0.1"
WG_IP_B="10.10.0.2"

RESULTS_DIR="/tmp/bench_macos_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# ── Cleanup ──
PID_A=""
PID_B=""
IPERF_PID=""

cleanup() {
    killall -9 iperf3 2>/dev/null || true
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_A" ] && wait "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && wait "$PID_B" 2>/dev/null || true
    killall -9 wireguard-go 2>/dev/null || true
    ifconfig "$UTUN_A" destroy 2>/dev/null || true
    ifconfig "$UTUN_B" destroy 2>/dev/null || true
    PID_A=""
    PID_B=""
    IPERF_PID=""
    rm -rf "${TMPDIR_KEYS:-}" 2>/dev/null || true
}

trap cleanup EXIT

# ── Preflight ──
[ "$(id -u)" -eq 0 ] || { echo "Error: must be root (sudo)" >&2; exit 1; }
[ -x "$WGC" ] || { echo "Error: $WGC not found or not executable" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg (wireguard-tools) not found" >&2; exit 1; }
command -v iperf3 &>/dev/null || { echo "Error: iperf3 not found" >&2; exit 1; }

if [ -n "$WG_GO" ]; then
    command -v "$WG_GO" &>/dev/null || [ -x "$WG_GO" ] || {
        echo "Error: $WG_GO not found" >&2; exit 1
    }
fi

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

# ── Start wg-c pair ──
start_wgc_pair() {
    "$WGC" -f "$UTUN_A" &
    PID_A=$!
    sleep 1
    kill -0 "$PID_A" 2>/dev/null || { log "wg-c A failed to start"; return 1; }

    "$WGC" -f "$UTUN_B" &
    PID_B=$!
    sleep 1
    kill -0 "$PID_B" 2>/dev/null || { log "wg-c B failed to start"; return 1; }

    configure_peers "$UTUN_A" "$UTUN_B"
}

# ── Start wireguard-go pair ──
start_wg_go_pair() {
    WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 "$WG_GO" "$UTUN_A"
    sleep 1
    WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 "$WG_GO" "$UTUN_B"
    sleep 1

    configure_peers "$UTUN_A" "$UTUN_B"
}

# ── Configure WireGuard peers ──
configure_peers() {
    local iface_a="$1"
    local iface_b="$2"

    wg set "$iface_a" \
        private-key "$TMPDIR_KEYS/key_a" \
        listen-port "$PORT_A" \
        peer "$KEY_B_PUB" \
        endpoint "127.0.0.1:${PORT_B}" \
        allowed-ips "${WG_IP_B}/32"

    wg set "$iface_b" \
        private-key "$TMPDIR_KEYS/key_b" \
        listen-port "$PORT_B" \
        peer "$KEY_A_PUB" \
        endpoint "127.0.0.1:${PORT_A}" \
        allowed-ips "${WG_IP_A}/32"

    # Point-to-point: local addr → remote addr (peer destination)
    # This tells the kernel: packets to WG_IP_B go via iface_a, and vice versa.
    ifconfig "$iface_a" inet "${WG_IP_A}" "${WG_IP_B}" up
    ifconfig "$iface_b" inet "${WG_IP_B}" "${WG_IP_A}" up

    sleep 1

    # Verify connectivity
    ping -c 2 -W 5 "$WG_IP_B" > /dev/null 2>&1 || {
        log "WARNING: ping failed, continuing anyway..."
    }
}

# ── Stop wg-c pair ──
stop_wgc_pair() {
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_A" ] && wait "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && wait "$PID_B" 2>/dev/null || true
    PID_A=""
    PID_B=""
    # Ensure interfaces are gone
    ifconfig "$UTUN_A" destroy 2>/dev/null || true
    ifconfig "$UTUN_B" destroy 2>/dev/null || true
    sleep 2
}

# ── Stop wireguard-go pair ──
stop_wg_go_pair() {
    # wireguard-go exits when interface is deleted
    ifconfig "$UTUN_A" destroy 2>/dev/null || true
    ifconfig "$UTUN_B" destroy 2>/dev/null || true
    # Also kill any lingering wireguard-go processes
    killall -9 wireguard-go 2>/dev/null || true
    sleep 2
    # Double-check interfaces are gone
    ifconfig "$UTUN_A" destroy 2>/dev/null || true
    ifconfig "$UTUN_B" destroy 2>/dev/null || true
}

# ── Run single iperf3 test ──
# Args: $1=impl_name $2=run_number
run_single_test() {
    local impl="$1"
    local run="$2"
    local result_file="$RESULTS_DIR/${impl}_run${run}.json"

    # Start iperf3 server on B side
    iperf3 -s -B "$WG_IP_B" -D -1 2>/dev/null
    sleep 1

    # Run iperf3 client
    iperf3 -c "$WG_IP_B" -B "$WG_IP_A" \
        -t "$DURATION" --omit "$OMIT" -P 1 -J \
        > "$result_file" 2>/dev/null || true

    # Kill iperf3 server
    killall -9 iperf3 2>/dev/null || true
    sleep 0.5

    # Extract results
    if [ -f "$result_file" ] && command -v jq &>/dev/null && jq -e '.end' "$result_file" > /dev/null 2>&1; then
        local bps=$(jq '.end.sum_sent.bits_per_second' "$result_file")
        local gbps=$(echo "scale=3; $bps / 1000000000" | bc)
        local retrans=$(jq '.end.sum_sent.retransmits // 0' "$result_file")

        log "  $impl run $run: ${gbps} Gbps, retrans=$retrans"
        echo "${gbps}" >> "$RESULTS_DIR/${impl}_gbps.txt"
        echo "${retrans}" >> "$RESULTS_DIR/${impl}_retrans.txt"
    else
        log "  $impl run $run: FAILED"
        echo "0" >> "$RESULTS_DIR/${impl}_gbps.txt"
        echo "-1" >> "$RESULTS_DIR/${impl}_retrans.txt"
    fi
}

# ════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════

log "╔══════════════════════════════════════════╗"
log "║   macOS Benchmark: wg-c                 ║"
log "╠══════════════════════════════════════════╣"
log "║  wg-c:     $WGC"
[ -n "$WG_GO" ] && log "║  wg-go:    $WG_GO"
log "║  Runs:     $RUNS each"
log "║  Duration: ${DURATION}s (--omit ${OMIT}s)"
log "║  Results:  $RESULTS_DIR"
log "╚══════════════════════════════════════════╝"
echo ""

# Initialize result files
> "$RESULTS_DIR/wgc_gbps.txt"
> "$RESULTS_DIR/wgc_retrans.txt"
if [ -n "$WG_GO" ]; then
    > "$RESULTS_DIR/wggo_gbps.txt"
    > "$RESULTS_DIR/wggo_retrans.txt"
fi

for i in $(seq 1 "$RUNS"); do
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "Round $i / $RUNS"

    # Randomize execution order to eliminate cache-warmth bias
    if [ -n "$WG_GO" ]; then
        ORDER=$(( RANDOM % 2 ))
    else
        ORDER=0
    fi

    if [ "$ORDER" -eq 0 ]; then
        log "  Order: wg-c first"
    else
        log "  Order: wg-go first"
    fi
    log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    run_wgc_round() {
        log "  [wg-c] Setting up..."
        generate_keys
        start_wgc_pair
        log "  [wg-c] Running iperf3..."
        run_single_test "wgc" "$i"

        # Dump pipeline stats (SIGUSR1) before stopping
        [ -n "$PID_A" ] && kill -USR1 "$PID_A" 2>/dev/null || true
        [ -n "$PID_B" ] && kill -USR1 "$PID_B" 2>/dev/null || true
        sleep 0.5

        stop_wgc_pair
        sleep 1
    }

    run_wggo_round() {
        log "  [wg-go] Setting up..."
        generate_keys
        start_wg_go_pair
        log "  [wg-go] Running iperf3..."
        run_single_test "wggo" "$i"
        stop_wg_go_pair
        sleep 1
    }

    if [ "$ORDER" -eq 0 ]; then
        run_wgc_round
        [ -n "$WG_GO" ] && run_wggo_round
    else
        run_wggo_round
        run_wgc_round
    fi
done

# ════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════
echo ""
log "╔══════════════════════════════════════════╗"
log "║              RESULTS                     ║"
log "╚══════════════════════════════════════════╝"
echo ""

calc_stats() {
    local file="$1"
    local label="$2"
    local values=$(cat "$file" 2>/dev/null | grep -v "^0$" || true)
    if [ -z "$values" ]; then
        echo "$label: NO VALID RESULTS"
        return
    fi
    local count=$(echo "$values" | wc -l | tr -d ' ')
    local sum=$(echo "$values" | paste -sd+ | bc)
    local avg=$(echo "scale=3; $sum / $count" | bc)
    local min=$(echo "$values" | sort -n | head -1)
    local max=$(echo "$values" | sort -n | tail -1)
    local mid=$(( (count + 1) / 2 ))
    local median=$(echo "$values" | sort -n | sed -n "${mid}p")

    echo "$label:"
    echo "  Count:  $count"
    echo "  Mean:   $avg Gbps"
    echo "  Median: $median Gbps"
    echo "  Min:    $min Gbps"
    echo "  Max:    $max Gbps"
}

echo "=== wg-c ==="
calc_stats "$RESULTS_DIR/wgc_gbps.txt" "wg-c"
echo ""
echo "Retransmissions per run:"
cat "$RESULTS_DIR/wgc_retrans.txt" | nl
echo ""

if [ -n "$WG_GO" ] && [ -f "$RESULTS_DIR/wggo_gbps.txt" ]; then
    echo "=== wg-go ==="
    calc_stats "$RESULTS_DIR/wggo_gbps.txt" "wg-go"
    echo ""
    echo "Retransmissions per run:"
    cat "$RESULTS_DIR/wggo_retrans.txt" | nl
    echo ""

    # Comparison
    WGC_AVG=$(cat "$RESULTS_DIR/wgc_gbps.txt" | grep -v "^0$" | paste -sd+ | bc 2>/dev/null || echo 0)
    WGC_COUNT=$(cat "$RESULTS_DIR/wgc_gbps.txt" | grep -v "^0$" | wc -l | tr -d ' ')
    WGGO_AVG=$(cat "$RESULTS_DIR/wggo_gbps.txt" | grep -v "^0$" | paste -sd+ | bc 2>/dev/null || echo 0)
    WGGO_COUNT=$(cat "$RESULTS_DIR/wggo_gbps.txt" | grep -v "^0$" | wc -l | tr -d ' ')

    if [ "$WGC_COUNT" -gt 0 ] && [ "$WGGO_COUNT" -gt 0 ]; then
        WGC_MEAN=$(echo "scale=3; $WGC_AVG / $WGC_COUNT" | bc)
        WGGO_MEAN=$(echo "scale=3; $WGGO_AVG / $WGGO_COUNT" | bc)
        RATIO=$(echo "scale=4; $WGC_MEAN / $WGGO_MEAN * 100" | bc | sed 's/\([0-9]*\.[0-9]\).*/\1/')
        echo "=== COMPARISON ==="
        echo "  wg-c mean:   $WGC_MEAN Gbps"
        echo "  wg-go mean:  $WGGO_MEAN Gbps"
        echo "  Ratio:       ${RATIO}% (wg-c / wg-go)"
    fi
fi

echo ""
log "Raw results saved to: $RESULTS_DIR"
log "Done."
