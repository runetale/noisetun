#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# macOS profiling: identify wg-c bottlenecks via dtruss + sample.
#
# Runs wg-c tunnel, captures:
#   1. Raw loopback baseline (iperf3 without WireGuard)
#   2. Syscall breakdown (dtruss -c)
#   3. CPU profile (sample)
#
# Usage:
#   sudo scripts/profile_macos.sh <wg-c-path>
#
# Example:
#   sudo scripts/profile_macos.sh ./build-release/tools/wg-c

set -euo pipefail

WGC="${1:?Usage: $0 <wg-c-path>}"
DURATION=10
OMIT=3

UTUN_A="utun98"
UTUN_B="utun99"
PORT_A=51820
PORT_B=51821
WG_IP_A="10.10.0.1"
WG_IP_B="10.10.0.2"

RESULTS_DIR="/tmp/profile_macos_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"

log() { echo "[$(date +%H:%M:%S)] $*"; }

PID_A=""
PID_B=""

cleanup() {
    killall -9 iperf3 2>/dev/null || true
    [ -n "$PID_A" ] && kill "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && kill "$PID_B" 2>/dev/null || true
    [ -n "$PID_A" ] && wait "$PID_A" 2>/dev/null || true
    [ -n "$PID_B" ] && wait "$PID_B" 2>/dev/null || true
    ifconfig "$UTUN_A" destroy 2>/dev/null || true
    ifconfig "$UTUN_B" destroy 2>/dev/null || true
    rm -rf "${TMPDIR_KEYS:-}" 2>/dev/null || true
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "Error: must be root (sudo)" >&2; exit 1; }
[ -x "$WGC" ] || { echo "Error: $WGC not found or not executable" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg (wireguard-tools) not found" >&2; exit 1; }
command -v iperf3 &>/dev/null || { echo "Error: iperf3 not found" >&2; exit 1; }

# ── Generate WireGuard keys ──
TMPDIR_KEYS=$(mktemp -d)
KEY_A_PRIV=$(wg genkey)
KEY_A_PUB=$(echo "$KEY_A_PRIV" | wg pubkey)
KEY_B_PRIV=$(wg genkey)
KEY_B_PUB=$(echo "$KEY_B_PRIV" | wg pubkey)
echo "$KEY_A_PRIV" > "$TMPDIR_KEYS/key_a"
echo "$KEY_B_PRIV" > "$TMPDIR_KEYS/key_b"
chmod 600 "$TMPDIR_KEYS/key_a" "$TMPDIR_KEYS/key_b"

log "╔══════════════════════════════════════════════╗"
log "║   macOS Profiling: wg-c bottleneck analysis  ║"
log "╠══════════════════════════════════════════════╣"
log "║  wg-c:     $WGC"
log "║  Duration: ${DURATION}s"
log "║  Results:  $RESULTS_DIR"
log "╚══════════════════════════════════════════════╝"
echo ""

# ════════════════════════════════════════════
# TEST 1: Raw loopback baseline (no WireGuard)
# ════════════════════════════════════════════
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "TEST 1: Raw loopback baseline (iperf3 127.0.0.1)"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

iperf3 -s -B 127.0.0.1 -D -1 2>/dev/null
sleep 1
iperf3 -c 127.0.0.1 -t "$DURATION" --omit "$OMIT" -J \
    > "$RESULTS_DIR/baseline_loopback.json" 2>/dev/null || true
killall -9 iperf3 2>/dev/null || true
sleep 0.5

if command -v jq &>/dev/null && [ -f "$RESULTS_DIR/baseline_loopback.json" ]; then
    BPS=$(jq '.end.sum_sent.bits_per_second // 0' "$RESULTS_DIR/baseline_loopback.json")
    GBPS=$(echo "scale=2; $BPS / 1000000000" | bc)
    log "  Loopback (no WG): ${GBPS} Gbps"
fi
echo ""

# ════════════════════════════════════════════
# TEST 2: WireGuard tunnel setup
# ════════════════════════════════════════════
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "TEST 2: Setting up wg-c tunnel..."
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

"$WGC" -f "$UTUN_A" &
PID_A=$!
sleep 1
"$WGC" -f "$UTUN_B" &
PID_B=$!
sleep 1

wg set "$UTUN_A" \
    private-key "$TMPDIR_KEYS/key_a" \
    listen-port "$PORT_A" \
    peer "$KEY_B_PUB" \
    endpoint "127.0.0.1:${PORT_B}" \
    allowed-ips "${WG_IP_B}/32"

wg set "$UTUN_B" \
    private-key "$TMPDIR_KEYS/key_b" \
    listen-port "$PORT_B" \
    peer "$KEY_A_PUB" \
    endpoint "127.0.0.1:${PORT_A}" \
    allowed-ips "${WG_IP_A}/32"

ifconfig "$UTUN_A" inet "${WG_IP_A}" "${WG_IP_B}" up
ifconfig "$UTUN_B" inet "${WG_IP_B}" "${WG_IP_A}" up
sleep 1

ping -c 2 -W 5 "$WG_IP_B" > /dev/null 2>&1 || log "WARNING: ping failed"
log "  wg-c tunnel up. PID_A=$PID_A PID_B=$PID_B"
echo ""

# ════════════════════════════════════════════
# TEST 3: iperf3 through WireGuard (baseline)
# ════════════════════════════════════════════
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "TEST 3: iperf3 through WireGuard tunnel"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

iperf3 -s -B "$WG_IP_B" -D -1 2>/dev/null
sleep 1
iperf3 -c "$WG_IP_B" -B "$WG_IP_A" \
    -t "$DURATION" --omit "$OMIT" -J \
    > "$RESULTS_DIR/wgc_baseline.json" 2>/dev/null || true
killall -9 iperf3 2>/dev/null || true
sleep 0.5

if command -v jq &>/dev/null && [ -f "$RESULTS_DIR/wgc_baseline.json" ]; then
    BPS=$(jq '.end.sum_sent.bits_per_second // 0' "$RESULTS_DIR/wgc_baseline.json")
    GBPS=$(echo "scale=3; $BPS / 1000000000" | bc)
    log "  WireGuard tunnel: ${GBPS} Gbps"
fi
echo ""

# ════════════════════════════════════════════
# TEST 4: dtruss syscall profiling (sender side = PID_A)
# ════════════════════════════════════════════
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "TEST 4: dtruss syscall profile (PID_A=$PID_A, ${DURATION}s)"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Start dtruss in background on sender
dtruss -c -p "$PID_A" 2>"$RESULTS_DIR/dtruss_sender.txt" &
DTRUSS_PID=$!

# Start iperf3 test
iperf3 -s -B "$WG_IP_B" -D -1 2>/dev/null
sleep 1
iperf3 -c "$WG_IP_B" -B "$WG_IP_A" \
    -t "$DURATION" --omit "$OMIT" \
    > "$RESULTS_DIR/dtruss_iperf.txt" 2>&1 || true
killall -9 iperf3 2>/dev/null || true
sleep 1

# Stop dtruss
kill "$DTRUSS_PID" 2>/dev/null || true
wait "$DTRUSS_PID" 2>/dev/null || true
sleep 1

log "  dtruss output saved to $RESULTS_DIR/dtruss_sender.txt"
echo ""
echo "=== Syscall Summary (sender) ==="
cat "$RESULTS_DIR/dtruss_sender.txt" 2>/dev/null | tail -30
echo ""

# ════════════════════════════════════════════
# TEST 5: dtruss on receiver side (PID_B)
# ════════════════════════════════════════════
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "TEST 5: dtruss syscall profile (PID_B=$PID_B, ${DURATION}s)"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

dtruss -c -p "$PID_B" 2>"$RESULTS_DIR/dtruss_receiver.txt" &
DTRUSS_PID=$!

iperf3 -s -B "$WG_IP_B" -D -1 2>/dev/null
sleep 1
iperf3 -c "$WG_IP_B" -B "$WG_IP_A" \
    -t "$DURATION" --omit "$OMIT" \
    > /dev/null 2>&1 || true
killall -9 iperf3 2>/dev/null || true
sleep 1

kill "$DTRUSS_PID" 2>/dev/null || true
wait "$DTRUSS_PID" 2>/dev/null || true
sleep 1

log "  dtruss output saved to $RESULTS_DIR/dtruss_receiver.txt"
echo ""
echo "=== Syscall Summary (receiver) ==="
cat "$RESULTS_DIR/dtruss_receiver.txt" 2>/dev/null | tail -30
echo ""

# ════════════════════════════════════════════
# TEST 6: CPU sample profile
# ════════════════════════════════════════════
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "TEST 6: CPU sample profile (both PIDs, ${DURATION}s)"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Start iperf3
iperf3 -s -B "$WG_IP_B" -D -1 2>/dev/null
sleep 1
iperf3 -c "$WG_IP_B" -B "$WG_IP_A" \
    -t "$DURATION" --omit "$OMIT" \
    > /dev/null 2>&1 &
IPERF_CLIENT=$!

# Sample both wg-c processes for 5 seconds during the test
sleep 2
sample "$PID_A" 5 -f "$RESULTS_DIR/sample_sender.txt" 2>/dev/null || true
sample "$PID_B" 5 -f "$RESULTS_DIR/sample_receiver.txt" 2>/dev/null || true

wait "$IPERF_CLIENT" 2>/dev/null || true
killall -9 iperf3 2>/dev/null || true
sleep 0.5

log "  CPU sample saved to $RESULTS_DIR/sample_sender.txt"
log "  CPU sample saved to $RESULTS_DIR/sample_receiver.txt"
echo ""

# Show top functions from sample
for side in sender receiver; do
    echo "=== Top functions ($side) ==="
    if [ -f "$RESULTS_DIR/sample_${side}.txt" ]; then
        # Extract the heaviest call tree lines
        grep -E '^\s+[0-9]+ ' "$RESULTS_DIR/sample_${side}.txt" 2>/dev/null \
            | sort -t' ' -k1 -rn | head -20
    else
        echo "  (no sample data)"
    fi
    echo ""
done

# ════════════════════════════════════════════
# TEST 7: Dump pipeline stats via SIGUSR1
# ════════════════════════════════════════════
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "TEST 7: Pipeline stats (SIGUSR1)"
log "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

kill -USR1 "$PID_A" 2>/dev/null || true
kill -USR1 "$PID_B" 2>/dev/null || true
sleep 1

# ════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════
echo ""
log "╔══════════════════════════════════════════════╗"
log "║              PROFILING COMPLETE               ║"
log "╚══════════════════════════════════════════════╝"
echo ""
log "Results directory: $RESULTS_DIR"
log "Files:"
ls -la "$RESULTS_DIR/"
echo ""
log "Key files to examine:"
log "  dtruss_sender.txt   — syscall counts & time (sender)"
log "  dtruss_receiver.txt — syscall counts & time (receiver)"
log "  sample_sender.txt   — CPU hot functions (sender)"
log "  sample_receiver.txt — CPU hot functions (receiver)"
log "Done."
