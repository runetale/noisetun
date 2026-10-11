#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# TUNN-1: Performance comparison benchmark — wg-c vs wireguard-go.
#
# Measures:
#   1. iperf3 throughput (TCP + UDP)
#   2. Ping latency (RTT min/avg/max)
#   3. Memory usage (RSS)
#   4. Binary size
#
# Prerequisites:
#   - Root (for netns + TUN)
#   - wg (wireguard-tools)
#   - Optional: iperf3, jq, wireguard-go
#   - wg-c daemon built (build/tools/wg-c)
#
# Usage:
#   sudo ./bench/bench_comparison.sh [duration_secs]
#
# Reference: issue #69

set -euo pipefail

DURATION=${1:-10}
PING_COUNT=100

# ──────────────────────────────────────────
# Output (all display to stderr)
# ──────────────────────────────────────────
BOLD='\033[1m'
NC='\033[0m'
log()    { echo -e "$*" >&2; }
header() { log "\n${BOLD}═══ $* ═══${NC}"; }

# ──────────────────────────────────────────
# Prerequisite checks
# ──────────────────────────────────────────
HAS_IPERF3=false
HAS_WGGO=false

check_prereqs() {
    if [ "$(id -u)" -ne 0 ]; then
        log "ERROR: must run as root"; exit 1
    fi
    for cmd in wg ip; do
        command -v "$cmd" &>/dev/null || { log "ERROR: $cmd not found"; exit 1; }
    done
    command -v iperf3 &>/dev/null && command -v jq &>/dev/null && HAS_IPERF3=true \
        || log "WARNING: iperf3 or jq not found — skipping throughput benchmarks"
    command -v wireguard-go &>/dev/null && HAS_WGGO=true \
        || log "WARNING: wireguard-go not found — skipping wireguard-go benchmarks"

    # Check kernel WireGuard module
    if lsmod 2>/dev/null | grep -q '^wireguard '; then
        log "WARNING: kernel wireguard module is loaded."
        log "         For a fair userspace-vs-userspace comparison, consider:"
        log "           sudo rmmod wireguard"
    fi

    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
    WGC_BIN="${PROJECT_ROOT}/build/tools/wg-c"
    [ -x "$WGC_BIN" ] || { log "ERROR: wg-c not found at $WGC_BIN"; exit 1; }
}

# ──────────────────────────────────────────
# Key generation
# ──────────────────────────────────────────
gen_wg_keypair() {
    local priv pub
    priv=$(wg genkey)
    pub=$(echo "$priv" | wg pubkey)
    echo "$priv $pub"
}

# ──────────────────────────────────────────
# Namespace
# ──────────────────────────────────────────
NS_L="bench_left"
NS_R="bench_right"
VETH_L="veth_bl"
VETH_R="veth_br"
VETH_IP_L="192.168.253.1/24"
VETH_IP_R="192.168.253.2/24"
VETH_ADDR_L="192.168.253.1"
VETH_ADDR_R="192.168.253.2"
WG_IP_L="10.102.0.1"
WG_IP_R="10.102.0.2"
WG_CIDR_L="10.102.0.1/24"
WG_CIDR_R="10.102.0.2/24"
PORT_L=53820
PORT_R=53821

WGC_L_PID=0; WGC_R_PID=0

cleanup() {
    log "[INFO] Cleaning up..."
    for ns in "$NS_L" "$NS_R"; do
        ip netns exec "$ns" killall -q iperf3 wireguard-go 2>/dev/null || true
    done
    [ "$WGC_L_PID" -gt 0 ] && kill "$WGC_L_PID" 2>/dev/null || true
    [ "$WGC_R_PID" -gt 0 ] && kill "$WGC_R_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    ip netns del "$NS_L" 2>/dev/null || true
    ip netns del "$NS_R" 2>/dev/null || true
}
trap cleanup EXIT

setup_netns() {
    ip netns del "$NS_L" 2>/dev/null || true
    ip netns del "$NS_R" 2>/dev/null || true
    ip netns add "$NS_L"
    ip netns add "$NS_R"
    ip link add "$VETH_L" type veth peer name "$VETH_R"
    ip link set "$VETH_L" netns "$NS_L"
    ip link set "$VETH_R" netns "$NS_R"
    ip netns exec "$NS_L" ip addr add "$VETH_IP_L" dev "$VETH_L"
    ip netns exec "$NS_L" ip link set "$VETH_L" up
    ip netns exec "$NS_L" ip link set lo up
    ip netns exec "$NS_R" ip addr add "$VETH_IP_R" dev "$VETH_R"
    ip netns exec "$NS_R" ip link set "$VETH_R" up
    ip netns exec "$NS_R" ip link set lo up
}

verify_tunnel() {
    local iface=${1:-}
    log "  Verifying tunnel..."

    # Check that the interface is a TUN device (userspace), not kernel wireguard
    if [ -n "$iface" ]; then
        local iftype
        iftype=$(ip netns exec "$NS_L" ip link show "$iface" 2>/dev/null \
                 | grep -o 'type [a-z]*' | awk '{print $2}' || true)
        if [ "$iftype" = "wireguard" ]; then
            log "  WARNING: $iface is kernel wireguard, NOT userspace!"
            log "           Run: sudo rmmod wireguard"
        else
            log "  Interface $iface: userspace TUN (type: ${iftype:-none})"
        fi
    fi

    if ip netns exec "$NS_L" ping -c 3 -W 5 "$WG_IP_R" >/dev/null 2>&1; then
        log "  Tunnel OK"; return 0
    else
        log "  ERROR: Tunnel ping failed"; return 1
    fi
}

# ──────────────────────────────────────────
# wg-c tunnel
# ──────────────────────────────────────────
setup_wgc_tunnel() {
    local priv_l pub_l priv_r pub_r
    read -r priv_l pub_l <<< "$(gen_wg_keypair)"
    read -r priv_r pub_r <<< "$(gen_wg_keypair)"

    ip netns exec "$NS_L" "$WGC_BIN" wgcL0 &
    WGC_L_PID=$!; sleep 0.5

    ip netns exec "$NS_L" bash -c "echo '$priv_l' | wg set wgcL0 \
        private-key /dev/stdin listen-port $PORT_L \
        peer $pub_r endpoint ${VETH_ADDR_R}:${PORT_R} allowed-ips ${WG_IP_R}/32"
    ip netns exec "$NS_L" ip addr add "$WG_CIDR_L" dev wgcL0
    ip netns exec "$NS_L" ip link set wgcL0 up

    ip netns exec "$NS_R" "$WGC_BIN" wgcR0 &
    WGC_R_PID=$!; sleep 0.5

    ip netns exec "$NS_R" bash -c "echo '$priv_r' | wg set wgcR0 \
        private-key /dev/stdin listen-port $PORT_R \
        peer $pub_l endpoint ${VETH_ADDR_L}:${PORT_L} allowed-ips ${WG_IP_L}/32"
    ip netns exec "$NS_R" ip addr add "$WG_CIDR_R" dev wgcR0
    ip netns exec "$NS_R" ip link set wgcR0 up
    sleep 1
}

dump_wgc_stats() {
    log "  Dumping pipeline stats (SIGUSR1)..."
    [ "$WGC_L_PID" -gt 0 ] && kill -USR1 "$WGC_L_PID" 2>/dev/null || true
    [ "$WGC_R_PID" -gt 0 ] && kill -USR1 "$WGC_R_PID" 2>/dev/null || true
    sleep 0.5
}

teardown_wgc_tunnel() {
    kill "$WGC_L_PID" 2>/dev/null || true
    kill "$WGC_R_PID" 2>/dev/null || true
    wait "$WGC_L_PID" 2>/dev/null || true
    wait "$WGC_R_PID" 2>/dev/null || true
    WGC_L_PID=0; WGC_R_PID=0
}

# ──────────────────────────────────────────
# wireguard-go tunnel
# ──────────────────────────────────────────
setup_wggo_tunnel() {
    local priv_l pub_l priv_r pub_r
    read -r priv_l pub_l <<< "$(gen_wg_keypair)"
    read -r priv_r pub_r <<< "$(gen_wg_keypair)"

    ip netns exec "$NS_L" wireguard-go wggoL0; sleep 0.5
    ip netns exec "$NS_L" bash -c "echo '$priv_l' | wg set wggoL0 \
        private-key /dev/stdin listen-port $PORT_L \
        peer $pub_r endpoint ${VETH_ADDR_R}:${PORT_R} allowed-ips ${WG_IP_R}/32"
    ip netns exec "$NS_L" ip addr add "$WG_CIDR_L" dev wggoL0
    ip netns exec "$NS_L" ip link set wggoL0 up

    ip netns exec "$NS_R" wireguard-go wggoR0; sleep 0.5
    ip netns exec "$NS_R" bash -c "echo '$priv_r' | wg set wggoR0 \
        private-key /dev/stdin listen-port $PORT_R \
        peer $pub_l endpoint ${VETH_ADDR_L}:${PORT_L} allowed-ips ${WG_IP_L}/32"
    ip netns exec "$NS_R" ip addr add "$WG_CIDR_R" dev wggoR0
    ip netns exec "$NS_R" ip link set wggoR0 up
    sleep 1
}

teardown_wggo_tunnel() {
    ip netns exec "$NS_L" killall -q wireguard-go 2>/dev/null || true
    ip netns exec "$NS_R" killall -q wireguard-go 2>/dev/null || true
    sleep 0.5
}

# ──────────────────────────────────────────
# iperf3 benchmarks
#
# Server runs in NS_R, client in NS_L.
# Server is started in a subshell so we can
# reliably clean it up.
# ──────────────────────────────────────────

run_iperf3_tcp() {
    local label=$1
    header "$label — iperf3 TCP (${DURATION}s)"

    # Run server in background, redirect its output away
    ip netns exec "$NS_R" iperf3 -s -p 5201 >/dev/null 2>&1 &
    local srv=$!
    sleep 1

    # Run client (non-JSON first to see if it works, then JSON for parsing)
    local tmpf
    tmpf=$(mktemp)
    ip netns exec "$NS_L" timeout $((DURATION + 15)) \
        iperf3 -c "$WG_IP_R" -p 5201 -t "$DURATION" -J > "$tmpf" 2>&1 || true

    # Kill server AFTER client finishes
    kill "$srv" 2>/dev/null || true; wait "$srv" 2>/dev/null || true

    local mbps="0.00"
    if [ -s "$tmpf" ]; then
        mbps=$(jq -r '.end.sum_sent.bits_per_second // 0' "$tmpf" 2>/dev/null \
               | awk '{printf "%.2f", $1/1000000}') || mbps="0.00"
    fi
    rm -f "$tmpf"

    log "  Throughput: ${mbps} Mbps"
    echo "$mbps"
}

run_iperf3_udp() {
    local label=$1
    header "$label — iperf3 UDP (${DURATION}s)"

    ip netns exec "$NS_R" iperf3 -s -p 5201 >/dev/null 2>&1 &
    local srv=$!
    sleep 1

    local tmpf
    tmpf=$(mktemp)
    ip netns exec "$NS_L" timeout $((DURATION + 15)) \
        iperf3 -c "$WG_IP_R" -p 5201 -u -b 0 -t "$DURATION" -J > "$tmpf" 2>&1 || true

    kill "$srv" 2>/dev/null || true; wait "$srv" 2>/dev/null || true

    local mbps="0.00" jitter="N/A" lost="N/A"
    if [ -s "$tmpf" ]; then
        mbps=$(jq -r '.end.sum.bits_per_second // 0' "$tmpf" 2>/dev/null \
               | awk '{printf "%.2f", $1/1000000}') || mbps="0.00"
        jitter=$(jq -r '.end.sum.jitter_ms // "N/A"' "$tmpf" 2>/dev/null) || jitter="N/A"
        lost=$(jq -r '.end.sum.lost_percent // "N/A"' "$tmpf" 2>/dev/null) || lost="N/A"
    fi
    rm -f "$tmpf"

    log "  Throughput: ${mbps} Mbps"
    log "  Jitter:     ${jitter} ms"
    log "  Loss:       ${lost}%"
    echo "$mbps"
}

# ──────────────────────────────────────────
# Ping latency
# ──────────────────────────────────────────
run_ping_latency() {
    local label=$1
    header "$label — Ping latency (${PING_COUNT} packets)"

    local output
    output=$(ip netns exec "$NS_L" ping -c "$PING_COUNT" -W 3 -q "$WG_IP_R" 2>&1) || true

    local rtt_line loss_line
    rtt_line=$(echo "$output" | grep 'rtt\|round-trip' || true)
    loss_line=$(echo "$output" | grep 'packet loss' || true)
    [ -n "$rtt_line" ] && log "  $rtt_line" || log "  (no latency data)"
    [ -n "$loss_line" ] && log "  $loss_line"

    # Extract avg RTT
    local avg
    avg=$(echo "$rtt_line" | awk -F'/' '{print $5}' || true)
    [ -z "$avg" ] && avg="N/A"
    echo "$avg"
}

# ──────────────────────────────────────────
# Memory
# ──────────────────────────────────────────
measure_memory() {
    local pid=$1
    if [ -f "/proc/$pid/status" ]; then
        local rss
        rss=$(awk '/VmRSS/{print $2}' "/proc/$pid/status")
        log "  Memory RSS: ${rss} KB"
        echo "$rss"
    else
        log "  Memory: (process not found)"
        echo "N/A"
    fi
}

# ──────────────────────────────────────────
# Main
# ──────────────────────────────────────────
main() {
    check_prereqs

    log ""
    log "╔═══════════════════════════════════════════════════╗"
    log "║   noisetun vs wireguard-go Benchmark Suite       ║"
    log "╠═══════════════════════════════════════════════════╣"
    log "║  Duration:    ${DURATION}s per iperf3 test                ║"
    log "║  Ping count:  ${PING_COUNT} packets                       ║"
    log "╚═══════════════════════════════════════════════════╝"

    # Binary size
    header "Binary size"
    local wgc_size_kb="N/A" wggo_size_kb="N/A"
    if [ -x "$WGC_BIN" ]; then
        local b; b=$(stat -c%s "$WGC_BIN" 2>/dev/null || stat -f%z "$WGC_BIN")
        wgc_size_kb=$((b / 1024))
        log "  wg-c:          ${wgc_size_kb} KB"
    fi
    local wggo_bin; wggo_bin=$(command -v wireguard-go 2>/dev/null || true)
    if [ -n "$wggo_bin" ]; then
        local b; b=$(stat -c%s "$wggo_bin" 2>/dev/null || stat -f%z "$wggo_bin")
        wggo_size_kb=$((b / 1024))
        log "  wireguard-go:  ${wggo_size_kb} KB"
    fi

    local wgc_tcp="N/A" wgc_udp="N/A" wgc_ping="N/A" wgc_mem="N/A"
    local wggo_tcp="N/A" wggo_udp="N/A" wggo_ping="N/A" wggo_mem="N/A"

    # ── wg-c ──
    header "Setting up wg-c tunnel"
    setup_netns
    setup_wgc_tunnel

    if verify_tunnel wgcL0; then
        [ "$HAS_IPERF3" = true ] && wgc_tcp=$(run_iperf3_tcp "wg-c")
        [ "$HAS_IPERF3" = true ] && wgc_udp=$(run_iperf3_udp "wg-c")
        wgc_ping=$(run_ping_latency "wg-c")
        [ "$WGC_L_PID" -gt 0 ] && wgc_mem=$(measure_memory "$WGC_L_PID")
        dump_wgc_stats
    else
        log "  Skipping wg-c benchmarks"
    fi
    teardown_wgc_tunnel

    # ── wireguard-go ──
    if [ "$HAS_WGGO" = true ]; then
        header "Setting up wireguard-go tunnel"
        setup_netns
        setup_wggo_tunnel

        if verify_tunnel wggoL0; then
            [ "$HAS_IPERF3" = true ] && wggo_tcp=$(run_iperf3_tcp "wireguard-go")
            [ "$HAS_IPERF3" = true ] && wggo_udp=$(run_iperf3_udp "wireguard-go")
            wggo_ping=$(run_ping_latency "wireguard-go")
            local pid
            pid=$(ip netns exec "$NS_L" pgrep -x wireguard-go 2>/dev/null | head -1 || true)
            [ -n "$pid" ] && wggo_mem=$(measure_memory "$pid")
        else
            log "  Skipping wireguard-go benchmarks"
        fi
        teardown_wggo_tunnel
    fi

    # ── Summary ──
    header "Summary"
    log ""
    log "  ┌──────────────────────┬────────────────┬────────────────┐"
    log "  │ Metric               │ wg-c           │ wireguard-go   │"
    log "  ├──────────────────────┼────────────────┼────────────────┤"
    printf "  │ Binary size (KB)     │ %14s │ %14s │\n" "$wgc_size_kb" "$wggo_size_kb" >&2
    printf "  │ TCP throughput (Mbps)│ %14s │ %14s │\n" "$wgc_tcp" "$wggo_tcp" >&2
    printf "  │ UDP throughput (Mbps)│ %14s │ %14s │\n" "$wgc_udp" "$wggo_udp" >&2
    printf "  │ Ping avg RTT (ms)   │ %14s │ %14s │\n" "$wgc_ping" "$wggo_ping" >&2
    printf "  │ Memory RSS (KB)     │ %14s │ %14s │\n" "$wgc_mem" "$wggo_mem" >&2
    log "  └──────────────────────┴────────────────┴────────────────┘"
    log ""
}

main "$@"
