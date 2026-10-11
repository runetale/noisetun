#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Resource comparison: wg-c vs wireguard-go
#
# Compares binary size and memory usage (RSS) of both implementations.
#
# Requirements: root (for daemon startup), wg-c, wireguard-go (optional)
# Usage: sudo scripts/bench_resources.sh [path-to-wg-c]

set -euo pipefail

WGC="${1:-./build/tools/wg-c}"
WG_IFACE="wg0"
NS="wgres_ns"

cleanup() {
    [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
}

trap cleanup EXIT

log() { echo "==> $*"; }

[ "$(id -u)" -eq 0 ] || { echo "Error: must be root" >&2; exit 1; }
[ -x "$WGC" ] || { echo "Error: $WGC not found" >&2; exit 1; }

HAS_WG_GO=true
command -v wireguard-go &>/dev/null || HAS_WG_GO=false

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║    Resource Comparison                     ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

# ──────────────────────────────────────
# Binary size
# ──────────────────────────────────────

WGC_SIZE=$(stat --printf="%s" "$WGC" 2>/dev/null || stat -f "%z" "$WGC" 2>/dev/null)
WGC_SIZE_KB=$((WGC_SIZE / 1024))

if $HAS_WG_GO; then
    WG_GO_PATH=$(which wireguard-go)
    WG_GO_SIZE=$(stat --printf="%s" "$WG_GO_PATH" 2>/dev/null || stat -f "%z" "$WG_GO_PATH" 2>/dev/null)
    WG_GO_SIZE_KB=$((WG_GO_SIZE / 1024))
fi

echo "  Binary Size:"
echo "    wg-c:          ${WGC_SIZE_KB} KB ($WGC)"
if $HAS_WG_GO; then
    echo "    wireguard-go:  ${WG_GO_SIZE_KB} KB ($WG_GO_PATH)"
    if [ "$WG_GO_SIZE_KB" -gt 0 ]; then
        RATIO=$(echo "scale=1; $WGC_SIZE_KB * 100 / $WG_GO_SIZE_KB" | bc 2>/dev/null || echo "N/A")
        echo "    wg-c is ${RATIO}% of wireguard-go size"
    fi
fi
echo ""

# ──────────────────────────────────────
# RSS memory: wg-c idle
# ──────────────────────────────────────

measure_rss() {
    local label="$1"
    local daemon_cmd="$2"

    ip netns add "$NS" 2>/dev/null || true
    ip netns exec "$NS" ip link set lo up

    ip netns exec "$NS" env WG_PROCESS_FOREGROUND=1 $daemon_cmd &
    PID=$!
    sleep 3

    if kill -0 "$PID" 2>/dev/null; then
        local rss
        rss=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
        echo "    $label:  ${rss} KB (pid=$PID)"
    else
        echo "    $label:  FAILED TO START"
    fi

    kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
    PID=""
    ip netns del "$NS" 2>/dev/null || true
    sleep 1
}

echo "  Memory Usage (RSS, idle):"
measure_rss "wg-c" "$WGC -f $WG_IFACE"

if $HAS_WG_GO; then
    measure_rss "wireguard-go" "wireguard-go -f $WG_IFACE"
fi

echo ""
echo "Done."
