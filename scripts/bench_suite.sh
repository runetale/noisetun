#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Benchmark suite — runs all micro-benchmarks and reports results.
# Usage: bench_suite.sh [duration_secs]
#   duration_secs: per-benchmark duration (default: 5)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/../build-release}"

DURATION="${1:-5}"

if [[ ! -d "$BUILD_DIR/bench" ]]; then
    echo "ERROR: bench binaries not found at $BUILD_DIR/bench"
    echo "Build with: cmake -B build-release -DCMAKE_BUILD_TYPE=Release && cmake --build build-release"
    exit 1
fi

echo "════════════════════════════════════════════════════════════"
echo "  wg-c Benchmark Suite (duration=${DURATION}s per bench)"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Platform: $(uname -m) / $(uname -s) $(uname -r)"
echo "CPU:      $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
echo "Date:     $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

# ── 1. Crypto (encrypt/decrypt throughput) ──
echo "── [1/3] ChaCha20-Poly1305 AEAD ──"
if [[ -x "$BUILD_DIR/bench/bench_crypto" ]]; then
    "$BUILD_DIR/bench/bench_crypto"
else
    echo "  SKIP: bench_crypto not built"
fi
echo ""

# ── 2. Handshake ──
echo "── [2/3] Noise IKpsk2 Handshake ──"
if [[ -x "$BUILD_DIR/bench/bench_handshake" ]]; then
    "$BUILD_DIR/bench/bench_handshake" "$DURATION"
else
    echo "  SKIP: bench_handshake not built"
fi
echo ""

# ── 3. Pipeline throughput ──
echo "── [3/3] Full Pipeline Throughput ──"
if [[ -x "$BUILD_DIR/bench/bench_throughput" ]]; then
    # No size argument: the default payload (1392) makes a 1420-byte
    # packet, the MTU. The argument is the payload, and 1420 did not fit.
    "$BUILD_DIR/bench/bench_throughput" "$DURATION" || echo "  ERROR: bench_throughput failed (exit $?)"
else
    echo "  SKIP: bench_throughput not built"
fi
echo ""

echo "════════════════════════════════════════════════════════════"
echo "  Done"
echo "════════════════════════════════════════════════════════════"
