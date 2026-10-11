#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Quick test script for Linux
# Usage: ./QUICKTEST.sh [asan|tsan|valgrind|all]

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

MODE="${1:-asan}"

case "$MODE" in
    asan)
        echo "🔍 Running AddressSanitizer tests..."
        rm -rf build
        CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=ON
        cmake --build build -j$(nproc)
        cd build
        ASAN_OPTIONS=detect_leaks=1:verbosity=0 ctest --output-on-failure
        echo "✅ ASAN tests passed!"
        ;;

    tsan)
        echo "🔍 Running ThreadSanitizer tests..."
        rm -rf build
        CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=OFF \
            -DCMAKE_C_FLAGS="-fsanitize=thread -g" \
            -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=thread"
        cmake --build build -j$(nproc)
        cd build
        TSAN_OPTIONS=verbosity=0 ctest --output-on-failure
        echo "✅ TSAN tests passed!"
        ;;

    valgrind)
        echo "🔍 Running Valgrind tests..."
        if ! command -v valgrind &> /dev/null; then
            echo "❌ Valgrind not found. Install: sudo apt-get install valgrind"
            exit 1
        fi
        rm -rf build
        cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=OFF
        cmake --build build -j$(nproc)
        cd build
        echo "Testing: test_handshake"
        valgrind --leak-check=full --error-exitcode=1 --quiet \
            ./tests/test_handshake
        echo "Testing: test_handshake_concurrent"
        valgrind --leak-check=full --error-exitcode=1 --quiet \
            ./tests/test_handshake_concurrent
        echo "✅ Valgrind tests passed!"
        ;;

    all)
        echo "🚀 Running ALL tests (ASAN + TSAN + Valgrind)..."
        echo ""
        $0 asan
        echo ""
        $0 tsan
        echo ""
        if command -v valgrind &> /dev/null; then
            $0 valgrind
        else
            echo "⚠️  Valgrind not available, skipping..."
        fi
        echo ""
        echo "======================================"
        echo "✅ ALL TESTS PASSED!"
        echo "======================================"
        ;;

    *)
        echo "Usage: $0 [asan|tsan|valgrind|all]"
        echo ""
        echo "  asan     - AddressSanitizer (memory errors)"
        echo "  tsan     - ThreadSanitizer (data races)"
        echo "  valgrind - Valgrind (memory leaks)"
        echo "  all      - Run all tests"
        exit 1
        ;;
esac
