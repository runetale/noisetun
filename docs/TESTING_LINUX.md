# Linux Testing Guide for noisetun

This guide describes how to test noisetun thoroughly on Linux.

## Prerequisites

### Installing the required packages

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libsodium-dev \
    valgrind \
    clang \
    git
```

#### Fedora/RHEL/CentOS
```bash
sudo dnf install -y \
    gcc \
    gcc-c++ \
    cmake \
    pkg-config \
    libsodium-devel \
    valgrind \
    clang \
    git
```

#### Arch Linux
```bash
sudo pacman -S --needed \
    base-devel \
    cmake \
    pkg-config \
    libsodium \
    valgrind \
    clang \
    git
```

---

## Test procedures

### 1. Normal build & test

```bash
# Go to the project root
cd /path/to/noisetun

# Build
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Run all tests
cd build
ctest --output-on-failure
```

**Expected result:**
```
100% tests passed, 0 tests failed out of N
```

---

### 2. AddressSanitizer (memory safety)

Detects memory leaks, buffer overflows, use-after-free and similar errors.

```bash
# ASAN build
rm -rf build
CC=clang cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWG_ASAN=ON
cmake --build build -j$(nproc)

# Run the tests
cd build
ctest --output-on-failure

# Run individual tests (verbose log)
ASAN_OPTIONS=verbosity=1:detect_leaks=1 ./tests/test_handshake
ASAN_OPTIONS=verbosity=1:detect_leaks=1 ./tests/test_handshake_concurrent
```

**Expected result:**
```
=================================================================
==XXXXX==ERROR: LeakSanitizer: ... must not appear
```

**ASAN options (detailed):**
```bash
# More thorough detection
ASAN_OPTIONS='verbosity=1:detect_leaks=1:check_initialization_order=1:detect_stack_use_after_return=1' \
    ./tests/test_handshake_concurrent
```

---

### 3. ThreadSanitizer (thread safety)

Detects data races and deadlocks.

```bash
# TSAN build (cannot be combined with ASAN)
rm -rf build
CC=clang cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWG_ASAN=OFF \
    -DCMAKE_C_FLAGS="-fsanitize=thread -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=thread"
cmake --build build -j$(nproc)

# Run the tests
cd build
ctest --output-on-failure

# Run the concurrency test in verbose mode
TSAN_OPTIONS='verbosity=1:history_size=7' \
    ./tests/test_handshake_concurrent
```

**Expected result:**
```
WARNING: ThreadSanitizer: data race ... must not appear
WARNING: ThreadSanitizer: lock-order-inversion ... must not appear
```

**TSAN options (detailed):**
```bash
# Stronger deadlock detection
TSAN_OPTIONS='verbosity=1:history_size=7:detect_deadlocks=1:second_deadlock_stack=1' \
    ./tests/test_handshake_concurrent
```

---

### 4. Valgrind (detailed memory error checks)

**Valgrind does the strictest memory checking, but it runs slowly.**

#### 4.1 Memory leak check
```bash
# Normal build (no optimization)
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=OFF
cmake --build build -j$(nproc)

cd build

# Check all tests for memory leaks
valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --verbose \
    ./tests/test_handshake

valgrind \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --verbose \
    ./tests/test_handshake_concurrent
```

**Expected result:**
```
==XXXXX== LEAK SUMMARY:
==XXXXX==    definitely lost: 0 bytes in 0 blocks
==XXXXX==    indirectly lost: 0 bytes in 0 blocks
==XXXXX==      possibly lost: 0 bytes in 0 blocks
==XXXXX==    still reachable: ... bytes in ... blocks
==XXXXX==         suppressed: 0 bytes in 0 blocks
```

**Note**: `still reachable` is memory that is still referenced when the program exits (libsodium, for example). It is normally not a problem.

#### 4.2 Thread error detection (Helgrind)
```bash
valgrind \
    --tool=helgrind \
    --verbose \
    ./tests/test_handshake_concurrent
```

**Expected result:**
```
==XXXXX== ERROR SUMMARY: 0 errors from 0 contexts
```

#### 4.3 Data race detection (DRD)
```bash
valgrind \
    --tool=drd \
    --check-stack-var=yes \
    --verbose \
    ./tests/test_handshake_concurrent
```

---

### 5. UndefinedBehaviorSanitizer (UB detection)

```bash
# UBSAN build
rm -rf build
CC=clang cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWG_ASAN=OFF \
    -DCMAKE_C_FLAGS="-fsanitize=undefined -fno-sanitize-recover=all -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=undefined"
cmake --build build -j$(nproc)

# Run the tests
cd build
ctest --output-on-failure
```

**Detected problems:**
- Integer overflow
- NULL dereference
- Misaligned access
- UB in shift operations

---

### 6. MemorySanitizer (uninitialized memory detection)

**Note**: MemorySanitizer requires rebuilding every dependency, including libsodium, so it is not normally used.

```bash
# MSAN build (advanced)
rm -rf build
CC=clang cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DWG_ASAN=OFF \
    -DCMAKE_C_FLAGS="-fsanitize=memory -fsanitize-memory-track-origins -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=memory"
cmake --build build -j$(nproc)

cd build
ctest --output-on-failure
```

---

### 7. Script that runs all sanitizers

Create a helper script:

```bash
cat > run_all_tests.sh << 'EOF'
#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

echo "=================================================="
echo "noisetun Comprehensive Test Suite"
echo "=================================================="

# 1. Normal build
echo ""
echo "[1/5] Normal Build & Test..."
rm -rf build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
(cd build && ctest --output-on-failure)

# 2. AddressSanitizer
echo ""
echo "[2/5] AddressSanitizer..."
rm -rf build
CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=ON
cmake --build build -j$(nproc)
(cd build && ASAN_OPTIONS=detect_leaks=1 ctest --output-on-failure)

# 3. ThreadSanitizer
echo ""
echo "[3/5] ThreadSanitizer..."
rm -rf build
CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=OFF \
    -DCMAKE_C_FLAGS="-fsanitize=thread -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=thread"
cmake --build build -j$(nproc)
(cd build && ctest --output-on-failure)

# 4. UndefinedBehaviorSanitizer
echo ""
echo "[4/5] UndefinedBehaviorSanitizer..."
rm -rf build
CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=OFF \
    -DCMAKE_C_FLAGS="-fsanitize=undefined -fno-sanitize-recover=all -g" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=undefined"
cmake --build build -j$(nproc)
(cd build && ctest --output-on-failure)

# 5. Valgrind (if available)
echo ""
echo "[5/5] Valgrind..."
if command -v valgrind &> /dev/null; then
    rm -rf build
    cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=OFF
    cmake --build build -j$(nproc)
    cd build
    valgrind --leak-check=full --error-exitcode=1 ./tests/test_handshake
    valgrind --leak-check=full --error-exitcode=1 ./tests/test_handshake_concurrent
    cd ..
else
    echo "  Valgrind not found, skipping..."
fi

echo ""
echo "=================================================="
echo "All tests passed! ✅"
echo "=================================================="
EOF

chmod +x run_all_tests.sh
```

**Run:**
```bash
./run_all_tests.sh
```

---

### 8. CI/CD integration (GitHub Actions example)

`.github/workflows/test.yml`:
```yaml
name: Tests

on: [push, pull_request]

jobs:
  test-linux:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        sanitizer: [none, asan, tsan, ubsan]
    steps:
      - uses: actions/checkout@v3
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y cmake libsodium-dev valgrind clang
      
      - name: Test with ${{ matrix.sanitizer }}
        run: |
          case "${{ matrix.sanitizer }}" in
            none)
              cmake -B build -DCMAKE_BUILD_TYPE=Release
              ;;
            asan)
              CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=ON
              ;;
            tsan)
              CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=OFF \
                -DCMAKE_C_FLAGS="-fsanitize=thread -g" \
                -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=thread"
              ;;
            ubsan)
              CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -DWG_ASAN=OFF \
                -DCMAKE_C_FLAGS="-fsanitize=undefined -g" \
                -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=undefined"
              ;;
          esac
          cmake --build build -j$(nproc)
          cd build && ctest --output-on-failure
      
      - name: Valgrind (only for 'none' matrix)
        if: matrix.sanitizer == 'none'
        run: |
          cd build
          valgrind --leak-check=full --error-exitcode=1 ./tests/test_handshake
```

---

## Troubleshooting

### ASAN reports "LeakSanitizer: detected memory leaks"
```bash
# Can be suppressed when it comes from libsodium initialization
export ASAN_OPTIONS=detect_leaks=0
```

### TSAN prints a large number of warnings
```bash
# Disable the stricter checks
export TSAN_OPTIONS=suppressions=tsan.supp

# Create the tsan.supp file
cat > tsan.supp << EOF
# libsodium internal locks
race:sodium_init
EOF
```

### Valgrind is too slow
```bash
# Reduce the number of threads in the concurrency test
# Change NUM_THREADS in tests/test_handshake_concurrent.c to 2
```

---

## Recommended test flow

**During development (fast):**
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build && cd build && ctest
```

**Before committing (medium):**
```bash
./run_all_tests.sh  # ASAN + TSAN + UBSAN
```

**Before a release (slow, complete):**
```bash
./run_all_tests.sh  # all sanitizers + Valgrind
```

---

## References

- [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [ThreadSanitizer](https://github.com/google/sanitizers/wiki/ThreadSanitizerCppManual)
- [Valgrind Manual](https://valgrind.org/docs/manual/manual.html)
- [WireGuard Specification](https://www.wireguard.com/papers/wireguard.pdf)
