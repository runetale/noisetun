# Testing Documentation Overview

This directory contains documentation on testing noisetun.

## Documents

### `TESTING_LINUX.md`
**Comprehensive testing guide for Linux (detailed version)**

Contents:
- How to install the dependencies (Ubuntu/Debian/Fedora/Arch)
- How to use AddressSanitizer (ASAN)
- How to use ThreadSanitizer (TSAN)
- How to use Valgrind (memory leak detection)
- Helgrind/DRD (thread error detection)
- UndefinedBehaviorSanitizer (UBSAN)
- CI/CD integration example (GitHub Actions)
- Troubleshooting

**Audience**: people testing on Linux for the first time, and people who need detailed explanations

---

## Quick start

### 1. Testing on Linux for the first time

```bash
# 1. Install the dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libsodium-dev valgrind clang
```

---

## Test list

The tests are registered in `tests/CMakeLists.txt`; `ctest -N` in the build
directory lists them. They cover the crypto primitives and RFC vectors, the
Noise handshake and cookies, replay protection, AllowedIPs, the index table,
peers, timers, the queues and worker threads, and full devices exchanging
packets. `test_tun_linux` and some device tests need root. On Windows only
the tests that need no POSIX headers are built (10 of them, run in CI).

---

## Recommended workflow

### Day-to-day development
```bash
# Normal build & test (fast)
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
cd build && ctest
```

---

## If you find a problem

### AddressSanitizer errors
```bash
# Enable verbose logging
cd build
ASAN_OPTIONS=verbosity=1:detect_leaks=1 ./tests/test_handshake
```

Example errors:
- `heap-use-after-free` → access after the memory was freed
- `heap-buffer-overflow` → buffer overflow
- `memory leak` → memory leak

### ThreadSanitizer errors
```bash
# Enable verbose logging
cd build
TSAN_OPTIONS=verbosity=1:history_size=7 ./tests/test_handshake_concurrent
```

Example errors:
- `data race` → data race
- `lock-order-inversion` → possible deadlock

### Valgrind errors
```bash
# More detailed information
cd build
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
    ./tests/test_handshake
```

---

## References

- [AddressSanitizer Wiki](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [ThreadSanitizer Wiki](https://github.com/google/sanitizers/wiki/ThreadSanitizerCppManual)
- [Valgrind Quick Start](https://valgrind.org/docs/manual/quick-start.html)
- [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)

---

## FAQ

**Q: Can I run the tests on macOS?**
A: Yes, but Valgrind is not available (ASAN/TSAN only).

**Q: Can I run the tests on Windows?**
A: For now, running them under WSL2 (a Linux environment) is recommended.

**Q: I want to integrate this into CI/CD**
A: `TESTING_LINUX.md` has a GitHub Actions example.

**Q: Valgrind is too slow**
A: Use ASAN/TSAN during development, and run Valgrind only before a release.

---

**Last updated**: 2026-09-26
**Maintainer**: Runetale Inc.
