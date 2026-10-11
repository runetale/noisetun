# Convenience Makefile for noisetun
#
# Usage:
#   make              # build + test (run inside `nix develop` or with deps installed)
#   make test-tun     # run platform TUN test (requires root)
#   make debug        # Debug build with ASan/UBSan
#   make clean        # remove build directory
#   make nix          # one-shot build+test via nix (no devshell needed)

BUILD_DIR  := build
BUILD_TYPE ?= Release
JOBS       ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

CMAKE_FLAGS := \
	-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
	-DWG_BUILD_TESTS=ON \
	-DWG_ASAN=OFF

.PHONY: all build test test-tun test-uapi test-interop bench bench-internal debug clean nix

## Default: build + test
all: build test

## CMake configure + build
build:
	@cmake -B $(BUILD_DIR) $(CMAKE_FLAGS)
	cmake --build $(BUILD_DIR) -j$(JOBS)

## Run all tests
test: build
	cd $(BUILD_DIR) && ctest --output-on-failure

## Run platform TUN test (requires root)
test-tun: build
ifeq ($(shell uname -s),Darwin)
	sudo $(BUILD_DIR)/tests/test_tun_darwin
else
	sudo $(BUILD_DIR)/tests/test_tun_linux
endif

## Run UAPI wg-compat test (requires root + wg tool)
test-uapi: build
	sudo $(BUILD_DIR)/tests/test_uapi_wg_compat

## Run interop test (requires root + wireguard-go + wg tool)
test-interop: build
	sudo $(BUILD_DIR)/tests/test_interop_wg_go

## Run performance comparison benchmark (requires root + iperf3 + wireguard-go)
bench: build
	@cmake -B $(BUILD_DIR) $(CMAKE_FLAGS) -DWG_BUILD_BENCH=ON
	cmake --build $(BUILD_DIR) -j$(JOBS)
	sudo bash bench/bench_comparison.sh

## Run in-memory throughput + latency benchmarks (no root needed)
bench-internal: build
	@cmake -B $(BUILD_DIR) $(CMAKE_FLAGS) -DWG_BUILD_BENCH=ON
	cmake --build $(BUILD_DIR) -j$(JOBS)
	$(BUILD_DIR)/bench/bench_throughput
	$(BUILD_DIR)/bench/bench_latency

## Debug build with ASan/UBSan
debug:
	@cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Debug -DWG_BUILD_TESTS=ON -DWG_ASAN=ON
	cmake --build $(BUILD_DIR) -j$(JOBS)
	cd $(BUILD_DIR) && ctest --output-on-failure

## Remove build directory
clean:
	rm -rf $(BUILD_DIR)

## One-shot build+test via nix (no devshell needed)
nix:
	nix build --print-build-logs
