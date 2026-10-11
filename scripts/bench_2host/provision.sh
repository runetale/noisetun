#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# One-time setup of a benchmark host (Ubuntu 26.04). Run as root with the
# wg-c source tarball at /tmp/wgc.tar.gz (git archive of the commit under test).
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq build-essential cmake pkg-config libssl-dev libsodium-dev iperf3 wireguard-tools golang-go jq sysstat git ethtool linux-tools-common linux-tools-$(uname -r) || apt-get install -yq build-essential cmake pkg-config libssl-dev libsodium-dev iperf3 wireguard-tools golang-go jq sysstat git ethtool
mkdir -p /opt/wgc && tar xzf /tmp/wgc.tar.gz -C /opt/wgc
cd /opt/wgc && cmake -B build-release -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS='-march=native' -DWG_BUILD_TESTS=OFF >/dev/null && cmake --build build-release --target wg-c -j$(nproc) >/dev/null
cd /opt && git clone -q https://git.zx2c4.com/wireguard-go && cd wireguard-go && git checkout -q 0.0.20250522 && go build -o wireguard-go .
# AppArmor on 26.04 blocks wg set for userspace impls (see bench_rigorous.sh header)
if [ -f /etc/apparmor.d/wg ]; then mkdir -p /etc/apparmor.d/local; echo '/run/wireguard/*.sock rw,' >> /etc/apparmor.d/local/wg; apparmor_parser -r /etc/apparmor.d/wg || true; fi
uname -r; gcc --version | head -1; openssl version; iperf3 --version | head -1; go version; ls -la /opt/wgc/build-release/tools/wg-c /opt/wireguard-go/wireguard-go
