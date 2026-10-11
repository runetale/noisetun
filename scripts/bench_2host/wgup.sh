#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Bring up wg0 with one implementation. Run as root on each host.
# usage: wgup.sh <wgc|wggo|kern> <my_tun_ip> <my_privkey_file> <peer_pub> <peer_underlay_ip> <peer_tun_ip>
set -e
IMPL=$1 ME=$2 KEY=$3 PPUB=$4 PEP=$5 PTUN=$6
case $IMPL in
  wgc)  WG_PROCESS_FOREGROUND=1 setsid nohup /opt/wgc/build-release/tools/wg-c -f wg0 >/tmp/wgc.log 2>&1 < /dev/null & sleep 1 ;;
  wggo) WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 /opt/wireguard-go/wireguard-go wg0; sleep 1 ;;
  kern) ip link add wg0 type wireguard ;;
esac
wg set wg0 private-key $KEY listen-port 51820 peer $PPUB endpoint $PEP:51820 allowed-ips $PTUN/32
ip addr add $ME/24 dev wg0
ip link set wg0 mtu 1420 up
ip -d link show wg0 | head -3 | tail -1
