#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Tear down whatever wgup.sh started. Run as root.
pkill -x iperf3 2>/dev/null; pkill -x wg-c 2>/dev/null; pkill -f /opt/wireguard-go/wireguard-go 2>/dev/null
ip link del wg0 2>/dev/null; sleep 1; ip link del wg0 2>/dev/null; true
