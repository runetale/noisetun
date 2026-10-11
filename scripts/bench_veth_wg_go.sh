#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# veth + iperf3 throughput benchmark for wireguard-go.
# Same setup as bench_veth_iperf3.sh for A/B comparison.
#
# Usage: sudo scripts/bench_veth_wg_go.sh [path-to-wireguard-go] [duration]

set -euo pipefail

WG_GO="${1:-wireguard-go}"
DURATION="${2:-10}"

NS_A="bench_a"
NS_B="bench_b"
VETH_A="veth_a"
VETH_B="veth_b"
WG_IFACE_A="wg0"
WG_IFACE_B="wg1"
PORT_A=51820
PORT_B=51821

VETH_IP_A="192.168.200.1/24"
VETH_IP_B="192.168.200.2/24"
VETH_ADDR_A="192.168.200.1"
VETH_ADDR_B="192.168.200.2"

WG_IP_A="10.10.0.1/24"
WG_IP_B="10.10.0.2/24"
WG_ADDR_A="10.10.0.1"
WG_ADDR_B="10.10.0.2"

log() { echo "==> $*"; }

cleanup() {
    [ -n "${PID_IPERF:-}" ] && kill "$PID_IPERF" 2>/dev/null || true
    # wireguard-go creates its own processes; kill by interface
    ip netns exec "$NS_A" ip link del "$WG_IFACE_A" 2>/dev/null || true
    ip netns exec "$NS_B" ip link del "$WG_IFACE_B" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    rm -rf "${TMPDIR_KEYS:-}" 2>/dev/null || true
}

trap cleanup EXIT

# ── Preflight ──
[ "$(id -u)" -eq 0 ] || { echo "Error: must be root" >&2; exit 1; }
command -v "$WG_GO" &>/dev/null || [ -x "$WG_GO" ] || { echo "Error: $WG_GO not found" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg not found" >&2; exit 1; }
command -v iperf3 &>/dev/null || { echo "Error: iperf3 not found" >&2; exit 1; }

log "wireguard-go: $WG_GO"
log "Duration: ${DURATION}s"

# ── Setup namespaces + veth ──
ip netns add "$NS_A"
ip netns add "$NS_B"

ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

ip netns exec "$NS_A" ip link set "$VETH_A" mtu 1500 txqueuelen 10000
ip netns exec "$NS_B" ip link set "$VETH_B" mtu 1500 txqueuelen 10000

ip netns exec "$NS_A" ip addr add "$VETH_IP_A" dev "$VETH_A"
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_A" ip link set lo up

ip netns exec "$NS_B" ip addr add "$VETH_IP_B" dev "$VETH_B"
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_B" ip link set lo up

# ── Generate keys ──
TMPDIR_KEYS=$(mktemp -d)
KEY_A_PRIV=$(wg genkey)
KEY_A_PUB=$(echo "$KEY_A_PRIV" | wg pubkey)
KEY_B_PRIV=$(wg genkey)
KEY_B_PUB=$(echo "$KEY_B_PRIV" | wg pubkey)
echo "$KEY_A_PRIV" > "$TMPDIR_KEYS/key_a"
echo "$KEY_B_PRIV" > "$TMPDIR_KEYS/key_b"
chmod 600 "$TMPDIR_KEYS/key_a" "$TMPDIR_KEYS/key_b"

# ── Start wireguard-go daemons ──
log "Starting wireguard-go (A)..."
ip netns exec "$NS_A" "$WG_GO" "$WG_IFACE_A"
sleep 1

log "Starting wireguard-go (B)..."
ip netns exec "$NS_B" "$WG_GO" "$WG_IFACE_B"
sleep 1

# ── Configure peers ──
ip netns exec "$NS_A" wg set "$WG_IFACE_A" \
    private-key "$TMPDIR_KEYS/key_a" \
    listen-port "$PORT_A" \
    peer "$KEY_B_PUB" \
    endpoint "${VETH_ADDR_B}:${PORT_B}" \
    allowed-ips "$WG_ADDR_B/32"

ip netns exec "$NS_B" wg set "$WG_IFACE_B" \
    private-key "$TMPDIR_KEYS/key_b" \
    listen-port "$PORT_B" \
    peer "$KEY_A_PUB" \
    endpoint "${VETH_ADDR_A}:${PORT_A}" \
    allowed-ips "$WG_ADDR_A/32"

# ── Bring up WG interfaces ──
ip netns exec "$NS_A" ip addr add "$WG_IP_A" dev "$WG_IFACE_A"
ip netns exec "$NS_A" ip link set "$WG_IFACE_A" up

ip netns exec "$NS_B" ip addr add "$WG_IP_B" dev "$WG_IFACE_B"
ip netns exec "$NS_B" ip link set "$WG_IFACE_B" up

# ── Verify connectivity ──
log "Verifying connectivity..."
ip netns exec "$NS_A" ping -c 2 -W 5 "$WG_ADDR_B" > /dev/null || { echo "Ping failed" >&2; exit 1; }
log "Connectivity OK"

# ── Run iperf3 ──
log "Starting iperf3 server (B)..."
ip netns exec "$NS_B" iperf3 -s -D -1
sleep 1

log "Running iperf3 client (A -> B) for ${DURATION}s..."
echo ""
ip netns exec "$NS_A" iperf3 -c "$WG_ADDR_B" -t "$DURATION" -P 1
echo ""

log "Done."
