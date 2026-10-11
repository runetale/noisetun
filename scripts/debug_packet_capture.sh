#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Packet capture debug script for WireGuard handshake + data transfer.
#
# Sets up two wg-c devices in separate network namespaces,
# captures packets on both the underlay (veth/UDP) and overlay (TUN/ICMP),
# and displays a decoded summary of the WireGuard protocol exchange.
#
# Requirements: root, wg-c binary, tcpdump, wg
# Usage: sudo scripts/debug_packet_capture.sh [path-to-wg-c]

set -euo pipefail

WGC="${1:-./build/tools/wg-c}"
CAPTURE_DIR="${CAPTURE_DIR:-/tmp/wg_packet_debug}"

NS_A="pktdbg_a"
NS_B="pktdbg_b"
VETH_A="veth_da"
VETH_B="veth_db"
WG_IFACE_A="wg0"
WG_IFACE_B="wg1"
PORT_A=55100
PORT_B=55101

VETH_IP_A="192.168.240.1/24"
VETH_IP_B="192.168.240.2/24"
VETH_ADDR_A="192.168.240.1"
VETH_ADDR_B="192.168.240.2"

WG_IP_A="10.88.0.1/24"
WG_IP_B="10.88.0.2/24"
WG_ADDR_A="10.88.0.1"
WG_ADDR_B="10.88.0.2"

# WireGuard message type constants
MSG_INITIATION=1
MSG_RESPONSE=2
MSG_COOKIE=3
MSG_TRANSPORT=4

log()  { echo -e "\033[1;36m==>\033[0m $*"; }
info() { echo -e "\033[0;33m    $*\033[0m"; }
pass() { echo -e "\033[1;32m  PASS:\033[0m $*"; }
fail() { echo -e "\033[1;31m  FAIL:\033[0m $*"; }
hdr()  { echo -e "\n\033[1;35m────────────────────────────────────────\033[0m"; echo -e "\033[1;35m  $*\033[0m"; echo -e "\033[1;35m────────────────────────────────────────\033[0m"; }

cleanup() {
    log "Cleaning up..."
    # Stop tcpdump processes
    for pid in "${TCPDUMP_PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
    done
    # Stop wg-c daemons
    [ -n "${PID_A:-}" ] && kill "$PID_A" 2>/dev/null && wait "$PID_A" 2>/dev/null || true
    [ -n "${PID_B:-}" ] && kill "$PID_B" 2>/dev/null && wait "$PID_B" 2>/dev/null || true
    # Remove namespaces
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    rm -rf "${TMPDIR_KEYS:-}" 2>/dev/null || true
}

trap cleanup EXIT
TCPDUMP_PIDS=()

# ──────────────────────────────────────
# Preflight
# ──────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must be root" >&2; exit 1
fi
[ -x "$WGC" ] || { echo "Error: $WGC not found (build first)" >&2; exit 1; }
command -v tcpdump &>/dev/null || { echo "Error: tcpdump not found (add to devShell)" >&2; exit 1; }
command -v wg &>/dev/null || { echo "Error: wg not found" >&2; exit 1; }

mkdir -p "$CAPTURE_DIR"

hdr "WireGuard Packet Capture Debug"
log "wg-c binary: $WGC"
log "Capture dir: $CAPTURE_DIR"

# ──────────────────────────────────────
# Setup namespaces + veth
# ──────────────────────────────────────

hdr "Network Setup"

ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true

ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$VETH_A" type veth peer name "$VETH_B"
ip link set "$VETH_A" netns "$NS_A"
ip link set "$VETH_B" netns "$NS_B"

ip netns exec "$NS_A" ip addr add "$VETH_IP_A" dev "$VETH_A"
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_A" ip link set lo up

ip netns exec "$NS_B" ip addr add "$VETH_IP_B" dev "$VETH_B"
ip netns exec "$NS_B" ip link set "$VETH_B" up
ip netns exec "$NS_B" ip link set lo up

if ip netns exec "$NS_A" ping -c 1 -W 2 "$VETH_ADDR_B" &>/dev/null; then
    pass "veth underlay connectivity"
else
    fail "veth underlay connectivity"; exit 1
fi

# ──────────────────────────────────────
# Generate keys
# ──────────────────────────────────────

TMPDIR_KEYS=$(mktemp -d)
KEY_A_PRIV=$(wg genkey)
KEY_A_PUB=$(echo "$KEY_A_PRIV" | wg pubkey)
KEY_B_PRIV=$(wg genkey)
KEY_B_PUB=$(echo "$KEY_B_PRIV" | wg pubkey)
echo "$KEY_A_PRIV" > "$TMPDIR_KEYS/key_a"
echo "$KEY_B_PRIV" > "$TMPDIR_KEYS/key_b"
chmod 600 "$TMPDIR_KEYS/key_a" "$TMPDIR_KEYS/key_b"

info "Device A pubkey: $KEY_A_PUB"
info "Device B pubkey: $KEY_B_PUB"

# ──────────────────────────────────────
# Start wg-c daemons
# ──────────────────────────────────────

hdr "Starting wg-c Daemons"

ip netns exec "$NS_A" env WG_PROCESS_FOREGROUND=1 "$WGC" -f "$WG_IFACE_A" &
PID_A=$!

ip netns exec "$NS_B" env WG_PROCESS_FOREGROUND=1 "$WGC" -f "$WG_IFACE_B" &
PID_B=$!

sleep 1

kill -0 "$PID_A" 2>/dev/null && pass "wg-c A started (PID $PID_A)" || { fail "wg-c A start"; exit 1; }
kill -0 "$PID_B" 2>/dev/null && pass "wg-c B started (PID $PID_B)" || { fail "wg-c B start"; exit 1; }

# ──────────────────────────────────────
# Configure peers
# ──────────────────────────────────────

hdr "Configuring Peers"

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

ip netns exec "$NS_A" ip addr add "$WG_IP_A" dev "$WG_IFACE_A"
ip netns exec "$NS_A" ip link set "$WG_IFACE_A" up
ip netns exec "$NS_B" ip addr add "$WG_IP_B" dev "$WG_IFACE_B"
ip netns exec "$NS_B" ip link set "$WG_IFACE_B" up

log "Configuration applied"
ip netns exec "$NS_A" wg show "$WG_IFACE_A"
echo ""
ip netns exec "$NS_B" wg show "$WG_IFACE_B"

# ──────────────────────────────────────
# Start packet captures
# ──────────────────────────────────────

hdr "Starting Packet Captures"

PCAP_UNDERLAY_A="$CAPTURE_DIR/underlay_a.pcap"
PCAP_UNDERLAY_B="$CAPTURE_DIR/underlay_b.pcap"
PCAP_OVERLAY_A="$CAPTURE_DIR/overlay_a.pcap"
PCAP_OVERLAY_B="$CAPTURE_DIR/overlay_b.pcap"

# Capture on underlay (veth) - shows WireGuard UDP packets
ip netns exec "$NS_A" tcpdump -i "$VETH_A" -w "$PCAP_UNDERLAY_A" -U udp port "$PORT_A" or udp port "$PORT_B" &
TCPDUMP_PIDS+=($!)
log "tcpdump underlay A (PID $!) -> $PCAP_UNDERLAY_A"

ip netns exec "$NS_B" tcpdump -i "$VETH_B" -w "$PCAP_UNDERLAY_B" -U udp port "$PORT_A" or udp port "$PORT_B" &
TCPDUMP_PIDS+=($!)
log "tcpdump underlay B (PID $!) -> $PCAP_UNDERLAY_B"

# Capture on overlay (TUN) - shows decrypted tunnel traffic (ICMP pings)
ip netns exec "$NS_A" tcpdump -i "$WG_IFACE_A" -w "$PCAP_OVERLAY_A" -U icmp &
TCPDUMP_PIDS+=($!)
log "tcpdump overlay A (PID $!) -> $PCAP_OVERLAY_A"

ip netns exec "$NS_B" tcpdump -i "$WG_IFACE_B" -w "$PCAP_OVERLAY_B" -U icmp &
TCPDUMP_PIDS+=($!)
log "tcpdump overlay B (PID $!) -> $PCAP_OVERLAY_B"

sleep 1  # let tcpdump initialize

# ──────────────────────────────────────
# Test: A -> B ping (triggers handshake)
# ──────────────────────────────────────

hdr "Test: A -> B Ping (triggers handshake)"

if ip netns exec "$NS_A" ping -c 5 -W 10 "$WG_ADDR_B"; then
    pass "A -> B ping through tunnel"
else
    fail "A -> B ping through tunnel"
fi

# ──────────────────────────────────────
# Test: B -> A ping (session established)
# ──────────────────────────────────────

hdr "Test: B -> A Ping (established session)"

if ip netns exec "$NS_B" ping -c 3 -W 5 "$WG_ADDR_A"; then
    pass "B -> A ping through tunnel"
else
    fail "B -> A ping through tunnel"
fi

sleep 1  # let captures flush

# ──────────────────────────────────────
# Stop captures
# ──────────────────────────────────────

for pid in "${TCPDUMP_PIDS[@]}"; do
    kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
done
TCPDUMP_PIDS=()

# ──────────────────────────────────────
# WireGuard state after tests
# ──────────────────────────────────────

hdr "WireGuard State After Tests"

log "Device A:"
ip netns exec "$NS_A" wg show "$WG_IFACE_A"
echo ""
log "Device B:"
ip netns exec "$NS_B" wg show "$WG_IFACE_B"

# ──────────────────────────────────────
# Analyze underlay captures (WireGuard protocol)
# ──────────────────────────────────────

hdr "Underlay Packet Analysis (WireGuard Protocol)"

analyze_wg_pcap() {
    local pcap="$1"
    local label="$2"

    if [ ! -s "$pcap" ]; then
        info "$label: no packets captured"
        return
    fi

    log "$label:"

    # Annotate each packet with WireGuard message type based on UDP payload size.
    # WireGuard message sizes are fixed (except transport which varies):
    #   Type 1 - Handshake Initiation:  148 bytes
    #   Type 2 - Handshake Response:     92 bytes
    #   Type 3 - Cookie Reply:           64 bytes
    #   Type 4 - Transport Data:     32+ bytes (32 header + encrypted payload)
    #            keepalive is exactly 32 bytes (empty payload)
    local init=0 resp=0 cookie=0 transport=0 keepalive=0

    while IFS= read -r line; do
        local len
        len=$(echo "$line" | grep -oP 'length \K[0-9]+')
        local tag=""
        case "$len" in
            148) init=$((init + 1));      tag="[Handshake Initiation]" ;;
            92)  resp=$((resp + 1));       tag="[Handshake Response]" ;;
            64)  cookie=$((cookie + 1));   tag="[Cookie Reply]" ;;
            32)  keepalive=$((keepalive + 1)); tag="[Keepalive]" ;;
            *)   transport=$((transport + 1)); tag="[Transport Data ($len B)]" ;;
        esac
        printf "    %-80s %s\n" "$line" "$tag"
    done < <(tcpdump -r "$pcap" -nn -t 2>/dev/null | head -60)

    echo ""
    info "WireGuard message breakdown:"
    printf "    Handshake Initiation (type 1): %d\n" "$init"
    printf "    Handshake Response   (type 2): %d\n" "$resp"
    printf "    Cookie Reply         (type 3): %d\n" "$cookie"
    printf "    Transport Data       (type 4): %d\n" "$transport"
    printf "    Keepalive            (type 4): %d\n" "$keepalive"
    local total=$((init + resp + cookie + transport + keepalive))
    printf "    Total:                         %d\n" "$total"
    echo ""
}

analyze_wg_pcap "$PCAP_UNDERLAY_A" "Namespace A underlay ($VETH_A)"
analyze_wg_pcap "$PCAP_UNDERLAY_B" "Namespace B underlay ($VETH_B)"

# ──────────────────────────────────────
# Analyze overlay captures (tunnel traffic)
# ──────────────────────────────────────

hdr "Overlay Packet Analysis (Tunnel ICMP)"

for label_pcap in "A:$PCAP_OVERLAY_A" "B:$PCAP_OVERLAY_B"; do
    label="${label_pcap%%:*}"
    pcap="${label_pcap#*:}"
    if [ -s "$pcap" ]; then
        log "Namespace $label overlay (TUN):"
        tcpdump -r "$pcap" -nn -t 2>/dev/null | head -30
        pkt_count=$(tcpdump -r "$pcap" -nn 2>/dev/null | wc -l)
        info "Total ICMP packets: $pkt_count"
    else
        info "Namespace $label: no overlay packets captured"
    fi
    echo ""
done

# ──────────────────────────────────────
# Packet flow timeline
# ──────────────────────────────────────

hdr "Combined Packet Timeline (underlay A)"

if [ -s "$PCAP_UNDERLAY_A" ]; then
    log "Chronological packet flow on $VETH_A:"
    info "(timestamps relative to first packet)"
    echo ""

    tcpdump -r "$PCAP_UNDERLAY_A" -nn -tttt 2>/dev/null | while IFS= read -r line; do
        # Colorize based on direction
        if echo "$line" | grep -q "${VETH_ADDR_A}.*> ${VETH_ADDR_B}"; then
            echo -e "    \033[1;32m>>>\033[0m $line"  # outgoing = green
        elif echo "$line" | grep -q "${VETH_ADDR_B}.*> ${VETH_ADDR_A}"; then
            echo -e "    \033[1;34m<<<\033[0m $line"  # incoming = blue
        else
            echo "    --- $line"
        fi
    done | head -80
fi

# ──────────────────────────────────────
# Summary
# ──────────────────────────────────────

hdr "Capture Files"
log "Saved pcap files for further analysis with Wireshark:"
info "$PCAP_UNDERLAY_A  (A underlay - WireGuard UDP)"
info "$PCAP_UNDERLAY_B  (B underlay - WireGuard UDP)"
info "$PCAP_OVERLAY_A   (A overlay  - Tunnel ICMP)"
info "$PCAP_OVERLAY_B   (B overlay  - Tunnel ICMP)"
echo ""
info "Open in Wireshark:  wireshark $PCAP_UNDERLAY_A"
info "WireGuard dissector: Wireshark automatically decodes WireGuard protocol"
echo ""
