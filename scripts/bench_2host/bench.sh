#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Two-host interleaved benchmark over a real NIC: raw / wg-c / wireguard-go /
# kernel WireGuard (performance-analysis.md #56). Runs on the operator's
# machine and drives host A (iperf3 client) and host B (iperf3 server) over ssh.
#
# Each host needs provision.sh run once, and wgup.sh / wgdown.sh / cpu.sh
# copied to /usr/local/bin. Each host's WireGuard private key is in
# /etc/wireguard/k (AppArmor on Ubuntu 26.04 only lets wg(8) read /etc/wireguard).
#
# Usage:
#   SSH_KEY=key.pem A=<A public IP> B=<B public IP> \
#   AP=<A private IP> BP=<B private IP> APUB=<A wg pubkey> BPUB=<B wg pubkey> \
#   [ROUNDS=6] [DUR=20] [OUT=results.tsv] scripts/bench_2host/bench.sh
#
# Odd rounds run raw -> wgc -> wggo -> kern, even rounds the reverse. CPU is
# the /proc/stat delta around the iperf3 run, in cores used out of all vCPUs.

set -u
: "${SSH_KEY:?}" "${A:?}" "${B:?}" "${AP:?}" "${BP:?}" "${APUB:?}" "${BPUB:?}"
ROUNDS=${ROUNDS:-6}; DUR=${DUR:-20}; OUT=${OUT:-results_$(date +%H%M%S).tsv}
sa() { ssh -i "$SSH_KEY" -o ServerAliveInterval=10 ubuntu@$A "$@"; }
sb() { ssh -i "$SSH_KEY" -o ServerAliveInterval=10 ubuntu@$B "$@"; }
NCPU=$(sa nproc)
sa 'sudo ip link set ens5 mtu 1500'; sb 'sudo ip link set ens5 mtu 1500'
echo -e "round\timpl\tgbps\tretr\tcpuA_cores\tcpuB_cores" | tee $OUT
cpu() { echo "$1 $2" | awk -v n=$NCPU '{printf "%.2f", ($3-$1)/($4-$2)*n}'; }
run() {
  local r=$1 impl=$2 dst
  sa 'sudo wgdown.sh'; sb 'sudo wgdown.sh'
  if [ $impl = raw ]; then dst=$BP; else
    sa "sudo wgup.sh $impl 10.99.0.1 /etc/wireguard/k $BPUB $BP 10.99.0.2" >/dev/null
    sb "sudo wgup.sh $impl 10.99.0.2 /etc/wireguard/k $APUB $AP 10.99.0.1" >/dev/null
    dst=10.99.0.2
    sa "ping -c 3 -W 3 $dst >/dev/null" || { echo "ping fail $impl"; return; }
  fi
  sb 'iperf3 -s -1 -D'; sleep 1
  local ca0=$(sa cpu.sh) cb0=$(sb cpu.sh)
  local j=$(sa "iperf3 -c $dst -t $DUR --omit 3 -C cubic -P 1 -J")
  local ca1=$(sa cpu.sh) cb1=$(sb cpu.sh)
  local g=$(echo "$j" | jq '.end.sum_received.bits_per_second/1e9')
  local rt=$(echo "$j" | jq '.end.sum_sent.retransmits')
  printf "%s\t%s\t%.3f\t%s\t%s\t%s\n" $r $impl $g $rt $(cpu "$ca0" "$ca1") $(cpu "$cb0" "$cb1") | tee -a $OUT
}
for r in $(seq 1 $ROUNDS); do
  if [ $((r % 2)) = 1 ]; then order="raw wgc wggo kern"; else order="kern wggo wgc raw"; fi
  for i in $order; do run $r $i; done
done
sa 'sudo wgdown.sh'; sb 'sudo wgdown.sh'
echo "== means"; awk -F'\t' 'NR>1{s[$2]+=$3;n[$2]++;ca[$2]+=$5;cb[$2]+=$6} END{for(k in s) printf "%s\t%.3f Gbps\tcpuA %.2f\tcpuB %.2f cores\n",k,s[k]/n[k],ca[k]/n[k],cb[k]/n[k]}' $OUT
