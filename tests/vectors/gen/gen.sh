#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Runetale Inc.
#
# Regenerates tests/vectors/wg_noise_vectors.h from wireguard-go 0.0.20250522.
# Usage: gen.sh [wireguard-go-dir] [output-header]
#   wireguard-go-dir: a checkout of that version; cloned from
#     https://git.zx2c4.com/wireguard-go if omitted.
#   output-header: defaults to $WG_VECTORS_OUT, else ../wg_noise_vectors.h
#     next to this script.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
version=0.0.20250522
out=${2:-${WG_VECTORS_OUT:-$here/../wg_noise_vectors.h}}
case $out in /*) ;; *) out=$PWD/$out ;; esac

work=$(mktemp -d "${TMPDIR:-/tmp}/wgvec.XXXXXX")
trap 'rm -rf "$work"' EXIT

if [ $# -ge 1 ]; then
    cp -R "$1" "$work/wireguard-go"
else
    git clone --quiet --depth 1 --branch "$version" \
        https://git.zx2c4.com/wireguard-go "$work/wireguard-go"
fi
cd "$work/wireguard-go"
rm -rf .git
patch -p1 --quiet < "$here/wireguard-go.patch"
cp "$here/vectors_test.go" device/vectors_test.go
WG_VECTORS_OUT=$out go test -count=1 -run '^TestEmitVectors$' ./device/
echo "wrote $out"
