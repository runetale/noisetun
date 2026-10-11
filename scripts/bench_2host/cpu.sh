#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025-2026 Runetale Inc.
# Copyright (C) 2025-2026 gx14ac
#
# Print busy and total jiffies across all CPUs (bench.sh takes the delta).
awk '/^cpu /{b=$2+$3+$4+$7+$8+$9; t=b+$5+$6; print b, t}' /proc/stat
