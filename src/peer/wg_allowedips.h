/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * AllowedIPs routing table: trie-based longest-prefix match.
 *
 * Separate tries for IPv4 (4-byte keys) and IPv6 (16-byte keys).
 * Each trie node stores a CIDR prefix and an associated peer pointer.
 * Lookup returns the peer with the longest matching prefix.
 *
 * Reference: wireguard-go/device/allowedips.go
 */

#ifndef WG_ALLOWEDIPS_H
#define WG_ALLOWEDIPS_H

#include "wg_error.h"

#include "platform/wg_platform.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Forward declaration — full Peer definition in wg_peer.h */
struct wg_peer;

/* ────────────────────────────────────────
 * Trie node
 * ──────────────────────────────────────── */
typedef struct wg_trie_node {
    struct wg_peer *peer;
    struct wg_trie_node *child[2];

    /* Parent indirection: pointer-to-pointer for in-place splicing */
    struct wg_trie_node **parent_ref;
    struct wg_trie_node *parent_node; /* direct parent (NULL for root) */
    uint8_t parent_bit;               /* 0 or 1, or 2 for root */

    uint8_t cidr;
    uint8_t bit_at_byte;  /* cidr / 8 */
    uint8_t bit_at_shift; /* 7 - (cidr % 8) */

    uint8_t bits[16]; /* masked IP: 4 bytes for IPv4, 16 for IPv6 */
    uint8_t addr_len; /* 4 or 16 */
} wg_trie_node_t;

/* ────────────────────────────────────────
 * AllowedIPs table
 * ──────────────────────────────────────── */
typedef struct {
    wg_trie_node_t *root4; /* IPv4 trie root */
    wg_trie_node_t *root6; /* IPv6 trie root */
    pthread_rwlock_t lock;
} wg_allowedips_t;

/* ────────────────────────────────────────
 * Lifecycle
 * ──────────────────────────────────────── */

wg_error_t wg_allowedips_init(wg_allowedips_t *table);
void wg_allowedips_destroy(wg_allowedips_t *table);

/* ────────────────────────────────────────
 * Operations
 * ──────────────────────────────────────── */

/*
 * Insert a CIDR prefix -> peer mapping.
 *
 * ip     — pointer to network-order IP bytes (4 for IPv4, 16 for IPv6)
 * cidr   — prefix length (0–32 for IPv4, 0–128 for IPv6)
 * family — AF_INET or AF_INET6
 * peer   — associated peer (must not be NULL)
 *
 * If the exact prefix already exists, updates the peer.
 */
wg_error_t wg_allowedips_insert(wg_allowedips_t *table, const uint8_t *ip, uint8_t cidr,
                                int family, struct wg_peer *peer);

/*
 * Lookup the peer for a given IP address (longest-prefix match).
 *
 * ip     — pointer to network-order IP bytes
 * family — AF_INET or AF_INET6
 *
 * Returns the matching peer, or NULL if no match.
 */
struct wg_peer *wg_allowedips_lookup(wg_allowedips_t *table, const uint8_t *ip,
                                     int family);

/*
 * Lock-free lookup — caller must hold table->lock for read.
 * Used in hot paths (drain_rx_order) where the lock is amortized over a batch.
 */
struct wg_peer *wg_allowedips_lookup_unlocked(wg_allowedips_t *table, const uint8_t *ip,
                                              int family);

/*
 * Remove the exact prefix ip/cidr if it maps to peer; otherwise nothing
 * happens. The UAPI's "allowed_ip=-<prefix>" (wireguard-go semantics).
 */
void wg_allowedips_remove(wg_allowedips_t *table, const uint8_t *ip, uint8_t cidr,
                          int family, struct wg_peer *peer);

/*
 * Remove all entries associated with a specific peer.
 * This is called when removing a peer from the device.
 */
void wg_allowedips_remove_by_peer(wg_allowedips_t *table, struct wg_peer *peer);

/*
 * Walk all entries for a specific peer, calling fn for each.
 * The visitor receives the IP (network order), CIDR, family (AF_INET/AF_INET6),
 * and user context. Return false from fn to stop early.
 */
typedef bool (*wg_allowedips_walk_fn)(const uint8_t *ip, uint8_t cidr, int family,
                                      void *ctx);

void wg_allowedips_walk_by_peer(wg_allowedips_t *table, struct wg_peer *peer,
                                wg_allowedips_walk_fn fn, void *ctx);

#endif /* WG_ALLOWEDIPS_H */
