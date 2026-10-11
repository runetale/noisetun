/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * AllowedIPs routing table: trie-based longest-prefix match.
 *
 * Reference: wireguard-go/device/allowedips.go
 */

#include "wg_allowedips.h"

#include <stdlib.h>
#include <string.h>

/* ────────────────────────────────────────
 * Helpers
 * ──────────────────────────────────────── */

static uint8_t common_bits(const uint8_t *a, const uint8_t *b, uint8_t len)
{
    uint8_t bits = 0;
    for (uint8_t i = 0; i < len; i++) {
        uint8_t x = a[i] ^ b[i];
        if (x == 0) {
            bits += 8;
        } else {
            bits += (uint8_t)__builtin_clz((unsigned int)x) - 24;
            break;
        }
    }
    return bits;
}

static uint8_t choose_bit(const wg_trie_node_t *node, const uint8_t *ip)
{
    return (ip[node->bit_at_byte] >> node->bit_at_shift) & 1;
}

static void mask_self(wg_trie_node_t *node)
{
    uint8_t full_bytes = node->cidr / 8;
    uint8_t remainder = node->cidr % 8;

    for (uint8_t i = 0; i < node->addr_len; i++) {
        if (i < full_bytes)
            continue;
        else if (i == full_bytes && remainder > 0)
            node->bits[i] &= (uint8_t)(0xFF << (8 - remainder));
        else
            node->bits[i] = 0;
    }
}

static void node_set_cidr_fields(wg_trie_node_t *n, uint8_t cidr, uint8_t addr_len)
{
    n->cidr = cidr;
    /*
     * P0-4 fix: when cidr == addr_len*8 (e.g. /32 for IPv4, /128 for IPv6),
     * cidr/8 equals addr_len, causing OOB in choose_bit (ip[addr_len]).
     * Clamp bit_at_byte to addr_len-1 so choose_bit always accesses
     * valid memory. trie_lookup also guards with bit_at_byte == addr_len.
     */
    uint8_t byte_pos = cidr / 8;
    if (byte_pos >= addr_len)
        byte_pos = (uint8_t)(addr_len - 1);
    n->bit_at_byte = byte_pos;
    n->bit_at_shift = 7 - (cidr % 8);
}

static wg_trie_node_t *node_alloc(const uint8_t *ip, uint8_t cidr, uint8_t addr_len,
                                  struct wg_peer *peer)
{
    wg_trie_node_t *n = calloc(1, sizeof(*n));
    if (!n)
        return NULL;

    n->peer = peer;
    n->addr_len = addr_len;
    node_set_cidr_fields(n, cidr, addr_len);
    memcpy(n->bits, ip, addr_len);
    mask_self(n);

    return n;
}

/* Find the deepest node whose prefix is a prefix of ip with cidr <= target_cidr.
 * If exact match found, sets *exact = true. */
static wg_trie_node_t *node_placement(wg_trie_node_t *node, const uint8_t *ip,
                                      uint8_t cidr, uint8_t addr_len, bool *exact)
{
    wg_trie_node_t *parent = NULL;
    *exact = false;

    while (node && node->cidr <= cidr &&
           common_bits(node->bits, ip, addr_len) >= node->cidr) {
        parent = node;
        if (parent->cidr == cidr) {
            *exact = true;
            return parent;
        }
        uint8_t bit = choose_bit(node, ip);
        node = node->child[bit];
    }
    return parent;
}

/* Free a single node (does not recurse). */
static void node_free(wg_trie_node_t *node)
{
    if (node) {
        node->peer = NULL;
        node->child[0] = NULL;
        node->child[1] = NULL;
        node->parent_ref = NULL;
        free(node);
    }
}

/* Recursively free all nodes in a trie. */
static void trie_free_recursive(wg_trie_node_t *node)
{
    if (!node)
        return;
    trie_free_recursive(node->child[0]);
    trie_free_recursive(node->child[1]);
    node_free(node);
}

/* Remove a single node from the trie, fixing up parent/child pointers. */
static void node_remove(wg_trie_node_t *node)
{
    node->peer = NULL;

    /* If both children exist, keep the node as an intermediate. */
    if (node->child[0] && node->child[1])
        return;

    /* Determine the surviving child (if any). */
    int bit = (node->child[0] == NULL) ? 1 : 0;
    wg_trie_node_t *child = node->child[bit];

    /* Splice child into parent's slot. */
    if (child) {
        child->parent_ref = node->parent_ref;
        child->parent_bit = node->parent_bit;
        child->parent_node = node->parent_node;
    }
    *node->parent_ref = child;

    /*
     * If the node has no children and its parent is an intermediate
     * (peer == NULL with exactly one remaining child), collapse it.
     */
    if (!node->child[0] && !node->child[1] && node->parent_node != NULL &&
        node->parent_bit <= 1) {
        wg_trie_node_t *parent = node->parent_node;

        if (parent->peer != NULL) {
            node_free(node);
            return;
        }

        /* Collapse: promote the other child of parent. */
        wg_trie_node_t *sibling = parent->child[node->parent_bit ^ 1];
        if (sibling) {
            sibling->parent_ref = parent->parent_ref;
            sibling->parent_bit = parent->parent_bit;
            sibling->parent_node = parent->parent_node;
        }
        *parent->parent_ref = sibling;
        node_free(node);
        node_free(parent);
        return;
    }

    node_free(node);
}

/* ────────────────────────────────────────
 * Insert into trie (internal, caller holds write lock)
 * ──────────────────────────────────────── */

static wg_error_t trie_insert(wg_trie_node_t **root, const uint8_t *ip, uint8_t cidr,
                              uint8_t addr_len, struct wg_peer *peer)
{
    /* Empty trie: create root node. */
    if (*root == NULL) {
        wg_trie_node_t *node = node_alloc(ip, cidr, addr_len, peer);
        if (!node)
            return WG_ERR_NO_MEMORY;
        node->parent_ref = root;
        node->parent_node = NULL;
        node->parent_bit = 2; /* root sentinel */
        *root = node;
        return WG_OK;
    }

    bool exact;
    wg_trie_node_t *parent = node_placement(*root, ip, cidr, addr_len, &exact);

    /* Exact prefix match: update peer. */
    if (exact) {
        parent->peer = peer;
        return WG_OK;
    }

    /* Create the new node. */
    wg_trie_node_t *new_node = node_alloc(ip, cidr, addr_len, peer);
    if (!new_node)
        return WG_ERR_NO_MEMORY;

    /* Determine which existing node is "below" the insertion point. */
    wg_trie_node_t *down;
    if (parent == NULL) {
        down = *root;
    } else {
        uint8_t bit = choose_bit(parent, ip);
        down = parent->child[bit];
        if (!down) {
            /* Simple leaf insertion. */
            new_node->parent_ref = &parent->child[bit];
            new_node->parent_node = parent;
            new_node->parent_bit = bit;
            parent->child[bit] = new_node;
            return WG_OK;
        }
    }

    /* Compute common prefix length between new_node and down. */
    uint8_t common = common_bits(down->bits, ip, addr_len);
    if (common < cidr)
        cidr = common;

    /* Case 1: new_node's cidr equals the common prefix — new_node becomes parent of down.
     */
    if (new_node->cidr == cidr) {
        uint8_t bit = choose_bit(new_node, down->bits);
        down->parent_ref = &new_node->child[bit];
        down->parent_node = new_node;
        down->parent_bit = bit;
        new_node->child[bit] = down;

        if (parent == NULL) {
            new_node->parent_ref = root;
            new_node->parent_node = NULL;
            new_node->parent_bit = 2;
            *root = new_node;
        } else {
            uint8_t pbit = choose_bit(parent, new_node->bits);
            new_node->parent_ref = &parent->child[pbit];
            new_node->parent_node = parent;
            new_node->parent_bit = pbit;
            parent->child[pbit] = new_node;
        }
        return WG_OK;
    }

    /* Case 2: need an intermediate node to split. */
    wg_trie_node_t *intermediate = calloc(1, sizeof(*intermediate));
    if (!intermediate) {
        node_free(new_node);
        return WG_ERR_NO_MEMORY;
    }

    intermediate->addr_len = addr_len;
    node_set_cidr_fields(intermediate, cidr, addr_len);
    memcpy(intermediate->bits, new_node->bits, addr_len);
    mask_self(intermediate);

    uint8_t bit = choose_bit(intermediate, down->bits);
    down->parent_ref = &intermediate->child[bit];
    down->parent_node = intermediate;
    down->parent_bit = bit;
    intermediate->child[bit] = down;

    bit = choose_bit(intermediate, new_node->bits);
    new_node->parent_ref = &intermediate->child[bit];
    new_node->parent_node = intermediate;
    new_node->parent_bit = bit;
    intermediate->child[bit] = new_node;

    if (parent == NULL) {
        intermediate->parent_ref = root;
        intermediate->parent_node = NULL;
        intermediate->parent_bit = 2;
        *root = intermediate;
    } else {
        bit = choose_bit(parent, intermediate->bits);
        intermediate->parent_ref = &parent->child[bit];
        intermediate->parent_node = parent;
        intermediate->parent_bit = bit;
        parent->child[bit] = intermediate;
    }

    return WG_OK;
}

/* ────────────────────────────────────────
 * Lookup in trie (internal, caller holds read lock)
 * ──────────────────────────────────────── */

static struct wg_peer *trie_lookup(wg_trie_node_t *node, const uint8_t *ip,
                                   uint8_t addr_len)
{
    struct wg_peer *found = NULL;

    while (node && common_bits(node->bits, ip, addr_len) >= node->cidr) {
        if (node->peer)
            found = node->peer;

        if (node->bit_at_byte == addr_len)
            break;

        uint8_t bit = choose_bit(node, ip);
        node = node->child[bit];
    }

    return found;
}

/* ────────────────────────────────────────
 * Remove by peer (internal, caller holds write lock)
 *
 * We cannot use recursive traversal with in-place removal because
 * node_remove may collapse intermediate nodes, freeing ancestors.
 * Instead, collect all matching nodes first, then remove them.
 * ──────────────────────────────────────── */

/* Collect all nodes matching a peer into a dynamic array. */
static void trie_collect_by_peer(wg_trie_node_t *node, struct wg_peer *peer,
                                 wg_trie_node_t ***list, size_t *count, size_t *capacity)
{
    if (!node)
        return;

    trie_collect_by_peer(node->child[0], peer, list, count, capacity);
    trie_collect_by_peer(node->child[1], peer, list, count, capacity);

    if (node->peer == peer) {
        if (*count == *capacity) {
            size_t new_cap = (*capacity == 0) ? 16 : *capacity * 2;
            wg_trie_node_t **new_list =
                realloc(*list, new_cap * sizeof(wg_trie_node_t *));
            if (!new_list) {
                /*
                 * OOM: stop collecting further nodes. The already-collected
                 * nodes will still be removed by the caller. The uncollected
                 * nodes will remain in the trie — a partial removal, but no
                 * crash or memory corruption.
                 */
                return;
            }
            *list = new_list;
            *capacity = new_cap;
        }
        (*list)[(*count)++] = node;
    }
}

static void trie_remove_by_peer(wg_trie_node_t *node, struct wg_peer *peer)
{
    wg_trie_node_t **list = NULL;
    size_t count = 0, capacity = 0;

    trie_collect_by_peer(node, peer, &list, &count, &capacity);

    for (size_t i = 0; i < count; i++)
        node_remove(list[i]);

    free(list);
}

/* ────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────── */

wg_error_t wg_allowedips_init(wg_allowedips_t *table)
{
    table->root4 = NULL;
    table->root6 = NULL;
    pthread_rwlock_init(&table->lock, NULL);
    return WG_OK;
}

void wg_allowedips_destroy(wg_allowedips_t *table)
{
    if (!table)
        return;

    trie_free_recursive(table->root4);
    trie_free_recursive(table->root6);
    table->root4 = NULL;
    table->root6 = NULL;
    pthread_rwlock_destroy(&table->lock);
}

wg_error_t wg_allowedips_insert(wg_allowedips_t *table, const uint8_t *ip, uint8_t cidr,
                                int family, struct wg_peer *peer)
{
    uint8_t addr_len;
    wg_trie_node_t **root;

    if (family == AF_INET) {
        addr_len = 4;
        root = &table->root4;
        if (cidr > 32)
            return WG_ERR_INVALID_ARGUMENT;
    } else if (family == AF_INET6) {
        addr_len = 16;
        root = &table->root6;
        if (cidr > 128)
            return WG_ERR_INVALID_ARGUMENT;
    } else {
        return WG_ERR_ALLOWEDIPS_FULL; /* invalid family */
    }

    pthread_rwlock_wrlock(&table->lock);
    wg_error_t err = trie_insert(root, ip, cidr, addr_len, peer);
    pthread_rwlock_unlock(&table->lock);

    return err;
}

struct wg_peer *wg_allowedips_lookup(wg_allowedips_t *table, const uint8_t *ip,
                                     int family)
{
    pthread_rwlock_rdlock(&table->lock);

    struct wg_peer *peer = NULL;
    if (family == AF_INET)
        peer = trie_lookup(table->root4, ip, 4);
    else if (family == AF_INET6)
        peer = trie_lookup(table->root6, ip, 16);

    pthread_rwlock_unlock(&table->lock);
    return peer;
}

struct wg_peer *wg_allowedips_lookup_unlocked(wg_allowedips_t *table, const uint8_t *ip,
                                              int family)
{
    if (family == AF_INET)
        return trie_lookup(table->root4, ip, 4);
    else if (family == AF_INET6)
        return trie_lookup(table->root6, ip, 16);
    return NULL;
}

void wg_allowedips_remove(wg_allowedips_t *table, const uint8_t *ip, uint8_t cidr,
                          int family, struct wg_peer *peer)
{
    uint8_t addr_len;
    wg_trie_node_t **root;

    if (family == AF_INET && cidr <= 32) {
        addr_len = 4;
        root = &table->root4;
    } else if (family == AF_INET6 && cidr <= 128) {
        addr_len = 16;
        root = &table->root6;
    } else {
        return;
    }

    pthread_rwlock_wrlock(&table->lock);
    bool exact;
    wg_trie_node_t *node = node_placement(*root, ip, cidr, addr_len, &exact);
    if (exact && node && node->peer == peer)
        node_remove(node);
    pthread_rwlock_unlock(&table->lock);
}

void wg_allowedips_remove_by_peer(wg_allowedips_t *table, struct wg_peer *peer)
{
    pthread_rwlock_wrlock(&table->lock);
    trie_remove_by_peer(table->root4, peer);
    trie_remove_by_peer(table->root6, peer);
    pthread_rwlock_unlock(&table->lock);
}

/* ────────────────────────────────────────
 * Walk: iterate all entries for a peer
 * ──────────────────────────────────────── */

static bool trie_walk_by_peer(const wg_trie_node_t *node, struct wg_peer *peer,
                              int family, wg_allowedips_walk_fn fn, void *ctx)
{
    if (!node)
        return true;
    if (node->peer == peer) {
        if (!fn(node->bits, node->cidr, family, ctx))
            return false;
    }
    if (!trie_walk_by_peer(node->child[0], peer, family, fn, ctx))
        return false;
    return trie_walk_by_peer(node->child[1], peer, family, fn, ctx);
}

void wg_allowedips_walk_by_peer(wg_allowedips_t *table, struct wg_peer *peer,
                                wg_allowedips_walk_fn fn, void *ctx)
{
    if (!table || !peer || !fn)
        return;

    pthread_rwlock_rdlock(&table->lock);
    if (trie_walk_by_peer(table->root4, peer, AF_INET, fn, ctx))
        trie_walk_by_peer(table->root6, peer, AF_INET6, fn, ctx);
    pthread_rwlock_unlock(&table->lock);
}
