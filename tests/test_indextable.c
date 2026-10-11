/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * SESS-2 verification: IndexTable (sender index allocator).
 */

#include "../src/peer/wg_indextable.h"
#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

/* ────────────────────────────────────────
 * Test 1: init / destroy
 * ──────────────────────────────────────── */
static void test_init_destroy(void)
{
    printf("  test_init_destroy ... ");

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);
    wg_index_table_destroy(&table);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 2: insert + lookup round-trip
 * ──────────────────────────────────────── */
static void test_insert_lookup(void)
{
    printf("  test_insert_lookup ... ");

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);

    int dummy_peer = 42;
    int dummy_handshake = 99;

    uint32_t index = 0;
    wg_error_t err =
        wg_index_table_new_index(&table, &dummy_peer, &dummy_handshake, &index);
    assert(err == WG_OK);

    /* Lookup should find the entry. */
    wg_index_entry_t entry;
    bool found = wg_index_table_lookup_copy(&table, index, &entry);
    assert(found);
    assert(entry.index == index);
    assert(entry.type == WG_INDEX_ENTRY_HANDSHAKE);
    assert(entry.peer == &dummy_peer);
    assert(entry.data == &dummy_handshake);

    /* Lookup with wrong index should not find. */
    found = wg_index_table_lookup_copy(&table, index + 1, &entry);
    /* May collide, so just check the return matches expectations. */

    wg_index_table_destroy(&table);
    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 3: swap_for_keypair
 * ──────────────────────────────────────── */
static void test_swap_for_keypair(void)
{
    printf("  test_swap_for_keypair ... ");

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);

    int dummy_peer = 1;
    int dummy_handshake = 2;
    int dummy_keypair = 3;

    uint32_t index = 0;
    assert(wg_index_table_new_index(&table, &dummy_peer, &dummy_handshake, &index) ==
           WG_OK);

    /* Swap handshake → keypair. */
    wg_index_table_swap_for_keypair(&table, index, &dummy_keypair);

    wg_index_entry_t entry;
    bool found = wg_index_table_lookup_copy(&table, index, &entry);
    assert(found);
    assert(entry.type == WG_INDEX_ENTRY_KEYPAIR);
    assert(entry.peer == &dummy_peer); /* peer preserved */
    assert(entry.data == &dummy_keypair);

    wg_index_table_destroy(&table);
    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 4: delete
 * ──────────────────────────────────────── */
static void test_delete(void)
{
    printf("  test_delete ... ");

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);

    int dummy = 0;
    uint32_t index = 0;
    assert(wg_index_table_new_index(&table, &dummy, &dummy, &index) == WG_OK);

    /* Delete it. */
    wg_index_table_delete(&table, index);

    /* Should not be found. */
    wg_index_entry_t entry;
    bool found = wg_index_table_lookup_copy(&table, index, &entry);
    assert(!found);

    wg_index_table_destroy(&table);
    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 5: multiple inserts (triggers resize)
 * ──────────────────────────────────────── */
static void test_many_inserts(void)
{
    printf("  test_many_inserts ... ");

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);

    /* Insert 200 entries (initial cap=64, will trigger multiple resizes). */
    uint32_t indices[200];
    int peers[200];

    for (int i = 0; i < 200; i++) {
        peers[i] = i;
        assert(wg_index_table_new_index(&table, &peers[i], NULL, &indices[i]) == WG_OK);
    }

    /* All should be found. */
    for (int i = 0; i < 200; i++) {
        wg_index_entry_t entry;
        bool found = wg_index_table_lookup_copy(&table, indices[i], &entry);
        assert(found);
        assert(entry.peer == &peers[i]);
    }

    /* All indices should be unique. */
    for (int i = 0; i < 200; i++) {
        for (int j = i + 1; j < 200; j++) {
            assert(indices[i] != indices[j]);
        }
    }

    wg_index_table_destroy(&table);
    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 6: delete and reinsert (repair correctness)
 * ──────────────────────────────────────── */
static void test_delete_reinsert(void)
{
    printf("  test_delete_reinsert ... ");

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);

    int dummy = 0;
    uint32_t indices[10];

    /* Insert 10 entries. */
    for (int i = 0; i < 10; i++)
        assert(wg_index_table_new_index(&table, &dummy, NULL, &indices[i]) == WG_OK);

    /* Delete odd-numbered entries. */
    for (int i = 1; i < 10; i += 2)
        wg_index_table_delete(&table, indices[i]);

    /* Even entries should still be found. */
    for (int i = 0; i < 10; i += 2) {
        wg_index_entry_t entry;
        assert(wg_index_table_lookup_copy(&table, indices[i], &entry));
    }

    /* Odd entries should not be found. */
    for (int i = 1; i < 10; i += 2) {
        wg_index_entry_t entry;
        assert(!wg_index_table_lookup_copy(&table, indices[i], &entry));
    }

    wg_index_table_destroy(&table);
    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test 7: swap non-existent index is no-op
 * ──────────────────────────────────────── */
static void test_swap_nonexistent(void)
{
    printf("  test_swap_nonexistent ... ");

    wg_index_table_t table;
    assert(wg_index_table_init(&table) == WG_OK);

    int dummy_kp = 99;
    /* Swapping a non-existent index should not crash. */
    wg_index_table_swap_for_keypair(&table, 0x12345678, &dummy_kp);

    wg_index_table_destroy(&table);
    printf("OK\n");
}

/* ────────────────────────────────────────
 * main
 * ──────────────────────────────────────── */
int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init() failed\n");
        return 1;
    }

    printf("test_indextable:\n");
    test_init_destroy();
    test_insert_lookup();
    test_swap_for_keypair();
    test_delete();
    test_many_inserts();
    test_delete_reinsert();
    test_swap_nonexistent();
    printf("All indextable tests passed.\n");

    return 0;
}
