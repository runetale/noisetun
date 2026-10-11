/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Test: macOS utun device implementation.
 *
 * Requires root or appropriate entitlements.
 * Skips gracefully if utun control socket is not accessible.
 */

#ifdef __APPLE__

#include "wireguard.h"
#include "../src/tun/wg_tun.h"
#include "../src/tun/wg_tun_darwin.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void skip(const char *reason)
{
    printf("SKIP: %s\n", reason);
    exit(0);
}

static void check_permissions(void)
{
    /*
     * Just opening a PF_SYSTEM socket may succeed in sandboxed builds
     * (e.g. nix), but connect() to utun control will fail.
     * Try a full create + destroy to be sure.
     */
    wg_tun_darwin_t *tun = NULL;
    wg_error_t err = wg_tun_darwin_create(&tun, "utun", 1420);
    if (err != WG_OK)
        skip("cannot create utun (need root or entitlements)");
    wg_tun_ops_t ops = wg_tun_darwin_ops(tun);
    ops.close(ops.ctx);
}

/* ────────────────────────────────────────
 * Test: create, query name/MTU, destroy
 * ──────────────────────────────────────── */
static void test_create_destroy(void)
{
    printf("  test_create_destroy... ");

    wg_tun_darwin_t *tun = NULL;
    wg_error_t err = wg_tun_darwin_create(&tun, "utun", 1420);
    assert(err == WG_OK);
    assert(tun != NULL);

    wg_tun_ops_t ops = wg_tun_darwin_ops(tun);
    assert(wg_tun_ops_valid(&ops));

    /* Check name starts with "utun" */
    const char *name = ops.name(ops.ctx);
    assert(name != NULL);
    assert(strncmp(name, "utun", 4) == 0);

    /* Check batch_size */
    assert(ops.batch_size(ops.ctx) == 1);

    /* Check MTU */
    int mtu = ops.mtu(ops.ctx);
    assert(mtu == 1420);

    /* Check events (should be empty initially or have UP) */
    int ev = ops.events(ops.ctx);
    (void)ev; /* events are asynchronous, just verify it doesn't crash */

    /* Close */
    ops.close(ops.ctx);

    printf("OK\n");
}

/* ────────────────────────────────────────
 * Test: ops valid helper
 * ──────────────────────────────────────── */
static void test_ops_valid(void)
{
    printf("  test_ops_valid... ");

    wg_tun_ops_t empty;
    memset(&empty, 0, sizeof(empty));
    assert(!wg_tun_ops_valid(&empty));
    assert(!wg_tun_ops_valid(NULL));

    printf("OK\n");
}

int main(void)
{
    check_permissions();

    printf("test_tun_darwin:\n");
    test_ops_valid();
    test_create_destroy();
    printf("All TUN Darwin tests passed.\n");
    return 0;
}

#else /* !__APPLE__ */

#include <stdio.h>
int main(void)
{
    printf("SKIP: Darwin TUN tests only run on macOS\n");
    return 0;
}

#endif /* __APPLE__ */
