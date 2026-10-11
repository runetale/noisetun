/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2025-2026 Runetale Inc.
 * Copyright (C) 2025-2026 gx14ac
 *
 * Tests for the crypto workers, wg_worker_rtc_send and wg_worker_rtc_recv.
 * Each pops elements from its own SPSC queue, encrypts or decrypts them in
 * place and marks them CRYPTED or DEAD (Two-Level Queue + Atomic State: the
 * sequential sender and receiver pick them up by state).
 */

#include "../src/crypto/wg_crypto.h"
#include "../src/device/wg_device.h"
#include "../src/noise/wg_noise.h"
#include "../src/replay/wg_replay.h"
#include "../src/transport/wg_transport.h"
#include "../src/workers/wg_workers.h"

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS(name) printf("  PASS: %s\n", name)

/* Spin-wait until element state leaves UNCRYPTED. */
/* A worker drops its queue's reference when it is done with an element,
 * so an element pushed straight into a worker queue needs the second
 * reference the producers give it, or the worker frees it under the test. */
#define HOLD_FOR_WORKER(elem) atomic_store(&(elem)->refs, 2)

/* INFLIGHT is not finished either. */
#define WAIT_ELEM(elem)                                                                  \
    do {                                                                                 \
        while (                                                                          \
            !wg_elem_done(atomic_load_explicit(&(elem)->state, memory_order_acquire))) { \
            sched_yield();                                                               \
        }                                                                                \
    } while (0)

/* ────────────────────────────────────────
 * Helpers: set up a keypair with known keys
 * ──────────────────────────────────────── */

static wg_noise_keypair_t *make_keypair(void)
{
    wg_noise_keypair_t *kp = calloc(1, sizeof(*kp));
    assert(kp);
    atomic_init(&kp->refcount, 1);

    /* Generate a random symmetric key for sending/receiving. */
    randombytes_buf(kp->sending_key, sizeof(kp->sending_key));

    /* Receiving = same key (for self-encrypt/decrypt test). */
    memcpy(kp->receiving_key, kp->sending_key, sizeof(kp->receiving_key));
    kp->has_keys = true;
    kp->birthdate_ns = 0;

    atomic_init(&kp->sending_counter, 0);
    wg_replay_counter_init(&kp->receiving_counter);

    kp->local_index = 42;
    kp->remote_index = 99;
    kp->i_am_initiator = true;

    return kp;
}

/* ────────────────────────────────────────
 * Test: outbound element alloc/free
 * ──────────────────────────────────────── */
static void test_outbound_elem_lifecycle(void)
{
    wg_outbound_elem_t *e = wg_outbound_elem_new();
    assert(e != NULL);
    wg_outbound_elem_free(e);
    PASS("outbound_elem_lifecycle");
}

/* ────────────────────────────────────────
 * Test: inbound element alloc/free
 * ──────────────────────────────────────── */
static void test_inbound_elem_lifecycle(void)
{
    wg_inbound_elem_t *e = wg_inbound_elem_new();
    assert(e != NULL);
    assert(e->ok == false);
    wg_inbound_elem_free(e);
    PASS("inbound_elem_lifecycle");
}

/* ────────────────────────────────────────
 * Helpers: run one crypto worker as wg_device_up does
 * ──────────────────────────────────────── */

static void start_send_worker(wg_device_t *dev, wg_rtc_send_worker_t *w)
{
    memset(w, 0, sizeof(*w));
    assert(wg_spsc_init(&w->queue, 64) == WG_OK);
    w->dev = dev;
    assert(pthread_create(&w->thread, NULL, wg_worker_rtc_send, w) == 0);
    w->started = true;
}

static void stop_send_worker(wg_rtc_send_worker_t *w)
{
    /* Closing the queue ends the worker's blocking pop. */
    wg_spsc_close(&w->queue);
    pthread_join(w->thread, NULL);
    wg_spsc_destroy(&w->queue);
}

static void start_recv_worker(wg_device_t *dev, wg_rtc_recv_worker_t *w)
{
    memset(w, 0, sizeof(*w));
    assert(wg_spsc_init(&w->queue, 64) == WG_OK);
    w->dev = dev;
    assert(pthread_create(&w->thread, NULL, wg_worker_rtc_recv, w) == 0);
    w->started = true;
}

static void stop_recv_worker(wg_rtc_recv_worker_t *w)
{
    wg_spsc_close(&w->queue);
    pthread_join(w->thread, NULL);
    wg_spsc_destroy(&w->queue);
}

/* ────────────────────────────────────────
 * Test: send worker encrypts an element
 * ──────────────────────────────────────── */
static void test_encryption_worker(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_rtc_send_worker_t enc;
    start_send_worker(dev, &enc);

    wg_noise_keypair_t *kp = make_keypair();

    wg_outbound_elem_t *elem = wg_outbound_elem_new();
    assert(elem);
    const char *plaintext = "Hello, WireGuard!";
    size_t pt_len = strlen(plaintext);
    memcpy(elem->buffer + WG_MESSAGE_TRANSPORT_HEADER, plaintext, pt_len);
    elem->packet_len = pt_len;
    elem->nonce = 0;
    elem->keypair = wg_noise_keypair_get(kp);
    elem->peer = NULL;
    atomic_store_explicit(&elem->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);

    HOLD_FOR_WORKER(elem);
    assert(wg_spsc_try_push(&enc.queue, elem) == WG_OK);
    WAIT_ELEM(elem);

    assert(atomic_load(&elem->state) == WG_ELEM_CRYPTED);
    assert(elem->packet_len > WG_MESSAGE_TRANSPORT_HEADER);

    /* Verify transport header. */
    wg_message_transport_t *hdr = (wg_message_transport_t *)elem->buffer;
    assert(wg_le32toh(hdr->header.type) == WG_MESSAGE_TRANSPORT);
    assert(wg_le32toh(hdr->receiver_index) == kp->remote_index);
    assert(wg_le64toh(hdr->counter) == 0);

    wg_outbound_elem_free(elem);
    wg_noise_keypair_put(kp);

    stop_send_worker(&enc);
    wg_device_close(dev);
    PASS("encryption_worker");
}

/* ────────────────────────────────────────
 * Test: receive worker decrypts an element
 * ──────────────────────────────────────── */
static void test_decryption_worker(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_rtc_recv_worker_t dec;
    start_recv_worker(dev, &dec);

    wg_noise_keypair_t *kp = make_keypair();

    /* Encrypt some data to get valid ciphertext. */
    const char *plaintext = "Test decryption!";
    size_t pt_len = strlen(plaintext);
    uint8_t enc_buf[WG_MAX_MESSAGE_SIZE];
    size_t enc_len = 0;
    assert(wg_transport_encrypt(kp, enc_buf, &enc_len, sizeof(enc_buf),
                                (const uint8_t *)plaintext, pt_len) == WG_OK);

    wg_inbound_elem_t *elem = wg_inbound_elem_new();
    assert(elem);
    memcpy(elem->buffer, enc_buf, enc_len);
    elem->packet_len = enc_len;
    elem->keypair = wg_noise_keypair_get(kp);
    elem->peer = NULL;
    atomic_store_explicit(&elem->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);

    HOLD_FOR_WORKER(elem);
    assert(wg_spsc_try_push(&dec.queue, elem) == WG_OK);
    WAIT_ELEM(elem);

    assert(atomic_load(&elem->state) == WG_ELEM_CRYPTED);
    assert(elem->ok == true);
    assert(elem->plaintext_len == pt_len);

    uint8_t *decrypted = elem->buffer + WG_MESSAGE_TRANSPORT_HEADER;
    assert(memcmp(decrypted, plaintext, pt_len) == 0);

    wg_inbound_elem_free(elem);
    wg_noise_keypair_put(kp);

    stop_recv_worker(&dec);
    wg_device_close(dev);
    PASS("decryption_worker");
}

/* ────────────────────────────────────────
 * Test: send worker → receive worker round trip
 * ──────────────────────────────────────── */
static void test_encrypt_decrypt_roundtrip(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_rtc_send_worker_t enc;
    wg_rtc_recv_worker_t dec;
    start_send_worker(dev, &enc);
    start_recv_worker(dev, &dec);

    wg_noise_keypair_t *kp = make_keypair();

    const char *msg = "Round trip test data payload!";
    size_t msg_len = strlen(msg);

    wg_outbound_elem_t *out_elem = wg_outbound_elem_new();
    assert(out_elem);
    memcpy(out_elem->buffer + WG_MESSAGE_TRANSPORT_HEADER, msg, msg_len);
    out_elem->packet_len = msg_len;
    out_elem->nonce = 0;
    out_elem->keypair = wg_noise_keypair_get(kp);
    atomic_store_explicit(&out_elem->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);

    HOLD_FOR_WORKER(out_elem);
    assert(wg_spsc_try_push(&enc.queue, out_elem) == WG_OK);
    WAIT_ELEM(out_elem);
    assert(out_elem->packet_len > 0);

    /* Decrypt the encrypted output. */
    wg_inbound_elem_t *in_elem = wg_inbound_elem_new();
    assert(in_elem);
    memcpy(in_elem->buffer, out_elem->buffer, out_elem->packet_len);
    in_elem->packet_len = out_elem->packet_len;
    in_elem->keypair = wg_noise_keypair_get(kp);
    atomic_store_explicit(&in_elem->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);

    wg_outbound_elem_free(out_elem);

    HOLD_FOR_WORKER(in_elem);
    assert(wg_spsc_try_push(&dec.queue, in_elem) == WG_OK);
    WAIT_ELEM(in_elem);

    assert(in_elem->ok == true);
    assert(in_elem->plaintext_len >= msg_len);
    uint8_t *decrypted = in_elem->buffer + WG_MESSAGE_TRANSPORT_HEADER;
    assert(memcmp(decrypted, msg, msg_len) == 0);

    wg_inbound_elem_free(in_elem);
    wg_noise_keypair_put(kp);

    stop_send_worker(&enc);
    stop_recv_worker(&dec);
    wg_device_close(dev);
    PASS("encrypt_decrypt_roundtrip");
}

/* ────────────────────────────────────────
 * Test: receive worker marks corrupted data DEAD
 * ──────────────────────────────────────── */
static void test_decryption_bad_data(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_rtc_recv_worker_t dec;
    start_recv_worker(dev, &dec);

    wg_noise_keypair_t *kp = make_keypair();

    const char *plaintext = "Will be corrupted";
    size_t pt_len = strlen(plaintext);
    uint8_t enc_buf[WG_MAX_MESSAGE_SIZE];
    size_t enc_len = 0;
    assert(wg_transport_encrypt(kp, enc_buf, &enc_len, sizeof(enc_buf),
                                (const uint8_t *)plaintext, pt_len) == WG_OK);

    /* Corrupt the ciphertext. */
    enc_buf[WG_MESSAGE_TRANSPORT_HEADER + 5] ^= 0xFF;

    wg_inbound_elem_t *elem = wg_inbound_elem_new();
    assert(elem);
    memcpy(elem->buffer, enc_buf, enc_len);
    elem->packet_len = enc_len;
    elem->keypair = wg_noise_keypair_get(kp);
    atomic_store_explicit(&elem->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);

    HOLD_FOR_WORKER(elem);
    assert(wg_spsc_try_push(&dec.queue, elem) == WG_OK);
    WAIT_ELEM(elem);

    assert(atomic_load(&elem->state) == WG_ELEM_DEAD);
    assert(elem->ok == false);
    assert(elem->plaintext_len == 0);

    wg_inbound_elem_free(elem);
    wg_noise_keypair_put(kp);

    stop_recv_worker(&dec);
    wg_device_close(dev);
    PASS("decryption_bad_data");
}

/* ────────────────────────────────────────
 * Test: send worker handles a batch of elements
 * ──────────────────────────────────────── */
static void test_encryption_multiple(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_rtc_send_worker_t enc;
    start_send_worker(dev, &enc);

    wg_noise_keypair_t *kp = make_keypair();
    enum { N = 10 };

    wg_outbound_elem_t *elems[N];
    for (int i = 0; i < N; i++) {
        elems[i] = wg_outbound_elem_new();
        assert(elems[i]);
        char msg[32];
        int len = snprintf(msg, sizeof(msg), "Packet %d", i);
        memcpy(elems[i]->buffer + WG_MESSAGE_TRANSPORT_HEADER, msg, (size_t)len);
        elems[i]->packet_len = (size_t)len;
        elems[i]->nonce = (uint64_t)i;
        elems[i]->keypair = wg_noise_keypair_get(kp);
        atomic_store_explicit(&elems[i]->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);
    }

    for (int i = 0; i < N; i++)
        HOLD_FOR_WORKER(elems[i]);
    int pushed = wg_spsc_try_push_batch(&enc.queue, (void **)elems, N);
    assert(pushed == N);

    for (int i = 0; i < N; i++)
        WAIT_ELEM(elems[i]);

    for (int i = 0; i < N; i++) {
        assert(atomic_load(&elems[i]->state) == WG_ELEM_CRYPTED);
        assert(elems[i]->packet_len > 0);
    }

    for (int i = 0; i < N; i++)
        wg_outbound_elem_free(elems[i]);
    wg_noise_keypair_put(kp);

    stop_send_worker(&enc);
    wg_device_close(dev);
    PASS("encryption_multiple");
}

/* ────────────────────────────────────────
 * Test: a crypto worker and a "sequential thread" contend for the same
 * elements (#63). Each element is pushed into the worker's queue with
 * the two references a producer gives it, and this thread then claims
 * it the way the sequential thread does and drops its reference at
 * once. Exactly one side must do the crypto, and the element must stay
 * alive until the worker has popped it: the bug TSan caught was the
 * worker claiming an element that had already been freed and recycled.
 * ASan turns a lost reference into a use-after-free here.
 * ──────────────────────────────────────── */
#if WG_SEQ_INLINE
static void test_claim_contention(void)
{
    wg_device_t *dev = NULL;
    assert(wg_device_new(&dev, NULL, NULL, NULL) == WG_OK);

    wg_rtc_send_worker_t enc;
    start_send_worker(dev, &enc);

    wg_noise_keypair_t *kp = make_keypair();
    enum { N = 4000 };
    uint64_t claimed_here = 0;

    for (int i = 0; i < N; i++) {
        wg_outbound_elem_t *elem = wg_outbound_elem_new();
        assert(elem);
        elem->packet_len = 64;
        elem->nonce = (uint64_t)i;
        elem->keypair = wg_noise_keypair_get(kp);
        atomic_store_explicit(&elem->state, WG_ELEM_UNCRYPTED, memory_order_relaxed);
        HOLD_FOR_WORKER(elem);

        /* Three shapes: claim before the worker can see it, race it, and
         * let the worker go first. */
        bool claim_first = (i % 3 == 0);
        if (claim_first && wg_elem_claim(&elem->state)) {
            atomic_store_explicit(&elem->state, WG_ELEM_CRYPTED, memory_order_release);
            claimed_here++;
        }
        while (wg_spsc_try_push(&enc.queue, elem) != WG_OK)
            sched_yield();
        if (i % 3 == 2)
            sched_yield();
        if (!claim_first && wg_elem_claim(&elem->state)) {
            atomic_store_explicit(&elem->state, WG_ELEM_CRYPTED, memory_order_release);
            claimed_here++;
        }
        /* The order queue's reference: the worker may not have popped
         * the element yet, so this must not free it. */
        wg_outbound_elem_free(elem);
    }

    /* Closing the queue lets the worker drain what is left, then exit. */
    stop_send_worker(&enc);

    uint64_t by_worker = atomic_load(&dev->stats.encrypt_count);
    assert(claimed_here + by_worker == N); /* each element exactly once */
    assert(claimed_here >= N / 3);         /* the claim-first third */

    wg_noise_keypair_put(kp);
    wg_device_close(dev);
    PASS("claim_contention");
}
#endif

/* ────────────────────────────────────────
 * Main
 * ──────────────────────────────────────── */

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    wg_noise_module_init();

    printf("=== test_workers ===\n");

    test_outbound_elem_lifecycle();
    test_inbound_elem_lifecycle();
    test_encryption_worker();
    test_decryption_worker();
    test_encrypt_decrypt_roundtrip();
    test_decryption_bad_data();
    test_encryption_multiple();
#if WG_SEQ_INLINE
    test_claim_contention();
#endif

    printf("All worker tests passed.\n");
    return 0;
}
