// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Runetale Inc.

// Emits fixed WireGuard handshake test vectors as a C header. Runs inside a
// wireguard-go tree patched with gen/wireguard-go.patch, which turns the
// handshake's ephemeral keys, timestamp and indices into package variables.

package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/tai64n"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// 2026-01-01T00:00:00Z
var vectorTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// vectorStamp encodes t the way tai64n.stamp does (that function is
// unexported): big-endian 0x400000000000000a+unix seconds, then the
// nanoseconds with the low 24 bits cleared. Checked against tai64n below.
func vectorStamp(t *testing.T, tm time.Time) tai64n.Timestamp {
	const base = uint64(0x400000000000000a)
	const whitenerMask = uint32(0x1000000 - 1)
	var ts tai64n.Timestamp
	binary.BigEndian.PutUint64(ts[:8], base+uint64(tm.Unix()))
	binary.BigEndian.PutUint32(ts[8:], uint32(tm.Nanosecond())&^whitenerMask)
	// tai64n's own decoder must give back the same instant.
	if ts.String() != time.Unix(tm.Unix(), int64(tm.Nanosecond())).String() {
		t.Fatalf("timestamp encoding mismatch: %s", ts.String())
	}
	// And it must order against tai64n.Now() like the wall clock does.
	if tai64n.Now().After(ts) != time.Now().After(tm) {
		t.Fatal("timestamp ordering mismatch with tai64n.Now")
	}
	return ts
}

func label(n int, what string) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("wg-c vector %d %s", n, what)))
}

func clampedKey(n int, what string) NoisePrivateKey {
	k := NoisePrivateKey(label(n, what))
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k
}

func index(n int, what string) uint32 {
	h := label(n, what)
	return binary.BigEndian.Uint32(h[:4])
}

type vector struct {
	name                               string
	initStatic, respStatic             NoisePrivateKey
	initPublic, respPublic             NoisePublicKey
	psk                                NoisePresharedKey
	initEphemeral, respEphemeral       NoisePrivateKey
	timestamp                          tai64n.Timestamp
	initIndex, respIndex               uint32
	initiation                         []byte
	initiationHash, initiationChainKey [32]byte
	response                           []byte
	responseHash, responseChainKey     [32]byte
	sendKey, recvKey                   [32]byte
}

func newVectorDevice(t *testing.T, sk NoisePrivateKey, bind *bindtest.ChannelBind) *Device {
	tun := tuntest.NewChannelTUN()
	dev := NewDevice(tun.TUN(), bind, NewLogger(LogLevelError, ""))
	if err := dev.SetPrivateKey(sk); err != nil {
		t.Fatal(err)
	}
	return dev
}

func marshal(t *testing.T, msg any, size int) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, msg); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != size {
		t.Fatalf("marshalled %d bytes, want %d", buf.Len(), size)
	}
	return buf.Bytes()
}

func makeVector(t *testing.T, n int, name string, withPSK bool) vector {
	v := vector{
		name:          name,
		initStatic:    clampedKey(n, "initiator static"),
		respStatic:    clampedKey(n, "responder static"),
		initEphemeral: clampedKey(n, "initiator ephemeral"),
		respEphemeral: clampedKey(n, "responder ephemeral"),
		timestamp:     vectorStamp(t, vectorTime),
		initIndex:     index(n, "initiator index"),
		respIndex:     index(n, "responder index"),
	}
	if withPSK {
		v.psk = NoisePresharedKey(label(n, "preshared key"))
	}
	v.initPublic = v.initStatic.publicKey()
	v.respPublic = v.respStatic.publicKey()

	// Inject the handshake's randomness and time. Each queue is consumed in
	// handshake order (initiator first); any extra call fails the run.
	ephemerals := []NoisePrivateKey{v.initEphemeral, v.respEphemeral}
	indices := []uint32{v.initIndex, v.respIndex}
	newEphemeralKey = func() (NoisePrivateKey, error) {
		if len(ephemerals) == 0 {
			panic("unexpected ephemeral key request")
		}
		k := ephemerals[0]
		ephemerals = ephemerals[1:]
		return k, nil
	}
	newHandshakeIndex = func() (uint32, error) {
		if len(indices) == 0 {
			panic("unexpected index request")
		}
		i := indices[0]
		indices = indices[1:]
		return i, nil
	}
	handshakeNow = func() tai64n.Timestamp { return v.timestamp }
	defer func() {
		newEphemeralKey = newPrivateKey
		newHandshakeIndex = randUint32
		handshakeNow = tai64n.Now
	}()

	binds := bindtest.NewChannelBinds()
	initDev := newVectorDevice(t, v.initStatic, binds[0].(*bindtest.ChannelBind))
	respDev := newVectorDevice(t, v.respStatic, binds[1].(*bindtest.ChannelBind))
	defer initDev.Close()
	defer respDev.Close()

	// respPeer: the responder as seen by the initiator, and vice versa.
	respPeer, err := initDev.NewPeer(v.respPublic)
	assertNil(t, err)
	initPeer, err := respDev.NewPeer(v.initPublic)
	assertNil(t, err)
	respPeer.handshake.presharedKey = v.psk
	initPeer.handshake.presharedKey = v.psk
	respPeer.Start()
	initPeer.Start()

	// Initiation.
	msg1, err := initDev.CreateMessageInitiation(respPeer)
	assertNil(t, err)
	if msg1.Sender != v.initIndex {
		t.Fatal("initiation sender index not injected")
	}
	v.initiationHash = respPeer.handshake.hash
	v.initiationChainKey = respPeer.handshake.chainKey
	v.initiation = marshal(t, msg1, MessageInitiationSize)
	respPeer.cookieGenerator.AddMacs(v.initiation)
	if !respDev.cookieChecker.CheckMAC1(v.initiation) {
		t.Fatal("responder rejects initiation mac1")
	}

	var in MessageInitiation
	assertNil(t, binary.Read(bytes.NewReader(v.initiation), binary.LittleEndian, &in))
	if p := respDev.ConsumeMessageInitiation(&in); p != initPeer {
		t.Fatal("responder failed to consume initiation")
	}
	assertEqual(t, initPeer.handshake.hash[:], v.initiationHash[:])
	assertEqual(t, initPeer.handshake.chainKey[:], v.initiationChainKey[:])

	// Response.
	msg2, err := respDev.CreateMessageResponse(initPeer)
	assertNil(t, err)
	if msg2.Sender != v.respIndex || msg2.Receiver != v.initIndex {
		t.Fatal("response indices unexpected")
	}
	v.response = marshal(t, msg2, MessageResponseSize)
	initPeer.cookieGenerator.AddMacs(v.response)
	if !initDev.cookieChecker.CheckMAC1(v.response) {
		t.Fatal("initiator rejects response mac1")
	}

	var out MessageResponse
	assertNil(t, binary.Read(bytes.NewReader(v.response), binary.LittleEndian, &out))
	if p := initDev.ConsumeMessageResponse(&out); p != respPeer {
		t.Fatal("initiator failed to consume response")
	}
	v.responseHash = respPeer.handshake.hash
	v.responseChainKey = respPeer.handshake.chainKey
	assertEqual(t, initPeer.handshake.hash[:], v.responseHash[:])
	assertEqual(t, initPeer.handshake.chainKey[:], v.responseChainKey[:])

	KDF2(&v.sendKey, &v.recvKey, v.responseChainKey[:], nil)

	// Complete the session on both sides and check the keys interoperate.
	assertNil(t, respPeer.BeginSymmetricSession())
	assertNil(t, initPeer.BeginSymmetricSession())
	kInit := respPeer.keypairs.current
	kResp := initPeer.keypairs.next.Load()
	if kInit == nil || kResp == nil {
		t.Fatal("session keypairs missing")
	}
	var nonce [12]byte
	ct := kInit.send.Seal(nil, nonce[:], []byte("vector"), nil)
	if _, err := kResp.receive.Open(nil, nonce[:], ct, nil); err != nil {
		t.Fatal("initiator->responder keys do not match")
	}
	ct = kResp.send.Seal(nil, nonce[:], []byte("vector"), nil)
	if _, err := kInit.receive.Open(nil, nonce[:], ct, nil); err != nil {
		t.Fatal("responder->initiator keys do not match")
	}
	if len(ephemerals) != 0 || len(indices) != 0 {
		t.Fatal("injected values not all consumed")
	}
	return v
}

func writeBytes(b *strings.Builder, field string, data []byte) {
	fmt.Fprintf(b, "        .%s = {", field)
	for i, c := range data {
		if i%12 == 0 {
			b.WriteString("\n            ")
		} else {
			b.WriteString(" ")
		}
		fmt.Fprintf(b, "0x%02x,", c)
	}
	b.WriteString("\n        },\n")
}

func emitHeader(vs []vector) string {
	var b strings.Builder
	b.WriteString(`/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Runetale Inc.
 *
 * Generated by tests/vectors/gen/gen.sh from wireguard-go 0.0.20250522
 * with fixed keys, ephemerals, indices and timestamp. Do not edit.
 */
/* clang-format off */
#ifndef WG_NOISE_VECTORS_H
#define WG_NOISE_VECTORS_H
#include <stdint.h>
typedef struct {
    const char *name;
    uint8_t initiator_static_private[32];
    uint8_t initiator_static_public[32];
    uint8_t responder_static_private[32];
    uint8_t responder_static_public[32];
    uint8_t preshared_key[32]; /* all zero: no preshared key */
    uint8_t initiator_ephemeral_private[32];
    uint8_t responder_ephemeral_private[32];
    uint8_t timestamp[12];
    uint32_t initiator_index;
    uint32_t responder_index;
    uint8_t initiation[148]; /* as sent: mac1 set, mac2 zero */
    uint8_t initiation_hash[32];
    uint8_t initiation_chaining_key[32];
    uint8_t response[92]; /* as sent: mac1 set, mac2 zero */
    uint8_t response_hash[32];
    uint8_t response_chaining_key[32];
    uint8_t initiator_send_key[32];
    uint8_t initiator_recv_key[32];
} wg_noise_vector_t;
static const wg_noise_vector_t wg_noise_vectors[] = {
`)
	for _, v := range vs {
		b.WriteString("    {\n")
		fmt.Fprintf(&b, "        .name = %q,\n", v.name)
		writeBytes(&b, "initiator_static_private", v.initStatic[:])
		writeBytes(&b, "initiator_static_public", v.initPublic[:])
		writeBytes(&b, "responder_static_private", v.respStatic[:])
		writeBytes(&b, "responder_static_public", v.respPublic[:])
		writeBytes(&b, "preshared_key", v.psk[:])
		writeBytes(&b, "initiator_ephemeral_private", v.initEphemeral[:])
		writeBytes(&b, "responder_ephemeral_private", v.respEphemeral[:])
		writeBytes(&b, "timestamp", v.timestamp[:])
		fmt.Fprintf(&b, "        .initiator_index = 0x%08xu,\n", v.initIndex)
		fmt.Fprintf(&b, "        .responder_index = 0x%08xu,\n", v.respIndex)
		writeBytes(&b, "initiation", v.initiation)
		writeBytes(&b, "initiation_hash", v.initiationHash[:])
		writeBytes(&b, "initiation_chaining_key", v.initiationChainKey[:])
		writeBytes(&b, "response", v.response)
		writeBytes(&b, "response_hash", v.responseHash[:])
		writeBytes(&b, "response_chaining_key", v.responseChainKey[:])
		writeBytes(&b, "initiator_send_key", v.sendKey[:])
		writeBytes(&b, "initiator_recv_key", v.recvKey[:])
		b.WriteString("    },\n")
	}
	b.WriteString("};\n#endif\n/* clang-format on */\n")
	return b.String()
}

func TestEmitVectors(t *testing.T) {
	path := os.Getenv("WG_VECTORS_OUT")
	if path == "" {
		t.Skip("WG_VECTORS_OUT not set")
	}
	vs := []vector{
		makeVector(t, 1, "psk", true),
		makeVector(t, 2, "no_psk", false),
	}
	if err := os.WriteFile(path, []byte(emitHeader(vs)), 0o644); err != nil {
		t.Fatal(err)
	}
}
