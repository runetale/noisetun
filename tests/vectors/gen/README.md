# Handshake vectors from wireguard-go

`../wg_noise_vectors.h` holds fixed WireGuard handshake vectors produced by
wireguard-go 0.0.20250522, so the C handshake can be checked byte for byte
against an independent implementation.

Each vector runs a full handshake between two wireguard-go devices (channel
TUN and channel bind, no sockets or root) with fixed static keys, ephemeral
keys, sender indices, timestamp (2026-01-01T00:00:00Z) and, for the `psk`
vector, a preshared key. All fixed bytes are SHA-256 of labels such as
`wg-c vector 1 initiator static`, clamped for X25519 where they are private
keys. The header records the messages as sent (mac1 set, mac2 zero), the hash
and chaining key after each message, and the transport keys.

`tests/test_noise_vectors.c` replays them through wg-c's handshake with the
same fixed inputs and compares every message, intermediate hash and chaining
key, and transport key.

## Regenerate

    ./gen.sh [path/to/wireguard-go] [output.h]

Without a path the script clones wireguard-go 0.0.20250522 from
https://git.zx2c4.com/wireguard-go. The output path may also be given as
`WG_VECTORS_OUT`; it defaults to `../wg_noise_vectors.h`. The script copies
the wireguard-go tree to a temporary directory, applies `wireguard-go.patch`,
copies `vectors_test.go` into `device/`, and runs
`go test -run TestEmitVectors ./device/`. Output is deterministic: two runs
produce identical headers.

## The patch

`wireguard-go.patch` only makes the handshake's sources of randomness and time
replaceable. It adds three package-level variables in `device`:

- `newEphemeralKey` (default `newPrivateKey`), used where
  `CreateMessageInitiation` and `CreateMessageResponse` create ephemeral keys;
- `handshakeNow` (default `tai64n.Now`), used for the initiation timestamp;
- `newHandshakeIndex` (default `randUint32`), used by `NewIndexForHandshake`.

The defaults are the original functions, so behaviour is unchanged unless a
test overrides them. No protocol code is touched.

wireguard-go's `tai64n` package keeps its encoder private, so
`vectors_test.go` encodes the fixed timestamp itself with the same constants
and checks the result against `tai64n`'s decoder and ordering.

The patch quotes lines of wireguard-go, which is distributed under the MIT
License (see NOTICE).
