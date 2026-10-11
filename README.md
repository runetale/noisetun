# noisetun

noisetun is a userspace implementation of the
[WireGuard](https://www.wireguard.com/) protocol in C. It comes in two
forms:

- **A library** with a C API (`include/wireguard.h`) that an application
  links in, with the TUN device and the UDP transport supplied by the
  application if it wants. This is what it was written for.
- **A daemon**, `wg-c`, that speaks the same cross-platform UAPI as
  wireguard-go, so it is configured with the usual
  [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8).

"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A.
Donenfeld. noisetun is not affiliated with or endorsed by the WireGuard
project.

**Status: pre-release.** It has not had a security audit yet; see
[SECURITY.md](SECURITY.md).

## Why a userspace library

Mesh VPN clients do more than move packets between a TUN device and a
UDP socket. They decide per packet whether it goes straight to a peer or
through a relay, share the WireGuard port with NAT traversal probes, and
on some platforms run without a TUN device at all, handing packets to a
userspace network stack. None of this fits the kernel module
([wireguard-linux](https://github.com/WireGuard/wireguard-linux)): it owns
its UDP socket and always creates a network interface, it exists only on
Linux, and it cannot be linked into an app on macOS, iOS, Android or
Windows.

noisetun is built for these clients, written in C, C++, Zig, Rust or
anything else with a C FFI, and needs no Go runtime:

- **Your own transport:** `wg_bind_ops_t` replaces the UDP layer, so the
  client can send WireGuard packets over direct UDP, a relay, or anything
  else, and choose per peer.
- **Your own TUN:** `wg_tun_ops_t` replaces the TUN device, for example
  with a userspace TCP/IP stack, or with packet filtering in between.
- **Or just a fd:** `wg_tunnel_start` takes the TUN fd that Android's
  `VpnService` or an Apple Network Extension hands over and uses the
  library's own TUN and UDP code.
- **Configuration** is the `wg(8)` text protocol (`wg_uapi_set` /
  `wg_uapi_get`), the same as wireguard-go's.
- **License:** Apache-2.0, so it can ship inside proprietary apps;
  wireguard-linux is GPL-2.0.

See [docs/embedding.md](docs/embedding.md) for the API and the build
without CMake.

## Using the daemon

Create an interface and run the daemon:

```
$ sudo wg-c wg0
```

This creates the interface and forks into the background. To remove it, use
the usual `ip link del wg0` (`ifconfig utunN destroy` on macOS), or remove
the control socket with `rm -f /var/run/wireguard/wg0.sock`; wg-c shuts down
either way. To stay in the foreground, pass `-f` or `--foreground` (or set
`WG_PROCESS_FOREGROUND=1`); `SIGINT` and `SIGTERM` stop it. The command
line and these behaviors are the same as wireguard-go's.

While it runs, configure it with `wg(8)` and bring the interface up with the
usual `ip(8)` or `ifconfig(8)` commands:

```
$ sudo wg set wg0 private-key ./private listen-port 51820 \
      peer <public-key> endpoint 203.0.113.1:51820 allowed-ips 10.0.0.2/32
$ sudo ip address add 10.0.0.1/24 dev wg0
$ sudo ip link set wg0 up
```

The stock `wg-quick(8)` works with wg-c as its userspace implementation:

```
$ sudo WG_QUICK_USERSPACE_IMPLEMENTATION=wg-c wg-quick up wg0
```

On Linux there is also `wg-quick-c up|down <config>`, which does the same
without the shell script. PreUp and SaveConfig are not implemented there.

Environment variables:

- `LOG_LEVEL`: `verbose` (or `debug`), `error` (default), `silent`.
- `WG_TUN_FD`, `WG_UAPI_FD`: use an already open TUN device or UAPI socket.
- `WG_TUN_NAME_FILE` (macOS): with the interface name `utun`, write the name
  the kernel picked to this file.
- `WG_STATS_INTERVAL=<seconds>`: print data path statistics to stderr
  periodically (on Linux and macOS also on `SIGUSR1`).

## Platforms

### Linux

The UAPI socket is `/var/run/wireguard/<name>.sock`. The data path uses
TUN offloads (GSO/GRO), `sendmmsg`/`recvmmsg` with UDP GSO, and runs
encryption and decryption on worker threads. Where the kernel has
WireGuard built in you may prefer it; wg-c is for systems where the kernel
module is not available or not wanted.

### macOS

This runs on macOS using the utun driver. The interface name must be
`utun[0-9]+`, or `utun` to have the kernel pick one (see
`WG_TUN_NAME_FILE` above). Because utun hands over
one packet per read, the data path runs on one thread in each direction.

### Windows

This runs on Windows using [Wintun](https://www.wintun.net/) and Registered
I/O sockets. Run it as Administrator; `wintun.dll` must sit next to
`wg-c.exe`. The UAPI is the named pipe
`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\<name>`, as in
wireguard-go, so `wg.exe` from the WireGuard for Windows installation can
configure it.

## Performance

Measured on the same host against wireguard-go v0.0.20250522, iperf3 over
the tunnel (2026-09-26):

| Host | wg-c vs wireguard-go |
|---|---|
| AWS c6i.2xlarge, x86-64, Linux 7.0 | 104–106% (two runs) |
| AWS c7g.2xlarge, Graviton3, Linux 7.0 | about 120% |
| Apple M5 Max, macOS 26.4 | 108%, at about half the CPU |
| Windows 11 ARM64 VM, 4 vCPU | 98% (level) |

Method and every experiment, including the ones that failed:
[docs/performance-analysis.md](docs/performance-analysis.md). Current summary:
[docs/OPTIMIZATION_STATUS.md](docs/OPTIMIZATION_STATUS.md). Design differences
from wireguard-go: [docs/wg-c-vs-wg-go.md](docs/wg-c-vs-wg-go.md).

## Building

Requirements: CMake 3.16 or newer, a C17 compiler, libsodium, and OpenSSL 3
for the default AEAD backend (`-DWG_USE_OPENSSL=OFF` uses libsodium only).

```
$ git clone https://github.com/runetale/noisetun
$ cd noisetun
$ cmake -B build -DCMAKE_BUILD_TYPE=Release
$ cmake --build build -j
```

The daemon is `build/tools/wg-c`. Options: `WG_BUILD_TESTS` (on),
`WG_BUILD_BENCH`, `WG_BUILD_FUZZ` (Clang), `WG_ASAN` / `WG_TSAN` (Debug
builds), `WG_USE_OPENSSL` (on), `WG_USE_IO_URING`.

To embed the library in an app (Android, an iOS or macOS Network
Extension) or compile it from another build system, see
[docs/embedding.md](docs/embedding.md). The list of sources per platform is
`sources.txt`.

Windows: build with MSVC using `build_wgc.bat`, or cross-compile from Linux
with `-DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64.cmake`. The Wintun binaries in
`third_party/wintun` are unmodified upstream releases; their provenance and
checksums are in `third_party/wintun/SOURCES.md`.

## Testing

```
$ cd build && ctest
```

Debug builds enable AddressSanitizer and UBSan; `-DWG_TSAN=ON` builds with
ThreadSanitizer. Some tests need root (TUN, network namespaces). CI runs the
full suite on Linux x86-64 and arm64 under ASan and TSan, and builds Windows
arm64 and x64 with MSVC, running the 10 tests that do not need POSIX
headers. macOS has no CI. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The Wintun
binaries are under their own license (`third_party/wintun/LICENSE.txt`), and
`wintun.h` is GPL-2.0 OR MIT.
