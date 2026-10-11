# Embedding noisetun

noisetun is a static library with a C API in `include/wireguard.h`. There are two ways to drive it.

| You have | Use |
|---|---|
| Your own TUN and UDP layers: a mesh client with ICE or relays, a userspace network stack, packet filtering | `wg_device_new(&dev, &tun_ops, &bind_ops, &logger)` with your own `wg_tun_ops_t` and `wg_bind_ops_t`, then `wg_uapi_set` / `wg_uapi_get` and `wg_device_up` |
| Only the TUN fd the platform gave you: Android's `VpnService`, an Apple Network Extension | `wg_tunnel_start(&t, tun_fd, settings, &logger)`, which uses noisetun's own TUN and UDP code |

Both are covered below. The platform notes at the end apply to either.

## Building from source without CMake

`CMakeLists.txt` is the reference build, but nothing in the sources depends on it. A build system that compiles the sources itself, such as a Zig `build.zig`, needs:

- **Sources:** the lines of `sources.txt` whose platform tag matches the target:
  - `all` everywhere
  - `posix` everywhere except Windows
  - `linux` on Linux and Android
  - `apple` on macOS, iOS, tvOS and visionOS
  - `windows` on Windows

  Read the file rather than copying the list, so that added or removed files follow automatically. Each line is `<path> <tag>`; lines that do not start with `src/` are comments.
- **Include paths:** `include/` and `src/`, plus libsodium's headers.
- **Defines:**

  | Target | Define |
  |---|---|
  | Linux (glibc or musl) | `_POSIX_C_SOURCE=200112L` (what CMake uses) or `_GNU_SOURCE` |
  | Android | `_GNU_SOURCE` (bionic declares `cpu_set_t` only with it) |
  | Apple platforms | `_DARWIN_C_SOURCE` |
  | Windows | `WIN32_LEAN_AND_MEAN` and `_WIN32_WINNT=0x0602` |

  Optional:
  - `WG_USE_OPENSSL=1`, with OpenSSL 3 linked, for the OpenSSL AEAD backend.
  - `WG_MEMORY_CONSTRAINED=1` to cap buffer pools on a platform where it is not the default (see Memory below).
  - Nothing else is required. The version is `WG_VERSION` in `wireguard.h`.
- **Language:** C17.
- **Link:**

  | Target | Libraries |
  |---|---|
  | All | libsodium |
  | POSIX | pthreads |
  | Windows | `ws2_32`, `ntdll`, `ole32`, `advapi32`, `synchronization` |
  | MinGW-w64 | also winpthreads, for `clock_gettime` and `nanosleep` (CMake links `libwinpthread.a` statically) |

  With `WG_USE_OPENSSL=1`, also OpenSSL's `libcrypto`.

CI compiles the Linux sources this way, straight from `sources.txt` without CMake, and links a test against them.

## Your own TUN and bind: `wg_device_new`

This is how a mesh VPN client with its own ICE/relay bind and TUN wrapper embeds noisetun: the client owns the sockets and the TUN, and noisetun does the WireGuard part.

- **`wg_tun_ops_t`:** read and write IP packets. On mobile the fd comes from the platform.
- **`wg_bind_ops_t`:** open, send, receive and close.
  - `open(ctx, port)` returns the port it bound (the device keeps it, so UAPI reports it and a rebind reuses it), 0 if the bind has no port of its own, or a negative value on error.
  - Because the bind creates the sockets, it is also where Android's `VpnService.protect()` belongs: call it on each socket before its first send.
- **Configuration:** `wg_uapi_set` / `wg_uapi_get` speak the same text protocol as `wg(8)`.
- **Other calls:**
  - `wg_device_disable_roaming(dev)` keeps peers' configured endpoints on networks where replies come from addresses that cannot be reached back.
  - `wg_logger_default(level)` gives a stderr logger.

## Only a TUN fd: `wg_tunnel_*`

| Call | What it does |
|---|---|
| `wg_tunnel_start(&t, tun_fd, settings, &logger)` | `settings` is a UAPI set body. The tunnel owns `tun_fd` and closes it in `wg_tunnel_stop`, or in `wg_tunnel_start` if starting fails. On Apple platforms the utun fd belongs to the Network Extension, so pass `dup(fd)` if the extension may start the tunnel again. |
| `wg_tunnel_set` / `wg_tunnel_get` | Reconfigure it and read its state. |
| `wg_tunnel_bump_sockets(t)` | Reopen the UDP sockets after a network change, on the same port. |
| `wg_tunnel_socket_fd(t, AF_INET)` / `(t, AF_INET6)` | The sockets, for `VpnService.protect()`. Ask again after a port change or `wg_tunnel_bump_sockets`. |
| `wg_tunnel_disable_roaming(t)` | As `wg_device_disable_roaming`. |
| `wg_tunnel_stop(t)` | Stop the tunnel and close the fd and the sockets. |

## Platform notes

### Memory

A Network Extension on iOS is stopped at about 50 MB. iOS builds therefore bound the data path, as wireguard-go's `queueconstants_ios.go` does (defined in `wg_constants.h`):

- queues of 1024 packets
- at most 1024 packet buffers per direction (a thread that needs one more waits for one to come back)
- 1700-byte buffers, since utun hands over one packet per read and there is no UDP coalescing

Android builds use queues of 1024 and at most 4096 buffers. `WG_MEMORY_CONSTRAINED=1` applies the caps elsewhere; the buffer size stays at 64 KB there, because Linux GSO/GRO needs it.

### iOS

- The SDK has no utun control API, so noisetun cannot create a utun there. `wg_tun_darwin_create` returns `WG_ERR_TUN`, and only the fd path is built.
- The app finds the utun fd the way WireGuardKit does. It looks for the socket whose peer is the `com.apple.net.utun_control` kernel control, calling `getpeername` and `CTLIOCGINFO` on each candidate fd.
- `os_sync_wait_on_address` is used from iOS 17.4 on and checked at run time, so older releases work.

### Android

- Build with the NDK toolchain and `_GNU_SOURCE`.
- Worker threads are not pinned to cores.
- `VpnService.Builder.establish()` gives the TUN; pass `detachFd()`.
