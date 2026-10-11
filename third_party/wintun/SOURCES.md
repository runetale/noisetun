# Wintun binaries: provenance

| Item | Value |
|---|---|
| Project | Wintun, https://www.wintun.net/ (WireGuard LLC) |
| Version | 0.14.1 |
| Download | https://www.wintun.net/builds/wintun-0.14.1.zip |
| Zip SHA-256 | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| License | `LICENSE.txt` in this directory (Prebuilt Binaries License, as shipped in the zip) |

The DLLs here are the unmodified files from `wintun/bin/<arch>/wintun.dll` in
that zip, and `include/wintun.h` is `wintun/include/wintun.h` from it.
`SHA256SUMS` lists their digests; CI checks it (`sha256sum -c`). Verified
against a fresh download on 2026-09-26.
