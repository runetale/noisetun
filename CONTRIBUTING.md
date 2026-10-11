# Contributing

## Building and testing

See [README.md](README.md) for the build. Before opening a pull request:

- `cmake --build build && (cd build && ctest)` passes.
- The Debug build with AddressSanitizer (default) and with
  `-DWG_TSAN=ON` passes on Linux; CI runs both.
- Code is formatted with clang-format 21 using the repository's
  `.clang-format` (`clang-format --dry-run --Werror --style=file` over
  `src include tests`); CI checks it.

## Platform rules

Platform-specific code is split with `#ifdef __linux__` /
`#ifdef __APPLE__` / `#ifdef _WIN32`. Changes to shared code (structs,
function signatures, the packet path) can affect the Linux hot path: any
change on that path is measured on Linux against `main`, interleaved on the
same host (`scripts/bench_rigorous.sh`), and must not fall below `main`.
Write down what you measured and how in `docs/performance-analysis.md`.

## Pull requests

One change per PR, with a description that says what was wrong, what the
change does, and how it was verified (which tests, which sanitizers, which
measurements). Commit messages follow the same idea.

## Security

Do not report vulnerabilities in issues; see [SECURITY.md](SECURITY.md).
