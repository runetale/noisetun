# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

- Preferred: GitHub **private vulnerability reporting** on this repository
  ("Report a vulnerability" under the Security tab). Reports, advisories,
  CVE requests and private fixes all stay inside GitHub.
- Alternative (no GitHub account needed): email **shinta@runetale.com**.

We will agree a disclosure plan with you before anything is published.

## Scope

The userspace WireGuard implementation in this repository (`src/`,
`include/`, `tools/`). The bundled Wintun driver binaries are unmodified
upstream releases (`third_party/wintun/SOURCES.md`); please report Wintun
issues to the WireGuard project.

## Supported versions

Pre-release: only the `main` branch receives fixes.
