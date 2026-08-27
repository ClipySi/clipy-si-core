# Security Policy

`clipy-si-core` is the shared Rust core of [ClipySi](https://github.com/ClipySi/clipy-si-macos),
a clipboard manager. The core implements secret detection/masking, the at-rest
crypto primitives (AES-GCM seal/open, HMAC content hashing), the vault
passphrase KDF, the record/vault formats, and sync merge decisions. Because the
app can observe and store **everything a user copies**, we treat reports about
this code with high priority.

## Reporting

**Please do not open a public issue for security vulnerabilities.**
Use GitHub's [private vulnerability reporting](https://github.com/ClipySi/clipy-si-core/security/advisories/new)
on this repository, or the app repository's
[reporting channel](https://github.com/ClipySi/clipy-si-macos/security/advisories/new) —
either is fine; we coordinate fixes across both.

Please **do not include real secrets** in a report — use clearly fake,
format-valid placeholder values (the style used throughout `kat/` and the
detector tests).

## How reports are triaged

We classify reports by **impact and reproducibility**, not by which component
they touch. Detection-evasion reports are *not* uniformly treated as
low-severity:

1. **Ordinary detector gaps** — an unsupported credential format, a false
   positive, or a false negative on organically occurring text: open a normal
   issue. These feed the KAT-driven improvement loop.
2. **Deliberate, reproducible evasion of a major credential format** — a
   transformation that reliably makes a mainstream token format (GitHub, AWS,
   Slack, JWT, private-key blocks, …) evade detection while remaining valid:
   report privately first.
3. **Core security failures** — plaintext persisted where encryption is
   promised, seal/open or KDF producing weak or wrong results, key material
   exposure, memory-safety issues at the FFI boundary: report privately as a
   vulnerability.

## Scope notes

- Masking is a **display-layer** defense on top of privacy-marker respect and
  at-rest encryption; the threat model and layering are described in the app's
  [security-guidance.md](https://github.com/ClipySi/clipy-si-macos/blob/main/security-guidance.md)
  and DESIGN.md §4.9.
- The KAT vectors in `kat/` are compatibility contracts. A report that a KAT
  value is *wrong* (not merely inconvenient) is security-relevant — see class 3.
- The core is pure logic: no I/O, no logging, no RNG. Reports about the host
  app's key storage, pasteboard capture, or update channel belong on the
  [app repository](https://github.com/ClipySi/clipy-si-macos/blob/main/SECURITY.md).

## Supported versions

Only the **latest released core version** (and the app release that embeds it)
receives security fixes.

## Disclosure process

1. We acknowledge your report as soon as we can (typically within a few days).
2. We investigate, develop a fix, and validate it against the KAT suite.
3. We publish a new core release (and an app release when user-facing) and a
   GitHub Security Advisory crediting the reporter (unless you prefer to
   remain anonymous).
