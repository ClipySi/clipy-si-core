# Contributing to clipy-si-core

Thanks for your interest! A few ground rules keep this core trustworthy.

## What this repository is

The shared, cross-platform Rust core for ClipySi: secret detection/masking,
at-rest crypto primitives, the vault passphrase KDF, record/vault formats, and
sync merge decisions. It is published for **transparency, auditability, and
distribution verification**. The Rust / FFI API is an implementation detail of
ClipySi (`0.x`, no stability guarantee) — see the README.

## Invariants (non-negotiable)

- **Pure**: no file/network/clock/RNG access in the core crates.
- **No logging**: never log values or verdicts (no `println!`, `dbg!`, `log`).
- **`forbid(unsafe_code)`** in `clipy-si-core` (generated UniFFI scaffolding is
  isolated in `clipy-si-core-ffi`).
- **KAT vectors are contracts**: `kat/*.json` pins observable behavior across
  every language binding. **Never regenerate a KAT to make a failing test
  pass** — a KAT change is a deliberate, reviewed behavior change and bumps
  `rules_version()` where applicable.

## Detector improvements

The most welcome contributions. Please include, in one PR:

1. The rule change (`src/redaction/`).
2. **New KAT cases** in `kat/redaction.json` covering the new/changed behavior
   (synthetic, format-valid values only — never real credentials).
3. The matching Rust test expectations.

False-positive reports are as valuable as false negatives: masking is ON by
default, so precision matters.

## Building and testing

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo deny check          # advisories / licenses / bans / sources

./build-xcframework.sh    # Swift bindings + XCFramework (macOS)
(cd bindings/swift/ClipySiCore && swift test)   # Swift KAT conformance
```

The toolchain is pinned by `rust-toolchain.toml`; rustup installs it on first
use. The generated Swift glue is committed — CI fails if rebuilding leaves the
tree dirty, so commit the regenerated glue together with FFI changes.

## Security

Do not open public issues for vulnerabilities or reliable detection-evasion
findings — see [SECURITY.md](SECURITY.md) for the private channel and how
reports are triaged.

## Commits

Small, focused commits with imperative subjects. CI must be green
(fmt, clippy `-D warnings`, tests, cargo-deny, Swift KAT).
