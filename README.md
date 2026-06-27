# clipy-si-core

**English** · [日本語](README_ja.md)

Shared, cross-platform **Rust** core for ClipySi. Every OS shell (macOS today;
Windows/iOS/Android later) embeds the *same* implementation via FFI (UniFFI for
Swift/Kotlin, C-ABI + P/Invoke for .NET), so redaction, crypto, record/vault
format, and sync decisions stay identical everywhere.

> **Status:** M8-M11 are implemented and this repository is the canonical
> private source for the shared core. The macOS app consumes it as a pinned
> submodule at `core/clipy-si-core`.

## Invariants

- **Pure** — no file/network/clock/RNG access. Deterministic and trivially testable.
- **No logging** — the core never logs values or verdicts (callers must not either).
- **Additive compatibility** — public enums are `#[non_exhaustive]`; behaviour is pinned by
  `rules_version()` and the language-independent KAT vectors in [`kat/`](kat/).

## Layout

```
clipy-si-core/
  Cargo.toml                         # workspace
  kat/{redaction,crypto,kdf,record,sync}.json
                                      # language-independent Known-Answer-Test vectors
  crates/clipy-si-core/
    src/{redaction,crypto,kdf,record,sync}/
                                      # pure core logic
    tests/                           # KAT regression + public-API unit tests
  crates/clipy-si-core-ffi/
                                      # UniFFI binding surface
  bindings/swift/ClipySiCore/
                                      # local SwiftPM package + Swift KAT tests
```

## Public API highlights

```rust
pub fn default_config() -> MaskConfig;                              // enabled=true, style=Full
pub fn detect_secrets(text: &str, config: &MaskConfig) -> Vec<SecretMatch>; // char-indexed spans
pub fn is_secret(text: &str, config: &MaskConfig) -> bool;         // fast yes/no
pub fn mask(text: &str, config: &MaskConfig) -> String;            // style-applied, whole-text
pub fn user_rule_errors(config: &MaskConfig) -> Vec<String>;       // names of uncompilable rules
pub fn rules_version() -> u32;

pub fn local_seal(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CoreError>;
pub fn local_open(key: &[u8], combined: &[u8]) -> Result<Vec<u8>, CoreError>;
pub fn derive_vault_key(passphrase: &str, descriptor: &KdfDescriptor) -> Result<[u8; 32], CoreError>;
pub fn seal_record(vault_key: &[u8], nonce: &[u8], plaintext: &RecordPlaintext) -> Result<Vec<u8>, CoreError>;
pub fn open_record(vault_key: &[u8], body: &[u8]) -> Result<RecordPlaintext, CoreError>;
pub fn merge_decide(local: &LocalState, remote_deleted: bool, remote_hlc: Hlc) -> MergeAction;
```

Detection is **precision-first** (false masks are visible because masking is ON by default):
GitHub/OpenAI/AWS/JWT/Slack/Google tokens, private-key blocks, URL-embedded secrets and
`key=value` secrets are High confidence; a length+entropy+character-class heuristic flags
otherwise-unstructured high-entropy strings at Medium confidence (UUIDs and hex digests are
deliberately excluded).

## Develop

The toolchain is managed by rustup; `cargo` lives in the toolchain bin:

```sh
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                       # KAT + unit
```

To regenerate the Swift XCFramework and run Swift KAT conformance tests:

```sh
./build-xcframework.sh
cd bindings/swift/ClipySiCore
swift test
```

`bindings/swift/ClipySiCore/ClipySiCoreFFI.xcframework` is generated output and
must not be committed. The generated Swift glue in
`bindings/swift/ClipySiCore/Sources/ClipySiCore/clipy_si_core_ffi.swift` is
committed; CI checks that rebuilding the XCFramework does not leave the tree
dirty.

## Release Assets

Tags matching `v*` build a release XCFramework zip and attach it to the GitHub
Release with `CHECKSUMS.sha256`. While this repository remains private, the
macOS app pins the core through a git submodule SHA. If the repository is made
public later, the Swift package can switch to `binaryTarget(url:checksum:)`
using the release asset and checksum.

## Interface Contract

See [INTERFACE.md](INTERFACE.md). The executable source code and the KAT vectors
are the source of truth; the interface document is the human-readable contract
for consumers and future platform shells.
