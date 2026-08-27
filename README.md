# clipy-si-core

**English** · [日本語](README_ja.md)

Shared, cross-platform **Rust** core for [ClipySi](https://github.com/ClipySi/clipy-si-macos).
Every OS shell (macOS today; Windows/iOS/Android later) embeds the *same*
implementation via FFI (UniFFI for Swift/Kotlin, C-ABI + P/Invoke for .NET), so
redaction, crypto, record/vault format, and sync decisions stay identical
everywhere.

> **Why this is public.** ClipySi's core claim is privacy-first, and a
> privacy-first app should not ask users to trust an unverifiable binary. This
> repository exists for **transparency, auditability, and distribution
> verification**: you can read the detection rules, review the crypto, rebuild
> the binary, and check the provenance of every released artifact.
>
> **API stability**: the Rust / FFI API is an implementation detail of ClipySi
> (`0.x`, no compatibility guarantee). Issues and PRs are welcome — see
> [CONTRIBUTING.md](CONTRIBUTING.md) — but the public contract is the KAT
> vectors, not the function signatures.

## What lives here

| Domain | Module | Notes |
| --- | --- | --- |
| Secret detection & display masking | `src/redaction/` | precision-first rules + entropy heuristic; `detect_secrets` / `is_secret` / `mask` / one-pass `evaluate` |
| At-rest crypto primitives | `src/crypto/` | AES-GCM seal/open (CryptoKit-wire-compatible), keyed HMAC content hashing |
| Vault passphrase KDF | `src/kdf/` | PBKDF2-HMAC-SHA256 over the NFC-normalised passphrase |
| Record/vault formats | `src/record/` | record envelope & vault manifest encoding/decoding |
| Sync decisions | `src/sync/` | content hashes, HLC helpers, merge/rejoin/stale-device rules |
| Known-Answer Tests | `kat/` | **5 language-independent vector files** — the compatibility contract |

Key management (Keychain, ThisDeviceOnly) and nonce generation (CSPRNG) stay in
the platform shells: the core is **pure** — no file/network/clock/RNG access,
no logging, `forbid(unsafe_code)`.

## Invariants

- **Pure & deterministic** — trivially testable, KAT-pinned.
- **No logging** — the core never logs values or verdicts (callers must not either).
- **Additive compatibility** — public enums are `#[non_exhaustive]`; behaviour is
  pinned by `rules_version()` and the KAT vectors in [`kat/`](kat/).

## Develop

The toolchain is pinned by [`rust-toolchain.toml`](rust-toolchain.toml); rustup
installs it (with components and targets) on first use.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked          # KAT + unit
cargo deny check             # advisories / licenses / bans / sources
```

To regenerate the Swift XCFramework and run Swift KAT conformance tests:

```sh
./build-xcframework.sh
cd bindings/swift/ClipySiCore
swift test
```

`bindings/swift/ClipySiCore/ClipySiCoreFFI.xcframework` is generated output and
must not be committed. The generated Swift glue in
`bindings/swift/ClipySiCore/Sources/ClipySiCore/clipy_si_core_ffi.swift` **is**
committed; CI checks that rebuilding leaves the tree clean.

## Releases and how to verify them

Tags matching `v*` run a gated pipeline (fmt / clippy / tests / cargo-deny →
XCFramework build → Swift KAT → provenance attestation → draft release). The
macOS app consumes the published asset via SwiftPM
`binaryTarget(url:checksum:)`.

Three distinct guarantees, in increasing order — know which one you are getting:

1. **Checksum** (SwiftPM pin): the downloaded zip is byte-identical to the one
   the app author pinned. Says nothing about where it came from.
2. **Provenance attestation** (current): the asset was built by this
   repository's release workflow from a specific tag/commit — verifiable by
   anyone:

   ```sh
   TAG=vX.Y.Z
   git fetch --no-tags origin main
   TAG_SHA=$(git rev-list -n1 "$TAG")
   gh attestation verify ClipySiCoreFFI.xcframework.zip \
     --repo ClipySi/clipy-si-core \
     --signer-workflow ClipySi/clipy-si-core/.github/workflows/release.yml \
     --source-ref "refs/tags/$TAG" \
     --source-digest "$TAG_SHA" \
     --deny-self-hosted-runners
   git merge-base --is-ancestor "$TAG_SHA" origin/main && echo "tag is on main"
   ```

3. **Reproducible build** (future work): a third party regenerates the exact
   bytes. Not yet claimed — the zip step (`ditto`) is not deterministic today.

Each release's notes record the source tag, commit, rustc and Xcode versions,
runner image, targets, and both checksums. Published releases are immutable: a
broken release means a new version, never a re-upload.

## Interface Contract

See [INTERFACE.md](INTERFACE.md). The executable source code and the KAT vectors
are the source of truth; the interface document is the human-readable contract
for consumers and future platform shells.

## Security

See [SECURITY.md](SECURITY.md) — including how detection-evasion reports are
triaged (they are not uniformly "low severity").

## License

[MIT](LICENSE).
