# clipy-si-core

[English](README.md) · **日本語**

ClipySi 向けのクロスプラットフォームな共有 **Rust** コアです。各 OS シェル（現時点では macOS、将来的に Windows / iOS / Android）は、FFI（Swift/Kotlin は UniFFI、.NET は C-ABI + P/Invoke）経由で**同一の実装**を組み込みます。これにより、マスキング・暗号・record/vault フォーマット・同期判定を全プラットフォームで一致させます。

> **状態:** M8-M11 は実装済みで、このリポジトリが共有コアの canonical な private source です。
> macOS アプリは `core/clipy-si-core` に pin した submodule としてこのコアを消費します。

## Invariants

- **Pure** — ファイル / ネットワーク / 時計 / RNG へアクセスしません。決定的で、テストしやすい実装です。
- **No logging** — コアは値や判定結果を一切ログに出しません（呼び出し側も出してはいけません）。
- **Additive compatibility** — public enum は `#[non_exhaustive]`。挙動は `rules_version()` と [`kat/`](kat/) の言語非依存 KAT ベクタで固定します。

## Layout

```text
clipy-si-core/
  Cargo.toml                         # workspace
  kat/{redaction,crypto,kdf,record,sync}.json
                                      # 言語非依存の Known-Answer-Test ベクタ
  crates/clipy-si-core/
    src/{redaction,crypto,kdf,record,sync}/
                                      # pure core logic
    tests/                           # KAT 回帰 + public API unit tests
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

検出は **precision-first**（誤マスクは目に見えるため。マスキングは既定 ON）です。GitHub / OpenAI / AWS / JWT / Slack / Google トークン、private-key block、URL 埋め込みの秘密情報、`key=value` 形式の秘密情報は High confidence として扱います。それ以外の構造を持たない高エントロピー文字列は、長さ + エントロピー + 文字種のヒューリスティックにより Medium confidence として検出します（UUID と hex digest は意図的に除外）。

## Develop

ツールチェーンは rustup で管理されます。`cargo` は toolchain bin にあります。

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                       # KAT + unit
```

Swift XCFramework の再生成と Swift KAT 適合テスト:

```bash
./build-xcframework.sh
cd bindings/swift/ClipySiCore
swift test
```

`bindings/swift/ClipySiCore/ClipySiCoreFFI.xcframework` は生成物なのでコミットしません。
生成された Swift glue
`bindings/swift/ClipySiCore/Sources/ClipySiCore/clipy_si_core_ffi.swift` はコミットします。
CI は XCFramework の再生成後に worktree が汚れないことを確認します。

## Release Assets

`v*` タグで release 用 XCFramework zip を生成し、GitHub Release に
`CHECKSUMS.sha256` と一緒に添付します。このリポジトリが private の間、macOS アプリは
git submodule の SHA pin でコアを固定します。将来 public 化する場合は、release asset と
checksum を使って Swift package を `binaryTarget(url:checksum:)` に切り替えられます。

## Interface Contract

[INTERFACE.md](INTERFACE.md) を参照してください。実行可能なソースコードと KAT ベクタが正本で、
interface 文書は利用側・将来の platform shell 向けの人間可読な契約です。
