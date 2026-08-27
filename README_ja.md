# clipy-si-core

[English](README.md) · **日本語**

[ClipySi](https://github.com/ClipySi/clipy-si-macos) 向けのクロスプラットフォームな共有 **Rust** コアです。各 OS シェル（現時点では macOS、将来的に Windows / iOS / Android）は、FFI（Swift/Kotlin は UniFFI、.NET は C-ABI + P/Invoke）経由で**同一の実装**を組み込みます。これにより、マスキング・暗号・record/vault フォーマット・同期判定を全プラットフォームで一致させます。

> **公開の位置づけ。** ClipySi の中核的な主張は privacy-first であり、privacy-first を名乗るアプリが検証不能なバイナリへの信頼をユーザーに求めるべきではありません。このリポジトリは**透明性・監査可能性・配布物の検証**のために公開されています: 検出ルールを読み、暗号実装をレビューし、バイナリを再ビルドし、リリース資産の来歴を検証できます。
>
> **API の安定性**: Rust / FFI API は当面 ClipySi の実装詳細です（`0.x`・互換性保証なし）。Issue / PR は歓迎します（[CONTRIBUTING.md](CONTRIBUTING.md) 参照）が、公開契約は関数シグネチャではなく KAT ベクタです。

## 何が入っているか

| ドメイン | モジュール | 備考 |
| --- | --- | --- |
| 秘密検出・表示マスキング | `src/redaction/` | precision-first のルール + エントロピーヒューリスティック。`detect_secrets` / `is_secret` / `mask` / ワンパス `evaluate` |
| 保存時暗号プリミティブ | `src/crypto/` | AES-GCM seal/open（CryptoKit とワイヤ互換）・keyed HMAC content hash |
| vault パスフレーズ KDF | `src/kdf/` | NFC 正規化したパスフレーズへの PBKDF2-HMAC-SHA256 |
| record/vault フォーマット | `src/record/` | record エンベロープ・vault マニフェストのエンコード/デコード |
| 同期判定 | `src/sync/` | content hash・HLC・merge/rejoin/stale-device 判定 |
| Known-Answer Tests | `kat/` | **言語非依存のベクタ 5 本** — 互換性の契約 |

鍵管理（Keychain, ThisDeviceOnly）と nonce 生成（CSPRNG）はプラットフォーム側の責務です。コアは **pure** — ファイル / ネットワーク / 時計 / RNG アクセスなし・ログなし・`forbid(unsafe_code)`。

## Invariants

- **Pure & deterministic** — 決定的で、KAT により固定。
- **No logging** — コアは値や判定結果を一切ログに出しません（呼び出し側も出してはいけません）。
- **Additive compatibility** — public enum は `#[non_exhaustive]`。挙動は `rules_version()` と [`kat/`](kat/) で固定します。

## 開発

toolchain は [`rust-toolchain.toml`](rust-toolchain.toml) で固定されており、rustup が初回実行時に自動インストールします。

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked          # KAT + unit
cargo deny check             # advisories / licenses / bans / sources
```

Swift XCFramework の再生成と Swift KAT 適合テスト:

```sh
./build-xcframework.sh
cd bindings/swift/ClipySiCore
swift test
```

`bindings/swift/ClipySiCore/ClipySiCoreFFI.xcframework` は生成物でありコミットしません。生成 Swift グルー（`Sources/ClipySiCore/clipy_si_core_ffi.swift`）は**コミット対象**で、再ビルドしてツリーが汚れないことを CI が検査します。

## リリースと検証方法

`v*` タグでゲート付きパイプラインが走ります（fmt / clippy / tests / cargo-deny → XCFramework ビルド → Swift KAT → 来歴 attestation → draft release）。macOS アプリは公開されたアセットを SwiftPM の `binaryTarget(url:checksum:)` で消費します。

保証は 3 層あり、それぞれ別物です:

1. **Checksum**（SwiftPM の pin）: ダウンロードした zip がアプリ作者の pin したものとバイト一致すること。出所については何も言いません。
2. **来歴 attestation**（現在の到達点）: アセットがこのリポジトリの release workflow により特定のタグ/コミットからビルドされたこと。誰でも検証できます（コマンドは [README.md](README.md#releases-and-how-to-verify-them) と各リリースノート参照）。
3. **再現可能ビルド**（今後の課題）: 第三者が同一バイト列を再生成できること。現時点では未達です（zip 生成の `ditto` が非決定的）。

各リリースノートにはソースタグ・コミット・rustc / Xcode バージョン・runner・target・checksum を記録します。公開済みリリースは不変です: 壊れたリリースは新バージョンで置き換え、再アップロードはしません。

## Interface Contract

[INTERFACE.md](INTERFACE.md) を参照してください。正はソースコードと KAT ベクタで、interface 文書は消費者と将来のプラットフォームシェル向けの人間可読な契約です。

## Security

[SECURITY.md](SECURITY.md) を参照してください（検出回避の報告を一律に「低深刻度」として扱わない triage 方針を含みます）。

## License

[MIT](LICENSE)
