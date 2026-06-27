//! UniFFI binding surface for [`clipy_si_core`].
//!
//! This crate is a **thin, logic-free wrapper**: it mirrors the pure-Rust public types as
//! UniFFI records/enums and forwards each call to the logic crate. The logic crate keeps
//! `#![forbid(unsafe_code)]`; all generated FFI scaffolding (which is `unsafe`) is confined
//! here so the core stays auditably pure.
//!
//! Design contract (see `INTERFACE.md` in this repository):
//! - `start`/`end` in [`SecretMatch`] are **Unicode scalar (`char`) offsets**, end-exclusive.
//!   Swift consumers must index via `String.unicodeScalars`, not `String.Index`.
//! - `kind` is the stable string label from `SecretKind::as_str()` (forward-compatible: new
//!   kinds surface as new strings rather than breaking an exhaustive enum match).

use clipy_si_core as core_lib;

uniffi::setup_scaffolding!();

/// How a detected-secret string is rendered for display. Mirrors `core_lib::MaskStyle`.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskStyle {
    /// Replace every character with a bullet (hides the whole value). Default.
    Full,
    /// Keep the first two characters, mask the rest.
    Prefix2,
    /// Keep the last four characters, mask the rest.
    Suffix4,
}

impl From<MaskStyle> for core_lib::MaskStyle {
    fn from(s: MaskStyle) -> Self {
        match s {
            MaskStyle::Full => core_lib::MaskStyle::Full,
            MaskStyle::Prefix2 => core_lib::MaskStyle::Prefix2,
            MaskStyle::Suffix4 => core_lib::MaskStyle::Suffix4,
        }
    }
}

impl From<core_lib::MaskStyle> for MaskStyle {
    fn from(s: core_lib::MaskStyle) -> Self {
        match s {
            core_lib::MaskStyle::Full => MaskStyle::Full,
            core_lib::MaskStyle::Prefix2 => MaskStyle::Prefix2,
            core_lib::MaskStyle::Suffix4 => MaskStyle::Suffix4,
            // `core_lib::MaskStyle` is `#[non_exhaustive]`; an unknown future style is
            // rendered as the safe-default Full (hide everything).
            _ => MaskStyle::Full,
        }
    }
}

/// Detector confidence. Mirrors `core_lib::Confidence`.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    /// A definite literal pattern.
    High,
    /// An entropy heuristic.
    Medium,
}

impl From<core_lib::Confidence> for Confidence {
    fn from(c: core_lib::Confidence) -> Self {
        match c {
            core_lib::Confidence::High => Confidence::High,
            core_lib::Confidence::Medium => Confidence::Medium,
            // `#[non_exhaustive]`: treat any future level as the less-certain Medium.
            _ => Confidence::Medium,
        }
    }
}

/// A detected secret span. `kind` is the stable `SecretKind::as_str()` label.
#[derive(uniffi::Record, Clone, Debug)]
pub struct SecretMatch {
    pub kind: String,
    pub start: u32,
    pub end: u32,
    pub confidence: Confidence,
}

impl From<core_lib::SecretMatch> for SecretMatch {
    fn from(m: core_lib::SecretMatch) -> Self {
        SecretMatch {
            kind: m.kind.as_str().to_string(),
            start: m.start,
            end: m.end,
            confidence: m.confidence.into(),
        }
    }
}

/// A user-supplied detection rule. Mirrors `core_lib::UserRule`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct UserRule {
    pub name: String,
    pub regex: String,
    pub kind_label: String,
}

impl From<UserRule> for core_lib::UserRule {
    fn from(r: UserRule) -> Self {
        core_lib::UserRule {
            name: r.name,
            regex: r.regex,
            kind_label: r.kind_label,
        }
    }
}

/// Detection + masking configuration. Mirrors `core_lib::MaskConfig`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct MaskConfig {
    pub enabled: bool,
    pub style: MaskStyle,
    pub min_entropy_len: u32,
    pub entropy_bits: f64,
    pub user_rules: Vec<UserRule>,
}

impl From<MaskConfig> for core_lib::MaskConfig {
    fn from(c: MaskConfig) -> Self {
        core_lib::MaskConfig {
            enabled: c.enabled,
            style: c.style.into(),
            min_entropy_len: c.min_entropy_len,
            entropy_bits: c.entropy_bits,
            user_rules: c.user_rules.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<core_lib::MaskConfig> for MaskConfig {
    fn from(c: core_lib::MaskConfig) -> Self {
        MaskConfig {
            enabled: c.enabled,
            style: c.style.into(),
            min_entropy_len: c.min_entropy_len,
            entropy_bits: c.entropy_bits,
            user_rules: c
                .user_rules
                .into_iter()
                .map(|r| UserRule {
                    name: r.name,
                    regex: r.regex,
                    kind_label: r.kind_label,
                })
                .collect(),
        }
    }
}

/// The default configuration: masking **ON**, style **Full**.
#[uniffi::export]
pub fn default_config() -> MaskConfig {
    core_lib::default_config().into()
}

/// Enumerate the secret spans in `text` (char offsets). Ignores `config.enabled`.
#[uniffi::export]
pub fn detect_secrets(text: String, config: MaskConfig) -> Vec<SecretMatch> {
    let cfg: core_lib::MaskConfig = config.into();
    core_lib::detect_secrets(&text, &cfg)
        .into_iter()
        .map(Into::into)
        .collect()
}

/// Fast yes/no used by the UI to mark a row masked. Ignores `config.enabled`.
#[uniffi::export]
pub fn is_secret(text: String, config: MaskConfig) -> bool {
    let cfg: core_lib::MaskConfig = config.into();
    core_lib::is_secret(&text, &cfg)
}

/// Apply `config.style` and return the display string (original text when `enabled=false`
/// or nothing is detected).
#[uniffi::export]
pub fn mask(text: String, config: MaskConfig) -> String {
    let cfg: core_lib::MaskConfig = config.into();
    core_lib::mask(&text, &cfg)
}

/// Names of user rules whose regex failed to compile (non-fatal; never carries a value).
#[uniffi::export]
pub fn user_rule_errors(config: MaskConfig) -> Vec<String> {
    let cfg: core_lib::MaskConfig = config.into();
    core_lib::user_rule_errors(&cfg)
}

/// The detection ruleset version (KAT / cross-binding compatibility pin).
#[uniffi::export]
pub fn rules_version() -> u32 {
    core_lib::rules_version()
}

// ===========================================================================================
// M10 — crypto / KDF / record-vault format surface.
//
// Composition stays in Rust (no low-level hkdf export). UUIDs cross as strings; vault manifests
// cross as their JSON bytes (what the shell writes to disk), so no manifest mirror is needed.
// ===========================================================================================

/// Fallible-operation error (crypto/KDF/format). Mirrors `core_lib::CoreError`; value-free.
#[derive(uniffi::Error, Debug, PartialEq, Eq)]
pub enum CoreErrorFfi {
    InvalidInput,
    DecryptFailed,
    UnsupportedFormat,
    KdfFailed,
    /// A core error category added after this binding was built (forward-compat catch-all).
    Unknown,
}

impl core::fmt::Display for CoreErrorFfi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CoreErrorFfi {}

impl From<core_lib::CoreError> for CoreErrorFfi {
    fn from(e: core_lib::CoreError) -> Self {
        match e {
            core_lib::CoreError::InvalidInput => CoreErrorFfi::InvalidInput,
            core_lib::CoreError::DecryptFailed => CoreErrorFfi::DecryptFailed,
            core_lib::CoreError::UnsupportedFormat => CoreErrorFfi::UnsupportedFormat,
            core_lib::CoreError::KdfFailed => CoreErrorFfi::KdfFailed,
            // `core_lib::CoreError` is `#[non_exhaustive]`; a future category surfaces as Unknown
            // rather than being silently mislabeled InvalidInput.
            _ => CoreErrorFfi::Unknown,
        }
    }
}

fn parse_uuid(s: &str) -> Result<uuid::Uuid, CoreErrorFfi> {
    uuid::Uuid::parse_str(s).map_err(|_| CoreErrorFfi::InvalidInput)
}

/// KDF algorithm (input only — mirrors `core_lib::KdfKind`).
#[derive(uniffi::Enum, Clone, Debug)]
pub enum KdfKindFfi {
    Pbkdf2HmacSha256 { iterations: u32 },
}

impl From<KdfKindFfi> for core_lib::KdfKind {
    fn from(k: KdfKindFfi) -> Self {
        match k {
            KdfKindFfi::Pbkdf2HmacSha256 { iterations } => {
                core_lib::KdfKind::Pbkdf2HmacSha256 { iterations }
            }
        }
    }
}

/// KDF descriptor (input only — mirrors `core_lib::KdfDescriptor`).
#[derive(uniffi::Record, Clone, Debug)]
pub struct KdfDescriptorFfi {
    pub kind: KdfKindFfi,
    pub salt: Vec<u8>,
    pub kdf_version: u32,
}

impl From<KdfDescriptorFfi> for core_lib::KdfDescriptor {
    fn from(d: KdfDescriptorFfi) -> Self {
        core_lib::KdfDescriptor {
            kind: d.kind.into(),
            salt: d.salt,
            kdf_version: d.kdf_version,
        }
    }
}

/// One captured representation (uttype + bytes).
#[derive(uniffi::Record, Clone, Debug)]
pub struct RecordRepresentationFfi {
    pub uttype: String,
    pub data: Vec<u8>,
}

impl From<core_lib::RecordRepresentation> for RecordRepresentationFfi {
    fn from(r: core_lib::RecordRepresentation) -> Self {
        RecordRepresentationFfi {
            uttype: r.uttype,
            data: r.data,
        }
    }
}
impl From<RecordRepresentationFfi> for core_lib::RecordRepresentation {
    fn from(r: RecordRepresentationFfi) -> Self {
        core_lib::RecordRepresentation {
            uttype: r.uttype,
            data: r.data,
        }
    }
}

/// The plaintext content of a record (what `seal_record` encrypts).
#[derive(uniffi::Record, Clone, Debug)]
pub struct RecordPlaintextFfi {
    pub title: String,
    pub primary_type: String,
    pub source_bundle: Option<String>,
    pub is_color_code: bool,
    pub representations: Vec<RecordRepresentationFfi>,
}

impl From<core_lib::RecordPlaintext> for RecordPlaintextFfi {
    fn from(p: core_lib::RecordPlaintext) -> Self {
        RecordPlaintextFfi {
            title: p.title,
            primary_type: p.primary_type,
            source_bundle: p.source_bundle,
            is_color_code: p.is_color_code,
            representations: p.representations.into_iter().map(Into::into).collect(),
        }
    }
}
impl From<RecordPlaintextFfi> for core_lib::RecordPlaintext {
    fn from(p: RecordPlaintextFfi) -> Self {
        core_lib::RecordPlaintext {
            title: p.title,
            primary_type: p.primary_type,
            source_bundle: p.source_bundle,
            is_color_code: p.is_color_code,
            representations: p.representations.into_iter().map(Into::into).collect(),
        }
    }
}

/// HLC wire stamp (UUID node as a string).
#[derive(uniffi::Record, Clone, Debug)]
pub struct HlcFfi {
    pub wall_millis: i64,
    pub counter: u32,
    pub node: String,
}

impl From<core_lib::Hlc> for HlcFfi {
    fn from(h: core_lib::Hlc) -> Self {
        HlcFfi {
            wall_millis: h.wall_millis,
            counter: h.counter,
            node: h.node.to_string(),
        }
    }
}
impl TryFrom<HlcFfi> for core_lib::Hlc {
    type Error = CoreErrorFfi;
    fn try_from(h: HlcFfi) -> Result<Self, Self::Error> {
        Ok(core_lib::Hlc {
            wall_millis: h.wall_millis,
            counter: h.counter,
            node: parse_uuid(&h.node)?,
        })
    }
}

/// Plaintext routing/merge header (UUIDs as strings).
#[derive(uniffi::Record, Clone, Debug)]
pub struct RecordHeaderFfi {
    pub format_version: u32,
    pub record_id: String,
    pub origin_device_id: String,
    pub hlc: HlcFfi,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted: bool,
    pub sync_hash: String,
}

impl From<core_lib::RecordHeader> for RecordHeaderFfi {
    fn from(h: core_lib::RecordHeader) -> Self {
        RecordHeaderFfi {
            format_version: h.format_version,
            record_id: h.record_id.to_string(),
            origin_device_id: h.origin_device_id.to_string(),
            hlc: h.hlc.into(),
            created_at: h.created_at,
            updated_at: h.updated_at,
            deleted: h.deleted,
            sync_hash: h.sync_hash,
        }
    }
}
impl TryFrom<RecordHeaderFfi> for core_lib::RecordHeader {
    type Error = CoreErrorFfi;
    fn try_from(h: RecordHeaderFfi) -> Result<Self, Self::Error> {
        Ok(core_lib::RecordHeader {
            format_version: h.format_version,
            record_id: parse_uuid(&h.record_id)?,
            origin_device_id: parse_uuid(&h.origin_device_id)?,
            hlc: h.hlc.try_into()?,
            created_at: h.created_at,
            updated_at: h.updated_at,
            deleted: h.deleted,
            sync_hash: h.sync_hash,
        })
    }
}

/// A full record envelope (header + optional sealed body). `body == None` is a tombstone.
#[derive(uniffi::Record, Clone, Debug)]
pub struct RecordEnvelopeFfi {
    pub header: RecordHeaderFfi,
    pub body: Option<Vec<u8>>,
}

impl From<core_lib::RecordEnvelope> for RecordEnvelopeFfi {
    fn from(e: core_lib::RecordEnvelope) -> Self {
        RecordEnvelopeFfi {
            header: e.header.into(),
            body: e.body,
        }
    }
}
impl TryFrom<RecordEnvelopeFfi> for core_lib::RecordEnvelope {
    type Error = CoreErrorFfi;
    fn try_from(e: RecordEnvelopeFfi) -> Result<Self, Self::Error> {
        Ok(core_lib::RecordEnvelope {
            header: e.header.try_into()?,
            body: e.body,
        })
    }
}

/// AES-256-GCM seal (CryptoKit `.combined` compatible). `nonce` is 12 caller-supplied CSPRNG bytes.
#[uniffi::export]
pub fn local_seal(
    key: Vec<u8>,
    nonce: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, CoreErrorFfi> {
    core_lib::local_seal(&key, &nonce, &plaintext).map_err(Into::into)
}

/// AES-256-GCM open of a `.combined` box.
#[uniffi::export]
pub fn local_open(key: Vec<u8>, combined: Vec<u8>) -> Result<Vec<u8>, CoreErrorFfi> {
    core_lib::local_open(&key, &combined).map_err(Into::into)
}

/// Keyed dedupe hash (HMAC-SHA256, lowercase hex) — CryptoKit-compatible.
#[uniffi::export]
pub fn content_hash(key: Vec<u8>, payload: Vec<u8>) -> String {
    core_lib::content_hash(&key, &payload)
}

/// Derive the 32-byte vault key from a passphrase (NFC-normalised PBKDF2).
#[uniffi::export]
pub fn derive_vault_key(
    passphrase: String,
    kdf: KdfDescriptorFfi,
) -> Result<Vec<u8>, CoreErrorFfi> {
    let descriptor: core_lib::KdfDescriptor = kdf.into();
    core_lib::derive_vault_key(&passphrase, &descriptor)
        .map(|k| k.to_vec())
        .map_err(Into::into)
}

/// Cross-device dedupe hash over the canonical payload (vault dedupe subkey).
#[uniffi::export]
pub fn compute_sync_hash(
    vault_key: Vec<u8>,
    canonical_payload: Vec<u8>,
) -> Result<String, CoreErrorFfi> {
    core_lib::compute_sync_hash(&vault_key, &canonical_payload).map_err(Into::into)
}

/// Seal a plaintext body under the vault cclip subkey; returns the `.combined` body bytes.
#[uniffi::export]
pub fn seal_record(
    vault_key: Vec<u8>,
    nonce: Vec<u8>,
    plaintext: RecordPlaintextFfi,
) -> Result<Vec<u8>, CoreErrorFfi> {
    let p: core_lib::RecordPlaintext = plaintext.into();
    core_lib::seal_record(&vault_key, &nonce, &p).map_err(Into::into)
}

/// Open a sealed body back into a plaintext.
#[uniffi::export]
pub fn open_record(vault_key: Vec<u8>, body: Vec<u8>) -> Result<RecordPlaintextFfi, CoreErrorFfi> {
    core_lib::open_record(&vault_key, &body)
        .map(Into::into)
        .map_err(Into::into)
}

/// Build `vault.json` bytes, sealing the verifier under the cclip subkey. (No key/passphrase in it.)
#[uniffi::export]
pub fn make_vault_manifest(
    vault_key: Vec<u8>,
    vault_id: String,
    created_at: i64,
    kdf: KdfDescriptorFfi,
    verifier_nonce: Vec<u8>,
) -> Result<Vec<u8>, CoreErrorFfi> {
    let id = parse_uuid(&vault_id)?;
    let descriptor: core_lib::KdfDescriptor = kdf.into();
    let manifest =
        core_lib::make_vault_manifest(&vault_key, id, created_at, descriptor, &verifier_nonce)?;
    Ok(core_lib::encode_vault_manifest(&manifest))
}

/// True iff `vault_key` opens the verifier in the given `vault.json` bytes (right passphrase).
#[uniffi::export]
pub fn verify_passphrase(vault_key: Vec<u8>, manifest_json: Vec<u8>) -> Result<bool, CoreErrorFfi> {
    let manifest = core_lib::decode_vault_manifest(&manifest_json)?;
    Ok(core_lib::verify_passphrase(&vault_key, &manifest))
}

/// Encode an envelope to its `.cclip` wire bytes (enforces the tombstone invariant).
#[uniffi::export]
pub fn encode_envelope(envelope: RecordEnvelopeFfi) -> Result<Vec<u8>, CoreErrorFfi> {
    let env: core_lib::RecordEnvelope = envelope.try_into()?;
    // Round-trip through decode so the body⟺deleted invariant is enforced on the way out too.
    let bytes = core_lib::encode_envelope(&env);
    core_lib::decode_envelope(&bytes)?;
    Ok(bytes)
}

/// Decode `.cclip` wire bytes into an envelope (rejects unknown version / invalid tombstone).
#[uniffi::export]
pub fn decode_envelope(bytes: Vec<u8>) -> Result<RecordEnvelopeFfi, CoreErrorFfi> {
    core_lib::decode_envelope(&bytes)
        .map(Into::into)
        .map_err(Into::into)
}

/// The frozen record wire version.
#[uniffi::export]
pub fn record_format_version() -> u32 {
    core_lib::record_format_version()
}

// ===========================================================================================
// M11 — sync merge-rule surface. Decisions only (no I/O); the Swift SyncEngine executes them.
// HLC stamps reuse HlcFfi (UUID node as a string).
// ===========================================================================================

/// What the shell knows locally about one incoming record id. Mirrors `core_lib::LocalState`.
#[derive(uniffi::Record, Clone, Debug)]
pub struct LocalStateFfi {
    pub applied: bool,
    pub applied_deleted: bool,
    pub live_duplicate_sync_hash: bool,
    pub tombstoned_duplicate_hlc: Option<HlcFfi>,
}

impl TryFrom<LocalStateFfi> for core_lib::LocalState {
    type Error = CoreErrorFfi;
    fn try_from(s: LocalStateFfi) -> Result<Self, Self::Error> {
        Ok(core_lib::LocalState {
            applied: s.applied,
            applied_deleted: s.applied_deleted,
            live_duplicate_sync_hash: s.live_duplicate_sync_hash,
            tombstoned_duplicate_hlc: s
                .tombstoned_duplicate_hlc
                .map(core_lib::Hlc::try_from)
                .transpose()?,
        })
    }
}

/// Merge decision for one incoming envelope. Mirrors `core_lib::MergeAction`.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeActionFfi {
    ApplyRemote,
    ApplyTombstone,
    RecordTombstoneOnly,
    Skip,
    SkipDuplicateContent,
}

impl From<core_lib::MergeAction> for MergeActionFfi {
    fn from(a: core_lib::MergeAction) -> Self {
        match a {
            core_lib::MergeAction::ApplyRemote => MergeActionFfi::ApplyRemote,
            core_lib::MergeAction::ApplyTombstone => MergeActionFfi::ApplyTombstone,
            core_lib::MergeAction::RecordTombstoneOnly => MergeActionFfi::RecordTombstoneOnly,
            core_lib::MergeAction::Skip => MergeActionFfi::Skip,
            core_lib::MergeAction::SkipDuplicateContent => MergeActionFfi::SkipDuplicateContent,
            // `#[non_exhaustive]`: an unknown future action degrades to the do-nothing Skip
            // (never applies or deletes anything it doesn't understand).
            _ => MergeActionFfi::Skip,
        }
    }
}

/// Stale-rejoin decision. Mirrors `core_lib::RejoinAction`.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejoinActionFfi {
    DeleteLocally,
    Repush,
}

impl From<core_lib::RejoinAction> for RejoinActionFfi {
    fn from(a: core_lib::RejoinAction) -> Self {
        match a {
            core_lib::RejoinAction::DeleteLocally => RejoinActionFfi::DeleteLocally,
            core_lib::RejoinAction::Repush => RejoinActionFfi::Repush,
            // `#[non_exhaustive]`: unknown future action degrades to DeleteLocally — the
            // conservative side (never re-publishes, so it can never resurrect a deletion).
            _ => RejoinActionFfi::DeleteLocally,
        }
    }
}

/// Next HLC stamp this device issues before publishing. `node` is this device's UUID string.
#[uniffi::export]
pub fn hlc_next(
    prev: Option<HlcFfi>,
    now_millis: i64,
    node: String,
) -> Result<HlcFfi, CoreErrorFfi> {
    let node = parse_uuid(&node)?;
    let prev = prev.map(core_lib::Hlc::try_from).transpose()?;
    Ok(core_lib::hlc_next(prev.as_ref(), now_millis, node).into())
}

/// Merge a received stamp into the local clock (skew-clamped; header stamps are never rewritten).
#[uniffi::export]
pub fn hlc_receive(
    local: Option<HlcFfi>,
    remote: HlcFfi,
    now_millis: i64,
    node: String,
) -> Result<HlcFfi, CoreErrorFfi> {
    let node = parse_uuid(&node)?;
    let local = local.map(core_lib::Hlc::try_from).transpose()?;
    let remote = core_lib::Hlc::try_from(remote)?;
    Ok(core_lib::hlc_receive(local.as_ref(), &remote, now_millis, node).into())
}

/// Total order over HLC stamps: -1 (a < b), 0 (equal), 1 (a > b).
#[uniffi::export]
pub fn hlc_compare(a: HlcFfi, b: HlcFfi) -> Result<i8, CoreErrorFfi> {
    let a = core_lib::Hlc::try_from(a)?;
    let b = core_lib::Hlc::try_from(b)?;
    Ok(match core_lib::hlc_compare(&a, &b) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    })
}

/// Decide what to do with one incoming envelope (pull must process tombstones first).
#[uniffi::export]
pub fn merge_decide(
    local: LocalStateFfi,
    remote_deleted: bool,
    remote_hlc: HlcFfi,
) -> Result<MergeActionFfi, CoreErrorFfi> {
    let local = core_lib::LocalState::try_from(local)?;
    let remote_hlc = core_lib::Hlc::try_from(remote_hlc)?;
    Ok(core_lib::merge_decide(&local, remote_deleted, &remote_hlc).into())
}

/// May this tombstone file be removed from the provider? (`last_seen` values are unix SECONDS.)
#[uniffi::export]
pub fn gc_eligible(
    tombstone_hlc: HlcFfi,
    devices_last_seen_secs: Vec<i64>,
    now_secs: i64,
) -> Result<bool, CoreErrorFfi> {
    let hlc = core_lib::Hlc::try_from(tombstone_hlc)?;
    let devices: Vec<core_lib::DevicePresence> = devices_last_seen_secs
        .into_iter()
        .map(|s| core_lib::DevicePresence { last_seen_secs: s })
        .collect();
    Ok(core_lib::gc_eligible(&hlc, &devices, now_secs))
}

/// Whether a device is stale (no longer blocks GC; must run stale-rejoin when it returns).
#[uniffi::export]
pub fn device_is_stale(last_seen_secs: i64, now_secs: i64) -> bool {
    core_lib::device_is_stale(last_seen_secs, now_secs)
}

/// Rejoin behaviour for previously-published records now absent from records/ AND tombs/.
#[uniffi::export]
pub fn rejoin_action(self_last_seen_secs: i64, now_secs: i64) -> RejoinActionFfi {
    core_lib::rejoin_action(self_last_seen_secs, now_secs).into()
}

/// Extract the KDF descriptor from `vault.json` bytes so the shell can derive the right key for
/// an existing vault (M10 hand-off). Unknown KDF kind / version → `unsupportedFormat`.
#[uniffi::export]
pub fn manifest_kdf(manifest_json: Vec<u8>) -> Result<KdfDescriptorFfi, CoreErrorFfi> {
    let manifest = core_lib::decode_vault_manifest(&manifest_json)?;
    let kind = match manifest.kdf.kind {
        core_lib::KdfKind::Pbkdf2HmacSha256 { iterations } => {
            KdfKindFfi::Pbkdf2HmacSha256 { iterations }
        }
        // `#[non_exhaustive]`: a KDF this binding doesn't know cannot derive a key.
        _ => return Err(CoreErrorFfi::UnsupportedFormat),
    };
    Ok(KdfDescriptorFfi {
        kind,
        salt: manifest.kdf.salt,
        kdf_version: manifest.kdf.kdf_version,
    })
}
