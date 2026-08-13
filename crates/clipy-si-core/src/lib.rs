//! `clipy-si-core` — shared cross-platform core for ClipySi.
//!
//! Shared redaction, crypto, record/vault format, and sync-rule logic. Every OS shell
//! (macOS/Windows/iOS/Android) embeds the *same* behaviour via FFI (UniFFI / C-ABI),
//! removing per-platform regex/entropy/crypto/protocol drift.
//!
//! Invariants (see `INTERFACE.md` in this repository):
//! - **Pure**: no file/network/clock/RNG access — deterministic and trivially testable.
//! - **No logging**: the core never logs values or verdicts (callers must not either).
//! - **Additive compatibility**: public enums are `#[non_exhaustive]`; behaviour is pinned
//!   by version constants, [`redaction::rules_version`], and the language-independent KAT
//!   vectors (`kat/`).

pub mod crypto;
pub mod error;
pub mod kdf;
pub mod record;
pub mod redaction;
pub mod sync;

mod hexutil;

pub use error::CoreError;
pub use redaction::{
    default_config, detect_secrets, evaluate, is_secret, mask, rules_version, user_rule_errors,
    Confidence, MaskConfig, MaskEvaluation, MaskStyle, SecretKind, SecretMatch, UserRule,
};

pub use crypto::{content_hash, hkdf_subkey, local_open, local_seal, KEY_LEN, NONCE_LEN, TAG_LEN};
pub use kdf::{derive_vault_key, KdfDescriptor, KdfKind, KDF_VERSION};
pub use record::{
    compute_sync_hash, decode_envelope, decode_vault_manifest, encode_envelope,
    encode_vault_manifest, make_vault_manifest, open_record, record_format_version, seal_record,
    verify_passphrase, DeviceDescriptor, Hlc, RecordEnvelope, RecordHeader, RecordPlaintext,
    RecordRepresentation, VaultManifest, DEVICE_FORMAT_VERSION, RECORD_FORMAT_VERSION,
    VAULT_FORMAT_VERSION,
};
pub use sync::{
    device_is_stale, gc_eligible, hlc_compare, hlc_next, hlc_receive, merge_decide, rejoin_action,
    DevicePresence, LocalState, MergeAction, RejoinAction, MAX_DRIFT_MILLIS, STALE_DEVICE_SECS,
    TOMBSTONE_RETENTION_SECS,
};
