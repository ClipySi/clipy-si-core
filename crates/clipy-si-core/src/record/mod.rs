//! Record & vault formats (M10 foundation freeze).
//!
//! Freezes the on-the-wire shapes that sync (M11) and every OS shell will share, plus the seal/open
//! that protect them with the **vault key** (distinct from the device-local key — design §4.1):
//!
//! - [`RecordEnvelope`] = a `.cclip`: a plaintext [`RecordHeader`] (routing/merge metadata that can
//!   be read without the vault key) + an optional encrypted body. `body == None` ⟺ tombstone.
//! - The body ciphertext hides the content: title, primary type, **source bundle**, representations
//!   (design §5.1). `content_hash` (the device-local dedupe hash) never appears here; cross-device
//!   dedupe uses [`compute_sync_hash`] under a separate HKDF subkey.
//! - [`VaultManifest`] = `vault.json`: KDF descriptor + a verifier (a public constant sealed under
//!   the cclip subkey) so a wrong passphrase is caught without touching records. No key, no phrase.
//!
//! The header & manifest are JSON; the encrypted body is an explicit binary layout (`canonical`).
//! All subkeys are HKDF-derived from the 32-byte vault master and zeroized after use.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::{self, hkdf_subkey, KEY_LEN};
use crate::error::CoreError;
use crate::kdf::KdfDescriptor;

mod canonical;
pub mod version;

pub use version::{DEVICE_FORMAT_VERSION, RECORD_FORMAT_VERSION, VAULT_FORMAT_VERSION};

/// HKDF domain-separation label for the body-encryption subkey. Immutable per major version.
const INFO_CCLIP: &[u8] = b"clipysi/v1/cclip";
/// HKDF label for the cross-device dedupe HMAC subkey.
const INFO_DEDUPE: &[u8] = b"clipysi/v1/dedupe";
/// Public, non-secret constant sealed under the cclip subkey as the vault verifier.
const VERIFIER_PLAINTEXT: &[u8] = b"clipysi-vault-verifier-v1";

/// Hybrid Logical Clock stamp. **M10 only freezes the wire shape**; the advance/merge/tiebreak
/// semantics are M11's (design §13.1 FIX-4). M10 stamps `wall_millis = updated_at*1000`,
/// `counter = 0`, `node = origin_device_id` as a placeholder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hlc {
    pub wall_millis: i64,
    pub counter: u32,
    pub node: Uuid,
}

/// Plaintext routing/merge header — readable without the vault key (carries no content).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordHeader {
    pub format_version: u32,
    pub record_id: Uuid,
    pub origin_device_id: Uuid,
    pub hlc: Hlc,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted: bool,
    /// Cross-device dedupe HMAC (hex) under the vault dedupe subkey — NOT the device `contentHash`.
    pub sync_hash: String,
}

/// One record: header + optional sealed body. `body == None` is a tombstone (`header.deleted` true).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEnvelope {
    pub header: RecordHeader,
    pub body: Option<Vec<u8>>,
}

/// A secondary representation captured alongside the primary (uttype + raw bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRepresentation {
    pub uttype: String,
    pub data: Vec<u8>,
}

/// The plaintext content of a record — everything that must be hidden from a vault file. Sealed into
/// [`RecordEnvelope::body`]; never serialized in the clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPlaintext {
    pub title: String,
    pub primary_type: String,
    pub source_bundle: Option<String>,
    pub is_color_code: bool,
    pub representations: Vec<RecordRepresentation>,
}

/// `vault.json`: how to re-derive the vault key + a verifier. No key, no passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultManifest {
    pub format_version: u32,
    pub vault_id: Uuid,
    pub created_at: i64,
    pub kdf: KdfDescriptor,
    #[serde(with = "crate::hexutil")]
    pub verifier: Vec<u8>,
}

/// One participating device. `last_seen` is updated by M11; M10 only freezes the shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDescriptor {
    pub format_version: u32,
    pub device_id: Uuid,
    pub display_name: String,
    pub platform: String,
    pub last_seen: i64,
}

fn as_key32(key: &[u8]) -> Result<[u8; KEY_LEN], CoreError> {
    key.try_into().map_err(|_| CoreError::InvalidInput)
}

/// The frozen record wire version.
pub fn record_format_version() -> u32 {
    RECORD_FORMAT_VERSION
}

/// Seal a plaintext body under the vault's cclip subkey. `nonce` is 12 caller-supplied CSPRNG bytes
/// (unique per key). Returns the `.combined` body bytes (`nonce ‖ ciphertext ‖ tag`).
pub fn seal_record(
    vault_key: &[u8],
    nonce: &[u8],
    plaintext: &RecordPlaintext,
) -> Result<Vec<u8>, CoreError> {
    let mut master = as_key32(vault_key)?;
    let mut cclip = hkdf_subkey(&master, INFO_CCLIP);
    let mut body = canonical::encode_plaintext(plaintext);
    let sealed = crypto::local_seal(&cclip, nonce, &body);
    body.zeroize();
    cclip.zeroize();
    master.zeroize();
    sealed
}

/// Open a sealed body produced by [`seal_record`] back into a plaintext.
pub fn open_record(vault_key: &[u8], body: &[u8]) -> Result<RecordPlaintext, CoreError> {
    let mut master = as_key32(vault_key)?;
    let mut cclip = hkdf_subkey(&master, INFO_CCLIP);
    let opened = crypto::local_open(&cclip, body);
    cclip.zeroize();
    master.zeroize();
    canonical::decode_plaintext(&opened?)
}

/// Cross-device dedupe hash over the canonical payload (the same bytes ClipySi hashes for its
/// device-local `contentHash`, but keyed by a *different* vault subkey — design §13.1 FIX-1).
pub fn compute_sync_hash(vault_key: &[u8], canonical_payload: &[u8]) -> Result<String, CoreError> {
    let mut master = as_key32(vault_key)?;
    let mut dedupe = hkdf_subkey(&master, INFO_DEDUPE);
    let hash = crypto::content_hash(&dedupe, canonical_payload);
    dedupe.zeroize();
    master.zeroize();
    Ok(hash)
}

/// Build a vault manifest, sealing the public verifier constant under the cclip subkey.
pub fn make_vault_manifest(
    vault_key: &[u8],
    vault_id: Uuid,
    created_at: i64,
    kdf: KdfDescriptor,
    verifier_nonce: &[u8],
) -> Result<VaultManifest, CoreError> {
    let mut master = as_key32(vault_key)?;
    let mut cclip = hkdf_subkey(&master, INFO_CCLIP);
    let verifier = crypto::local_seal(&cclip, verifier_nonce, VERIFIER_PLAINTEXT);
    cclip.zeroize();
    master.zeroize();
    Ok(VaultManifest {
        format_version: VAULT_FORMAT_VERSION,
        vault_id,
        created_at,
        kdf,
        verifier: verifier?,
    })
}

/// True iff `vault_key` opens the manifest verifier — i.e. the passphrase that derived it is right.
pub fn verify_passphrase(vault_key: &[u8], manifest: &VaultManifest) -> bool {
    let mut master = match as_key32(vault_key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let mut cclip = hkdf_subkey(&master, INFO_CCLIP);
    let opened = crypto::local_open(&cclip, &manifest.verifier);
    cclip.zeroize();
    master.zeroize();
    matches!(opened, Ok(pt) if pt.as_slice() == VERIFIER_PLAINTEXT)
}

/// Encode an envelope to its wire bytes: `u32-LE header_len ‖ JSON header ‖ has_body:u8 ‖ body`.
pub fn encode_envelope(env: &RecordEnvelope) -> Vec<u8> {
    let header_json = serde_json::to_vec(&env.header).expect("header serializes");
    let body_len = env.body.as_ref().map_or(0, Vec::len);
    let mut out = Vec::with_capacity(4 + header_json.len() + 1 + body_len);
    out.extend_from_slice(&(header_json.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_json);
    match &env.body {
        Some(body) => {
            out.push(1);
            out.extend_from_slice(body);
        }
        None => out.push(0),
    }
    out
}

/// Decode envelope wire bytes. Enforces the tombstone invariant (`body present ⟺ not deleted`,
/// design §13.1 FIX-3) and rejects an unknown `format_version`.
pub fn decode_envelope(bytes: &[u8]) -> Result<RecordEnvelope, CoreError> {
    if bytes.len() < 5 {
        return Err(CoreError::UnsupportedFormat);
    }
    let header_len = u32::from_le_bytes(bytes[0..4].try_into().expect("4 bytes")) as usize;
    let header_end = 4usize
        .checked_add(header_len)
        .ok_or(CoreError::UnsupportedFormat)?;
    let header_bytes = bytes
        .get(4..header_end)
        .ok_or(CoreError::UnsupportedFormat)?;
    let header: RecordHeader =
        serde_json::from_slice(header_bytes).map_err(|_| CoreError::UnsupportedFormat)?;
    if header.format_version != RECORD_FORMAT_VERSION {
        return Err(CoreError::UnsupportedFormat);
    }
    let has_body = *bytes.get(header_end).ok_or(CoreError::UnsupportedFormat)?;
    let body = match has_body {
        0 => None,
        1 => Some(
            bytes
                .get(header_end + 1..)
                .ok_or(CoreError::UnsupportedFormat)?
                .to_vec(),
        ),
        _ => return Err(CoreError::UnsupportedFormat),
    };
    if body.is_some() == header.deleted {
        return Err(CoreError::UnsupportedFormat);
    }
    Ok(RecordEnvelope { header, body })
}

/// Serialize a vault manifest to `vault.json` bytes.
pub fn encode_vault_manifest(manifest: &VaultManifest) -> Vec<u8> {
    serde_json::to_vec(manifest).expect("manifest serializes")
}

/// Parse `vault.json` bytes, rejecting an unknown `format_version`.
pub fn decode_vault_manifest(bytes: &[u8]) -> Result<VaultManifest, CoreError> {
    let manifest: VaultManifest =
        serde_json::from_slice(bytes).map_err(|_| CoreError::UnsupportedFormat)?;
    if manifest.format_version != VAULT_FORMAT_VERSION {
        return Err(CoreError::UnsupportedFormat);
    }
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfKind;

    const KEY: [u8; 32] = [0x2A; 32];
    const NONCE: [u8; 12] = [0; 12];

    fn sample_plaintext() -> RecordPlaintext {
        RecordPlaintext {
            title: "secret token ghp_xxx".to_string(),
            primary_type: "public.utf8-plain-text".to_string(),
            source_bundle: Some("com.example.app".to_string()),
            is_color_code: false,
            representations: vec![RecordRepresentation {
                uttype: "public.utf8-plain-text".to_string(),
                data: b"secret token ghp_xxx".to_vec(),
            }],
        }
    }

    #[test]
    fn record_seal_open_roundtrip() {
        let p = sample_plaintext();
        let body = seal_record(&KEY, &NONCE, &p).unwrap();
        assert_eq!(open_record(&KEY, &body).unwrap(), p);
    }

    #[test]
    fn record_body_is_independent_of_local_key() {
        // The vault key is unrelated to the device-local key; only the vault key opens the body.
        let body = seal_record(&KEY, &NONCE, &sample_plaintext()).unwrap();
        let wrong = [0x99u8; 32];
        assert_eq!(open_record(&wrong, &body), Err(CoreError::DecryptFailed));
    }

    #[test]
    fn body_hides_content_and_source_bundle() {
        let body = seal_record(&KEY, &NONCE, &sample_plaintext()).unwrap();
        // Neither the secret-ish title nor the source bundle survive in the ciphertext.
        assert!(!body.windows(4).any(|w| w == b"ghp_"));
        assert!(!body.windows(11).any(|w| w == b"com.example"));
    }

    #[test]
    fn envelope_roundtrip_live_and_tombstone() {
        let id = Uuid::nil();
        let header = RecordHeader {
            format_version: RECORD_FORMAT_VERSION,
            record_id: id,
            origin_device_id: id,
            hlc: Hlc {
                wall_millis: 0,
                counter: 0,
                node: id,
            },
            created_at: 0,
            updated_at: 0,
            deleted: false,
            sync_hash: "00".to_string(),
        };
        let live = RecordEnvelope {
            header: header.clone(),
            body: Some(seal_record(&KEY, &NONCE, &sample_plaintext()).unwrap()),
        };
        assert_eq!(decode_envelope(&encode_envelope(&live)).unwrap(), live);

        let tomb_header = RecordHeader {
            deleted: true,
            ..header
        };
        let tomb = RecordEnvelope {
            header: tomb_header,
            body: None,
        };
        assert_eq!(decode_envelope(&encode_envelope(&tomb)).unwrap(), tomb);
    }

    #[test]
    fn decode_rejects_body_tombstone_mismatch() {
        // deleted=true but a body present → invalid.
        let id = Uuid::nil();
        let header = RecordHeader {
            format_version: RECORD_FORMAT_VERSION,
            record_id: id,
            origin_device_id: id,
            hlc: Hlc {
                wall_millis: 0,
                counter: 0,
                node: id,
            },
            created_at: 0,
            updated_at: 0,
            deleted: true,
            sync_hash: "00".to_string(),
        };
        let bad = RecordEnvelope {
            header,
            body: Some(vec![0u8; 28]),
        };
        assert_eq!(
            decode_envelope(&encode_envelope(&bad)),
            Err(CoreError::UnsupportedFormat)
        );
    }

    #[test]
    fn verifier_accepts_right_key_rejects_wrong() {
        let kdf = KdfDescriptor {
            kind: KdfKind::Pbkdf2HmacSha256 { iterations: 4096 },
            salt: b"0123456789abcdef".to_vec(),
            kdf_version: crate::KDF_VERSION,
        };
        let manifest = make_vault_manifest(&KEY, Uuid::nil(), 0, kdf, &NONCE).unwrap();
        assert!(verify_passphrase(&KEY, &manifest));
        assert!(!verify_passphrase(&[0x99u8; 32], &manifest));
        // manifest round-trips through vault.json bytes.
        let bytes = encode_vault_manifest(&manifest);
        assert_eq!(decode_vault_manifest(&bytes).unwrap(), manifest);
    }
}
