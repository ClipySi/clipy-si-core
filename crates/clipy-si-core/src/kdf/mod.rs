//! Vault-key derivation (M10 foundation freeze).
//!
//! Turns a user passphrase into the 32-byte vault master key via PBKDF2-HMAC-SHA256. The same
//! passphrase must derive the same key on every OS, so the passphrase is **NFC-normalised** before
//! UTF-8 encoding (composed/decomposed Unicode forms then agree — an M12 cross-platform prereq).
//!
//! The KDF parameters live in the vault manifest as a [`KdfDescriptor`], so a future Argon2id is a
//! new [`KdfKind`] variant rather than a rewrite (existing PBKDF2 vaults stay openable). The shell
//! calibrates the iteration count (≥250 ms on the slowest device; floor 600_000) and gates cloud
//! sync on a stronger KDF (design §13.2 FIX-5); the core only rejects a zero count / empty salt.
//!
//! Pure, no I/O, no logging. The normalised passphrase copy is zeroized before return.

use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::crypto::KEY_LEN;
use crate::error::CoreError;

/// KDF descriptor version frozen by M10. A binding refuses a descriptor it does not understand.
pub const KDF_VERSION: u32 = 1;

/// The key-derivation algorithm. `#[non_exhaustive]` so Argon2id etc. can be added later without
/// breaking an exhaustive match in any binding.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfKind {
    /// PBKDF2-HMAC-SHA256 with the given iteration count.
    Pbkdf2HmacSha256 { iterations: u32 },
}

/// Everything needed to re-derive a vault key from a passphrase. Stored in the vault manifest
/// (plaintext — salt and parameters are not secret; the passphrase never is). `salt` serialises as
/// a hex string so `vault.json` stays readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfDescriptor {
    pub kind: KdfKind,
    #[serde(with = "crate::hexutil")]
    pub salt: Vec<u8>,
    pub kdf_version: u32,
}

/// Derive the 32-byte vault master key from `passphrase` and `descriptor`.
///
/// The passphrase is NFC-normalised then UTF-8 encoded. Errors:
/// - [`CoreError::UnsupportedFormat`] — unknown `kdf_version`.
/// - [`CoreError::KdfFailed`] — empty salt or zero iteration count.
pub fn derive_vault_key(
    passphrase: &str,
    descriptor: &KdfDescriptor,
) -> Result<[u8; KEY_LEN], CoreError> {
    if descriptor.kdf_version != KDF_VERSION {
        return Err(CoreError::UnsupportedFormat);
    }
    if descriptor.salt.is_empty() {
        return Err(CoreError::KdfFailed);
    }
    let mut normalized: String = passphrase.nfc().collect();
    let mut key = [0u8; KEY_LEN];
    let result = match &descriptor.kind {
        KdfKind::Pbkdf2HmacSha256 { iterations } if *iterations > 0 => {
            pbkdf2_hmac::<Sha256>(
                normalized.as_bytes(),
                &descriptor.salt,
                *iterations,
                &mut key,
            );
            Ok(key)
        }
        KdfKind::Pbkdf2HmacSha256 { .. } => Err(CoreError::KdfFailed),
    };
    normalized.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(iterations: u32) -> KdfDescriptor {
        KdfDescriptor {
            kind: KdfKind::Pbkdf2HmacSha256 { iterations },
            salt: b"0123456789abcdef".to_vec(),
            kdf_version: KDF_VERSION,
        }
    }

    #[test]
    fn nfc_composed_and_decomposed_agree() {
        let composed = "caf\u{00E9}"; // café (U+00E9)
        let decomposed = "cafe\u{0301}"; // café (e + combining acute)
        let d = descriptor(4096);
        assert_eq!(
            derive_vault_key(composed, &d).unwrap(),
            derive_vault_key(decomposed, &d).unwrap()
        );
    }

    #[test]
    fn zero_iterations_and_empty_salt_rejected() {
        assert_eq!(
            derive_vault_key("x", &descriptor(0)),
            Err(CoreError::KdfFailed)
        );
        let mut d = descriptor(4096);
        d.salt.clear();
        assert_eq!(derive_vault_key("x", &d), Err(CoreError::KdfFailed));
    }

    #[test]
    fn unknown_version_rejected() {
        let mut d = descriptor(4096);
        d.kdf_version = 99;
        assert_eq!(derive_vault_key("x", &d), Err(CoreError::UnsupportedFormat));
    }
}
