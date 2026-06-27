//! Symmetric crypto primitives for ClipySi history & sync records (M10 foundation freeze).
//!
//! This is the single cross-platform implementation of the at-rest/in-transit crypto. The macOS
//! shell historically used CryptoKit (`HistoryCipher`); M10 ports that path here so every OS shell
//! embeds the *same* bytes. The two load-bearing compatibility facts, pinned by `kat/crypto.json`:
//!
//! 1. **`local_seal`/`local_open` are byte-compatible with CryptoKit `AES.GCM …`.combined`** —
//!    layout `nonce(12) ‖ ciphertext ‖ tag(16)`. Existing users' blobs MUST keep decrypting, so
//!    the interop KAT (CryptoKit-produced vectors → `local_open`) is the M10.1 kill-switch.
//! 2. **`content_hash` equals CryptoKit `HMAC<SHA256>`** over the same bytes (the dedupe key).
//!
//! Invariants: pure, no I/O, no logging, **no RNG** — the caller supplies the nonce (AES-GCM
//! security requires a unique nonce per (key, message); the shell generates it with a CSPRNG).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::CoreError;

/// AES-256-GCM nonce length (bytes). Matches CryptoKit's default 96-bit nonce.
pub const NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length (bytes).
pub const TAG_LEN: usize = 16;
/// Symmetric key length (bytes).
pub const KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

fn cipher(key: &[u8]) -> Result<Aes256Gcm, CoreError> {
    if key.len() != KEY_LEN {
        return Err(CoreError::InvalidInput);
    }
    Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)))
}

/// AES-256-GCM seal producing a CryptoKit-compatible `.combined` box: `nonce ‖ ciphertext ‖ tag`.
///
/// `key` must be 32 bytes and `nonce` 12 bytes, else [`CoreError::InvalidInput`]. The caller is
/// responsible for nonce uniqueness per key (reuse breaks GCM confidentiality).
pub fn local_seal(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cipher = cipher(key)?;
    if nonce.len() != NONCE_LEN {
        return Err(CoreError::InvalidInput);
    }
    let ct_and_tag = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| CoreError::InvalidInput)?;
    let mut combined = Vec::with_capacity(NONCE_LEN + ct_and_tag.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&ct_and_tag);
    Ok(combined)
}

/// AES-256-GCM open of a CryptoKit `.combined` box produced by [`local_seal`] (or CryptoKit).
///
/// Splits `nonce = combined[..12]`, `ciphertext‖tag = combined[12..]`. Returns
/// [`CoreError::DecryptFailed`] on a short box, a wrong key, or a failed authentication tag.
pub fn local_open(key: &[u8], combined: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cipher = cipher(key)?;
    if combined.len() < NONCE_LEN + TAG_LEN {
        return Err(CoreError::DecryptFailed);
    }
    let (nonce, ct_and_tag) = combined.split_at(NONCE_LEN);
    cipher
        .decrypt(Nonce::from_slice(nonce), ct_and_tag)
        .map_err(|_| CoreError::DecryptFailed)
}

/// Keyed dedupe hash (lowercase hex) — HMAC-SHA256, byte-identical to CryptoKit
/// `HMAC<SHA256>.authenticationCode(for:using:)`. HMAC accepts any key length, but ClipySi keys
/// are 32 bytes. The stored hash reveals nothing about the content without the key.
pub fn content_hash(key: &[u8], payload: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload);
    hex_lower(&mac.finalize().into_bytes())
}

/// HKDF-SHA256 **expand-only** subkey derivation from an already-strong 32-byte master (the PBKDF2
/// vault key is a valid PRK). `info` is a domain-separation label (e.g. `b"clipysi/v1/cclip"`);
/// distinct labels yield independent subkeys. Not exported over FFI — composition stays in Rust.
pub fn hkdf_subkey(master: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::from_prk(master).expect("32-byte PRK is valid for SHA-256");
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm)
        .expect("32-byte OKM is within HKDF length bound");
    okm
}

/// Lowercase hex of a byte slice (matches the original Swift `contentHash` formatting).
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [0x2A_u8; KEY_LEN];
        let nonce = [0u8; NONCE_LEN];
        let pt = b"roundtrip";
        let combined = local_seal(&key, &nonce, pt).unwrap();
        assert_eq!(combined.len(), NONCE_LEN + pt.len() + TAG_LEN);
        assert_eq!(&combined[..NONCE_LEN], &nonce);
        assert_eq!(local_open(&key, &combined).unwrap(), pt);
    }

    #[test]
    fn open_rejects_tampered_tag() {
        let key = [0x2A_u8; KEY_LEN];
        let nonce = [1u8; NONCE_LEN];
        let mut combined = local_seal(&key, &nonce, b"abc").unwrap();
        let last = combined.len() - 1;
        combined[last] ^= 0x01;
        assert_eq!(local_open(&key, &combined), Err(CoreError::DecryptFailed));
    }

    #[test]
    fn open_rejects_wrong_key() {
        let combined = local_seal(&[0x2A; KEY_LEN], &[0u8; NONCE_LEN], b"abc").unwrap();
        assert_eq!(
            local_open(&[0x2B; KEY_LEN], &combined),
            Err(CoreError::DecryptFailed)
        );
    }

    #[test]
    fn invalid_lengths_rejected() {
        assert_eq!(
            local_seal(&[0u8; 16], &[0u8; NONCE_LEN], b""),
            Err(CoreError::InvalidInput)
        );
        assert_eq!(
            local_seal(&[0u8; KEY_LEN], &[0u8; 8], b""),
            Err(CoreError::InvalidInput)
        );
        assert_eq!(
            local_open(&[0u8; KEY_LEN], b"short"),
            Err(CoreError::DecryptFailed)
        );
    }

    #[test]
    fn hkdf_labels_are_independent() {
        let master = [0x2A_u8; KEY_LEN];
        let a = hkdf_subkey(&master, b"clipysi/v1/cclip");
        let b = hkdf_subkey(&master, b"clipysi/v1/dedupe");
        let c = hkdf_subkey(&master, b"clipysi/v1/device");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
        // Deterministic.
        assert_eq!(a, hkdf_subkey(&master, b"clipysi/v1/cclip"));
    }
}
