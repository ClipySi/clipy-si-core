//! Shared error type for the fallible core operations (crypto / KDF / record decode).
//!
//! Deliberately **value-free**: each variant is a category only — never a message that could
//! carry plaintext, a key, or a passphrase across a log or the FFI boundary (security-guidance.md
//! §5). The FFI crate mirrors this as a UniFFI error enum; keep it `#[non_exhaustive]` so new
//! categories can be added without breaking an exhaustive match in any binding.

use core::fmt;

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    /// A caller-supplied argument was malformed (wrong key/nonce length, etc.).
    InvalidInput,
    /// AES-GCM authentication failed: wrong key, corrupted ciphertext, or tampering.
    DecryptFailed,
    /// A serialized record/manifest had an unknown `format_version` or a broken layout.
    UnsupportedFormat,
    /// Key derivation (PBKDF2/HKDF) could not produce a key with the given parameters.
    KdfFailed,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CoreError::InvalidInput => "invalid input",
            CoreError::DecryptFailed => "decryption failed",
            CoreError::UnsupportedFormat => "unsupported format",
            CoreError::KdfFailed => "key derivation failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for CoreError {}
