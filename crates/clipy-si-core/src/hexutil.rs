//! serde helper: `Vec<u8>` ⇄ lowercase hex string.
//!
//! Used for the binary fields that live inside the JSON manifest (KDF salt, vault verifier) so
//! `vault.json` stays human-readable and byte-deterministic instead of a noisy array of integers.

use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    use core::fmt::Write;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(hex, "{b:02x}");
    }
    serializer.serialize_str(&hex)
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    if s.len() % 2 != 0 {
        return Err(serde::de::Error::custom("odd hex length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
        .collect()
}
