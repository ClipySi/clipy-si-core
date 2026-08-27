//! M10.2 KDF Known-Answer-Test over `kat/kdf.json`.
//!
//! Pins PBKDF2-HMAC-SHA256 against an independent reference and asserts the NFC-normalisation
//! contract (the same passphrase in composed/decomposed form derives one key). The same file is the
//! contract every future binding (Swift/Kotlin/.NET) must satisfy.

use clipy_si_core::{derive_vault_key, KdfDescriptor, KdfKind, KDF_VERSION};
use serde::Deserialize;

#[derive(Deserialize)]
struct Kat {
    salt_hex: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    note: String,
    passphrase_hex: String,
    iterations: u32,
    key_hex: String,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn load() -> Kat {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../kat/kdf.json");
    let data = std::fs::read_to_string(path).expect("read kat/kdf.json");
    serde_json::from_str(&data).expect("parse kat/kdf.json")
}

#[test]
fn pbkdf2_matches_reference() {
    let kat = load();
    let salt = unhex(&kat.salt_hex);
    for c in &kat.cases {
        let passphrase = String::from_utf8(unhex(&c.passphrase_hex)).expect("utf8 passphrase");
        let descriptor = KdfDescriptor {
            kind: KdfKind::Pbkdf2HmacSha256 {
                iterations: c.iterations,
            },
            salt: salt.clone(),
            kdf_version: KDF_VERSION,
        };
        let key = derive_vault_key(&passphrase, &descriptor).expect("derive");
        assert_eq!(tohex(&key), c.key_hex, "kdf mismatch ({})", c.note);
    }
}

/// Belt-and-suspenders over the KAT: the composed and decomposed cases pin the same key, and that
/// key really comes from one normalised passphrase.
#[test]
fn nfc_forms_collapse_to_one_key() {
    let kat = load();
    let composed = kat.cases.iter().find(|c| c.note == "nfc-composed").unwrap();
    let decomposed = kat
        .cases
        .iter()
        .find(|c| c.note == "nfc-decomposed")
        .unwrap();
    assert_ne!(
        composed.passphrase_hex, decomposed.passphrase_hex,
        "the two NFC cases must differ in bytes"
    );
    assert_eq!(
        composed.key_hex, decomposed.key_hex,
        "NFC-equal passphrases must pin the same key"
    );
}
