//! M10.1 crypto Known-Answer-Test over `kat/crypto.json`.
//!
//! The load-bearing one is `aead_interop_open`: vectors produced by **Apple CryptoKit** must open
//! in the Rust core (`.combined` byte-compatibility). If this regresses, every existing user's
//! history becomes unreadable — it is the M10.1 kill-switch (design §13.3 KEEP-3). The same file is
//! the contract every future binding (Swift/Kotlin/.NET) must satisfy.

use clipy_si_core::crypto::hkdf_subkey;
use clipy_si_core::{content_hash, local_open, local_seal};
use serde::Deserialize;

#[derive(Deserialize)]
struct Kat {
    key_hex: String,
    aead_combined: Aead,
    hmac_sha256: Hmac,
    hkdf_sha256_expand: Hkdf,
}

#[derive(Deserialize)]
struct Aead {
    nonce_hex: String,
    cases: Vec<AeadCase>,
}
#[derive(Deserialize)]
struct AeadCase {
    note: String,
    plaintext_hex: String,
    combined_hex: String,
}
#[derive(Deserialize)]
struct Hmac {
    cases: Vec<HmacCase>,
}
#[derive(Deserialize)]
struct HmacCase {
    note: String,
    input_hex: String,
    hmac_hex: String,
}
#[derive(Deserialize)]
struct Hkdf {
    master_hex: String,
    cases: Vec<HkdfCase>,
}
#[derive(Deserialize)]
struct HkdfCase {
    info_utf8: String,
    okm_hex: String,
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
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../kat/crypto.json");
    let data = std::fs::read_to_string(path).expect("read kat/crypto.json");
    serde_json::from_str(&data).expect("parse kat/crypto.json")
}

/// KILL-SWITCH: CryptoKit-produced `.combined` boxes must decrypt in the Rust core.
#[test]
fn aead_interop_open() {
    let kat = load();
    let key = unhex(&kat.key_hex);
    for c in &kat.aead_combined.cases {
        let combined = unhex(&c.combined_hex);
        let want = unhex(&c.plaintext_hex);
        let got = local_open(&key, &combined)
            .unwrap_or_else(|_| panic!("open failed for CryptoKit vector '{}'", c.note));
        assert_eq!(got, want, "interop open mismatch ({})", c.note);
    }
}

/// The reverse direction: Rust seal with the pinned nonce reproduces CryptoKit's exact bytes.
#[test]
fn aead_seal_matches_cryptokit() {
    let kat = load();
    let key = unhex(&kat.key_hex);
    let nonce = unhex(&kat.aead_combined.nonce_hex);
    for c in &kat.aead_combined.cases {
        let pt = unhex(&c.plaintext_hex);
        let got = local_seal(&key, &nonce, &pt).expect("seal");
        assert_eq!(
            tohex(&got),
            c.combined_hex,
            "seal bytes diverge from CryptoKit ({})",
            c.note
        );
    }
}

#[test]
fn hmac_matches_cryptokit() {
    let kat = load();
    let key = unhex(&kat.key_hex);
    for c in &kat.hmac_sha256.cases {
        let input = unhex(&c.input_hex);
        assert_eq!(
            content_hash(&key, &input),
            c.hmac_hex,
            "hmac mismatch ({})",
            c.note
        );
    }
}

#[test]
fn hkdf_matches_reference() {
    let kat = load();
    let master: [u8; 32] = unhex(&kat.hkdf_sha256_expand.master_hex)
        .try_into()
        .expect("32-byte master");
    for c in &kat.hkdf_sha256_expand.cases {
        let okm = hkdf_subkey(&master, c.info_utf8.as_bytes());
        assert_eq!(
            okm.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            c.okm_hex,
            "hkdf okm mismatch ({})",
            c.info_utf8
        );
    }
}
