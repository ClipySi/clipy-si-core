//! M10.3 record/vault format-freeze KAT over `kat/record.json`.
//!
//! Unlike crypto/kdf (pinned against external references), the record format is *defined* by this
//! core, so these vectors pin the core's own output: any drift in the wire bytes — JSON field order,
//! the binary body layout, the tombstone shape — fails the test. That is the freeze. The same file
//! is the contract every future binding (Swift/Kotlin/.NET) must reproduce.

use clipy_si_core::{
    compute_sync_hash, decode_envelope, encode_envelope, encode_vault_manifest,
    make_vault_manifest, open_record, seal_record, verify_passphrase, Hlc, KdfDescriptor, KdfKind,
    RecordEnvelope, RecordHeader, RecordPlaintext, RecordRepresentation, RECORD_FORMAT_VERSION,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
struct Kat {
    key_hex: String,
    nonce_hex: String,
    canonical_payload_hex: String,
    body_hex: String,
    envelope_hex: String,
    tombstone_hex: String,
    sync_hash: String,
    vault_json: String,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn load() -> Kat {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../kat/record.json");
    let data = std::fs::read_to_string(path).expect("read kat/record.json");
    serde_json::from_str(&data).expect("parse kat/record.json")
}

// The frozen test fixture (must match what produced kat/record.json).
fn plaintext() -> RecordPlaintext {
    RecordPlaintext {
        title: "hello clip".to_string(),
        primary_type: "public.utf8-plain-text".to_string(),
        source_bundle: Some("com.example.app".to_string()),
        is_color_code: false,
        representations: vec![RecordRepresentation {
            uttype: "public.utf8-plain-text".to_string(),
            data: b"hello clip".to_vec(),
        }],
    }
}

fn header(deleted: bool) -> RecordHeader {
    let rid = Uuid::from_u128(0x0102030405060708090a0b0c0d0e0f10);
    let did = Uuid::from_u128(0x1112131415161718191a1b1c1d1e1f20);
    RecordHeader {
        format_version: RECORD_FORMAT_VERSION,
        record_id: rid,
        origin_device_id: did,
        hlc: Hlc {
            wall_millis: 1_700_000_000_000,
            counter: 0,
            node: did,
        },
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        deleted,
        sync_hash: "deadbeef".to_string(),
    }
}

#[test]
fn record_format_frozen() {
    let kat = load();
    let key = unhex(&kat.key_hex);
    let nonce = unhex(&kat.nonce_hex);

    let body = seal_record(&key, &nonce, &plaintext()).unwrap();
    assert_eq!(
        tohex(&body),
        kat.body_hex,
        "sealed body bytes drifted (format change!)"
    );
    assert_eq!(
        open_record(&key, &body).unwrap(),
        plaintext(),
        "open round-trip"
    );

    let live = RecordEnvelope {
        header: header(false),
        body: Some(body),
    };
    let env_bytes = encode_envelope(&live);
    assert_eq!(
        tohex(&env_bytes),
        kat.envelope_hex,
        "envelope bytes drifted"
    );
    assert_eq!(
        decode_envelope(&env_bytes).unwrap(),
        live,
        "envelope round-trip"
    );

    let tomb = RecordEnvelope {
        header: header(true),
        body: None,
    };
    assert_eq!(
        tohex(&encode_envelope(&tomb)),
        kat.tombstone_hex,
        "tombstone bytes drifted"
    );

    assert_eq!(
        compute_sync_hash(&key, &unhex(&kat.canonical_payload_hex)).unwrap(),
        kat.sync_hash,
        "sync_hash drifted"
    );
}

#[test]
fn vault_manifest_frozen() {
    let kat = load();
    let key = unhex(&kat.key_hex);
    let nonce = unhex(&kat.nonce_hex);
    let kdf = KdfDescriptor {
        kind: KdfKind::Pbkdf2HmacSha256 { iterations: 4096 },
        salt: b"0123456789abcdef".to_vec(),
        kdf_version: 1,
    };
    let manifest = make_vault_manifest(
        &key,
        Uuid::from_u128(0x2122232425262728292a2b2c2d2e2f30),
        1_700_000_000,
        kdf,
        &nonce,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8(encode_vault_manifest(&manifest)).unwrap(),
        kat.vault_json,
        "vault.json drifted"
    );
    assert!(
        verify_passphrase(&key, &manifest),
        "verifier must accept the right key"
    );
}

/// The plaintext title and source bundle must never appear in the envelope (header is JSON metadata,
/// body is ciphertext) — the §5.1 leak-surface guarantee, at the frozen-vector level.
#[test]
fn frozen_envelope_leaks_no_content() {
    let env = unhex(&load().envelope_hex);
    assert!(!env.windows(10).any(|w| w == b"hello clip"), "title leaked");
    assert!(
        !env.windows(11).any(|w| w == b"com.example"),
        "source bundle leaked"
    );
}
