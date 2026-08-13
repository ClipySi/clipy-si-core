//! Known-Answer-Test regression over the language-independent vectors in `kat/redaction.json`.
//! The same file is the contract every future binding (Swift/Kotlin/.NET) must also satisfy.

use clipy_si_core::{default_config, detect_secrets, is_secret, mask, rules_version};
use serde::Deserialize;

#[derive(Deserialize)]
struct Kat {
    rules_version: u32,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    text: String,
    is_secret: bool,
    kind: Option<String>,
    mask_full: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

fn load() -> Kat {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../kat/redaction.json");
    let data = std::fs::read_to_string(path).expect("read kat/redaction.json");
    serde_json::from_str(&data).expect("parse kat/redaction.json")
}

#[test]
fn kat_rules_version_matches() {
    assert_eq!(
        load().rules_version,
        rules_version(),
        "KAT rules_version drift"
    );
}

#[test]
fn kat_vectors() {
    let cfg = default_config();
    for c in &load().cases {
        let label = c.note.as_deref().unwrap_or("-");

        assert_eq!(
            is_secret(&c.text, &cfg),
            c.is_secret,
            "is_secret mismatch (note: {label})"
        );

        if let Some(kind) = &c.kind {
            let kinds: Vec<&str> = detect_secrets(&c.text, &cfg)
                .iter()
                .map(|m| m.kind.as_str())
                .collect();
            assert!(
                kinds.iter().any(|k| k == kind),
                "expected kind {kind} among {kinds:?} (note: {label})"
            );
        }

        if let Some(expected) = &c.mask_full {
            // Guard against a miscounted vector: a Full mask is one bullet per source char.
            assert_eq!(
                expected.chars().count(),
                c.text.chars().count(),
                "mask_full vector length != text length (note: {label})"
            );
            assert_eq!(
                &mask(&c.text, &cfg),
                expected,
                "mask_full mismatch (note: {label})"
            );
        }
    }
}

/// M-UI.11 P1-R: the one-pass `evaluate` API must satisfy the SAME vectors as the two-pass
/// pair it replaces — the vectors are the contract and are NOT regenerated for a new API.
#[test]
fn kat_vectors_one_pass_evaluate() {
    let cfg = default_config();
    for c in &load().cases {
        let label = c.note.as_deref().unwrap_or("-");
        let e = clipy_si_core::evaluate(&c.text, &cfg);
        assert_eq!(
            e.is_secret, c.is_secret,
            "evaluate.is_secret mismatch (note: {label})"
        );
        assert_eq!(
            e.display,
            mask(&c.text, &cfg),
            "evaluate.display != mask (note: {label})"
        );
        if let Some(expected) = &c.mask_full {
            assert_eq!(
                &e.display, expected,
                "evaluate mask_full mismatch (note: {label})"
            );
        }
    }
}
