//! Public-API unit tests for the redaction core (mask styles, char indexing, user rules,
//! overlap resolution, config gating). KAT vectors live in `kat.rs`.

use clipy_si_core::{
    default_config, detect_secrets, is_secret, mask, user_rule_errors, Confidence, MaskConfig,
    MaskStyle, SecretKind, UserRule,
};

const GH: &str = "ghp_0000000000000000000000000000000000AB"; // 40 chars

#[test]
fn full_mask_is_one_bullet_per_char() {
    let masked = mask(GH, &default_config());
    assert_eq!(masked.chars().count(), GH.chars().count());
    assert!(masked.chars().all(|c| c == '\u{2022}'));
}

#[test]
fn prefix_and_suffix_styles_keep_ends() {
    let prefix = mask(
        GH,
        &MaskConfig {
            style: MaskStyle::Prefix2,
            ..default_config()
        },
    );
    assert!(prefix.starts_with("gh"));
    assert_eq!(
        prefix.chars().filter(|&c| c == '\u{2022}').count(),
        GH.chars().count() - 2
    );

    let suffix = mask(
        GH,
        &MaskConfig {
            style: MaskStyle::Suffix4,
            ..default_config()
        },
    );
    assert!(suffix.ends_with("00AB"));
    assert_eq!(
        suffix.chars().filter(|&c| c == '\u{2022}').count(),
        GH.chars().count() - 4
    );
}

#[test]
fn non_secret_text_is_returned_verbatim() {
    let text = "just a normal clipboard note";
    assert_eq!(mask(text, &default_config()), text);
    assert!(!is_secret(text, &default_config()));
}

#[test]
fn disabled_config_never_masks() {
    let cfg = MaskConfig {
        enabled: false,
        ..default_config()
    };
    assert_eq!(mask(GH, &cfg), GH);
    // detection still reports the truth even when masking is disabled.
    assert!(is_secret(GH, &cfg));
}

#[test]
fn char_indices_account_for_multibyte_prefix() {
    // 4 leading emoji (each 1 char, multi-byte) then the token.
    let text = format!("🔑🔑🔑🔑 {GH}");
    let matches = detect_secrets(&text, &default_config());
    assert_eq!(matches.len(), 1);
    let m = matches[0];
    assert_eq!(m.kind, SecretKind::GithubToken);
    assert_eq!(m.start, 5); // 4 emoji + 1 space (char indices, not bytes)
    assert_eq!(m.end, 5 + GH.chars().count() as u32);
}

#[test]
fn high_entropy_is_medium_confidence() {
    let text = "VRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2";
    let matches = detect_secrets(text, &default_config());
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].kind, SecretKind::HighEntropyString);
    assert_eq!(matches[0].confidence, Confidence::Medium);
}

#[test]
fn provider_tokens_are_high_confidence() {
    let matches = detect_secrets(GH, &default_config());
    assert_eq!(matches[0].confidence, Confidence::High);
}

#[test]
fn user_rule_matches_and_invalid_rule_is_reported() {
    let cfg = MaskConfig {
        user_rules: vec![
            UserRule {
                name: "employee-id".into(),
                regex: r"EMP-\d{5}".into(),
                kind_label: "Employee ID".into(),
            },
            UserRule {
                name: "broken".into(),
                regex: r"([".into(), // does not compile
                kind_label: "Broken".into(),
            },
        ],
        ..default_config()
    };

    let matches = detect_secrets("ticket for EMP-12345 please", &cfg);
    assert!(matches.iter().any(|m| m.kind == SecretKind::UserDefined));
    assert_eq!(user_rule_errors(&cfg), vec!["broken".to_string()]);
}

#[test]
fn url_secret_suppresses_overlapping_key_value_match() {
    let text = "see https://x.test/cb?password=superSecretValue123 now";
    let kinds: Vec<SecretKind> = detect_secrets(text, &default_config())
        .iter()
        .map(|m| m.kind)
        .collect();
    assert_eq!(kinds, vec![SecretKind::UrlEmbeddedSecret]);
}

#[test]
fn empty_text_is_safe() {
    assert!(!is_secret("", &default_config()));
    assert_eq!(mask("", &default_config()), "");
    assert!(detect_secrets("", &default_config()).is_empty());
}
