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

// -------------------------------------------------------------------------------------------
// One-pass `evaluate` parity (M-UI.11 P1-R). The KAT vectors carry a single mask_full case, so
// the primary display-parity guarantee is this grid: every config/style combination over a
// corpus that exercises every detector source and the mask-length edge cases.
//
// `mask` currently *delegates* to `evaluate`, so `e.display == mask(...)` alone would be
// tautological. The grid therefore also checks both against `expected_display`, a
// test-local re-implementation of the masking rules whose verdict comes from
// `detect_secrets` (an API `evaluate` does not call) — independent ground truth that stays
// meaningful even if `evaluate` is later re-implemented without the delegation.
// -------------------------------------------------------------------------------------------

use clipy_si_core::{evaluate, MaskEvaluation};

/// Independent oracle: what the display must be, per the documented masking rules.
fn expected_display(text: &str, cfg: &MaskConfig) -> String {
    let secret = !detect_secrets(text, cfg).is_empty();
    if !cfg.enabled || !secret {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let bullet = |n: usize| "\u{2022}".repeat(n);
    match cfg.style {
        MaskStyle::Full => bullet(chars.len()),
        MaskStyle::Prefix2 if chars.len() > 2 => {
            chars[..2].iter().collect::<String>() + &bullet(chars.len() - 2)
        }
        MaskStyle::Suffix4 if chars.len() > 4 => {
            bullet(chars.len() - 4) + &chars[chars.len() - 4..].iter().collect::<String>()
        }
        // len <= keep: never echo through the keep window.
        _ => bullet(chars.len()),
    }
}

/// Inputs covering: empty, plain, provider token, entropy heuristic, URL/key-value secrets,
/// multi-secret, Unicode (multibyte, combining marks, ZWJ), data-URI suppression, and
/// user-rule matches shorter than the Prefix2/Suffix4 keep counts.
fn parity_corpus() -> Vec<String> {
    vec![
        String::new(),
        "just a normal clipboard note".into(),
        GH.into(),
        format!("token {GH} pasted"),
        "VRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2".into(),
        "see https://x.test/cb?password=superSecretValue123 now".into(),
        "password: superSecretValue123".into(),
        format!("{GH} and https://x.test/cb?password=superSecretValue123"),
        format!("🔑🔑🔑🔑 {GH}"),
        format!("cafe\u{301} {GH}"),               // combining acute on the prefix
        format!("👨\u{200D}👩\u{200D}👧 {GH}"),    // ZWJ family before the token
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==".into(),
        "ab".into(),   // user-rule secret, len == Prefix2 keep
        "abc".into(),  // user-rule secret, len < Suffix4 keep
    ]
}

fn parity_configs() -> Vec<MaskConfig> {
    // A rule that turns the tiny "ab"/"abc" inputs into secrets, driving keep_prefix/keep_suffix
    // through their len <= keep branches via the public API.
    let short_rule = UserRule {
        name: "short".into(),
        regex: r"^abc?$".into(),
        kind_label: "Short".into(),
    };
    let mut configs = Vec::new();
    for style in [MaskStyle::Full, MaskStyle::Prefix2, MaskStyle::Suffix4] {
        for enabled in [true, false] {
            for rules in [Vec::new(), vec![short_rule.clone()]] {
                configs.push(MaskConfig {
                    enabled,
                    style,
                    user_rules: rules,
                    ..default_config()
                });
            }
        }
    }
    configs
}

/// `evaluate` == (`is_secret`, `mask`) == the independent oracle over the whole grid, plus
/// the shape invariants a masked display must satisfy.
#[test]
fn evaluate_matches_two_pass_everywhere() {
    for cfg in parity_configs() {
        for text in parity_corpus() {
            let e: MaskEvaluation = evaluate(&text, &cfg);
            // Independent ground truth: verdict via detect_secrets, display via the
            // test-local oracle. These hold regardless of how evaluate/mask are wired.
            assert_eq!(
                e.is_secret,
                !detect_secrets(&text, &cfg).is_empty(),
                "verdict vs detect_secrets (enabled={}, style={:?})",
                cfg.enabled,
                cfg.style
            );
            assert_eq!(
                e.display,
                expected_display(&text, &cfg),
                "display vs oracle (enabled={}, style={:?})",
                cfg.enabled,
                cfg.style
            );
            // Cross-API equality (currently true by delegation; guards a future refactor
            // that re-implements either side independently).
            assert_eq!(e.is_secret, is_secret(&text, &cfg));
            assert_eq!(e.display, mask(&text, &cfg));
            if !cfg.enabled || !e.is_secret {
                assert_eq!(e.display, text, "unmasked display must be verbatim");
            } else {
                assert_eq!(
                    e.display.chars().count(),
                    text.chars().count(),
                    "masked display keeps the char count"
                );
                assert!(
                    e.display.chars().any(|c| c == '\u{2022}'),
                    "masked display must contain bullets"
                );
            }
        }
    }
}

/// The verdict stays truthful when masked display is off (sensitivity flags / auth gates
/// depend on it), while the display is verbatim.
#[test]
fn evaluate_disabled_keeps_verdict_and_text() {
    let cfg = MaskConfig {
        enabled: false,
        ..default_config()
    };
    let e = evaluate(GH, &cfg);
    assert!(e.is_secret);
    assert_eq!(e.display, GH);
}

/// Style edge: a secret no longer than the kept prefix/suffix must be fully bulleted, never
/// echoed back through the "keep" window.
#[test]
fn evaluate_short_secret_never_leaks_through_keep_window() {
    let short_rule = UserRule {
        name: "short".into(),
        regex: r"^abc?$".into(),
        kind_label: "Short".into(),
    };
    for style in [MaskStyle::Prefix2, MaskStyle::Suffix4] {
        for text in ["ab", "abc"] {
            let cfg = MaskConfig {
                style,
                user_rules: vec![short_rule.clone()],
                ..default_config()
            };
            let e = evaluate(text, &cfg);
            if text.chars().count() <= 2
                || (style == MaskStyle::Suffix4 && text.chars().count() <= 4)
            {
                assert!(e.is_secret);
                assert!(
                    e.display.chars().all(|c| c == '\u{2022}'),
                    "len <= keep must bullet everything (style={style:?}, text={text:?})"
                );
            }
        }
    }
}
