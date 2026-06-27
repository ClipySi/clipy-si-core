//! Detection orchestration: run every pattern source, resolve overlaps, return char-indexed
//! [`SecretMatch`]es.

use super::rules::MaskConfig;
use super::{entropy, patterns};

/// A detected secret span.
///
/// `start`/`end` are **Unicode scalar (`char`) offsets**, end-exclusive. Bindings must map
/// them through the scalar view, NOT a grapheme-based string index:
/// - Swift: `text.unicodeScalars.index(_:offsetBy:)` (NOT `String.Index`/`offsetBy:`, which
///   counts `Character`/grapheme clusters).
/// - .NET: convert the scalar offset to a UTF-16 code-unit index (a scalar may be 2 units).
///
/// `#[non_exhaustive]` so future fields (e.g. a display label) are additive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SecretMatch {
    pub kind: SecretKind,
    pub start: u32,
    pub end: u32,
    pub confidence: Confidence,
}

/// The category of a detected secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretKind {
    GithubToken,
    OpenAiKey,
    StripeKey,
    GitlabToken,
    AwsAccessKeyId,
    Jwt,
    SlackToken,
    GoogleApiKey,
    PrivateKeyBlock,
    BearerToken,
    UrlEmbeddedSecret,
    KeyValueSecret,
    /// A distinctive-prefix provider token without a dedicated kind (SendGrid, npm, …).
    ApiToken,
    HighEntropyString,
    UserDefined,
}

impl SecretKind {
    /// Stable identifier used by the KAT vectors and FFI labels.
    pub fn as_str(self) -> &'static str {
        match self {
            SecretKind::GithubToken => "GithubToken",
            SecretKind::OpenAiKey => "OpenAiKey",
            SecretKind::StripeKey => "StripeKey",
            SecretKind::GitlabToken => "GitlabToken",
            SecretKind::AwsAccessKeyId => "AwsAccessKeyId",
            SecretKind::Jwt => "Jwt",
            SecretKind::SlackToken => "SlackToken",
            SecretKind::GoogleApiKey => "GoogleApiKey",
            SecretKind::PrivateKeyBlock => "PrivateKeyBlock",
            SecretKind::BearerToken => "BearerToken",
            SecretKind::UrlEmbeddedSecret => "UrlEmbeddedSecret",
            SecretKind::KeyValueSecret => "KeyValueSecret",
            SecretKind::ApiToken => "ApiToken",
            SecretKind::HighEntropyString => "HighEntropyString",
            SecretKind::UserDefined => "UserDefined",
        }
    }
}

/// How sure the detector is. High = a definite literal pattern; Medium = an entropy heuristic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Confidence {
    High,
    Medium,
}

/// Internal match in **byte** offsets (regex/entropy work in bytes; converted to chars last).
pub(crate) struct RawMatch {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) kind: SecretKind,
    pub(crate) confidence: Confidence,
}

/// Enumerate the secret spans in `text` (overlaps merged: earliest start wins, ties broken
/// by higher confidence then longer span). Ignores `config.enabled`.
pub fn detect_secrets(text: &str, config: &MaskConfig) -> Vec<SecretMatch> {
    let kept = merge_non_overlapping(collect_raw(text, config));
    if kept.is_empty() {
        return Vec::new();
    }
    // kept is sorted by start and non-overlapping, so [start0, end0, start1, …] is monotonic
    // non-decreasing — convert all byte boundaries to char offsets in a single pass.
    let mut boundaries = Vec::with_capacity(kept.len() * 2);
    for m in &kept {
        boundaries.push(m.start);
        boundaries.push(m.end);
    }
    let chars = byte_to_char_offsets(text, &boundaries);
    kept.iter()
        .enumerate()
        .map(|(i, m)| SecretMatch {
            kind: m.kind,
            start: chars[i * 2],
            end: chars[i * 2 + 1],
            confidence: m.confidence,
        })
        .collect()
}

/// `true` if `text` contains at least one secret. Ignores `config.enabled`.
pub fn is_secret(text: &str, config: &MaskConfig) -> bool {
    !collect_raw(text, config).is_empty()
}

/// Names of user rules whose regex failed to compile (values never included).
pub fn user_rule_errors(config: &MaskConfig) -> Vec<String> {
    patterns::user_rule_errors(config)
}

fn collect_raw(text: &str, config: &MaskConfig) -> Vec<RawMatch> {
    let mut all = Vec::new();
    patterns::provider_matches(text, &mut all);
    patterns::gated_literal_matches(text, &mut all);

    let mut urls = Vec::new();
    patterns::url_matches(text, &mut urls);
    let url_spans: Vec<(usize, usize)> = urls.iter().map(|m| (m.start, m.end)).collect();

    let mut kv = Vec::new();
    patterns::kv_matches(text, &mut kv);
    // A sensitive query param inside a URL is reported as UrlEmbeddedSecret, not KeyValueSecret.
    kv.retain(|m| !overlaps_any(m.start, m.end, &url_spans));

    all.append(&mut urls);
    all.append(&mut kv);
    patterns::user_matches(text, config, &mut all);

    // High-entropy strings fill spans not already claimed by a literal pattern, nor by an inline
    // data: URI blob (whose base64 `/` would otherwise fragment into qualifying runs).
    let mut occupied: Vec<(usize, usize)> = all.iter().map(|m| (m.start, m.end)).collect();
    occupied.extend(patterns::data_uri_spans(text));
    entropy::high_entropy_matches(text, config, &occupied, &mut all);
    all
}

fn merge_non_overlapping(mut raws: Vec<RawMatch>) -> Vec<RawMatch> {
    raws.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| conf_rank(b.confidence).cmp(&conf_rank(a.confidence)))
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
    });
    let mut kept: Vec<RawMatch> = Vec::new();
    let mut last_end = 0usize;
    for m in raws {
        if kept.is_empty() || m.start >= last_end {
            last_end = m.end;
            kept.push(m);
        }
    }
    kept
}

fn conf_rank(c: Confidence) -> u8 {
    match c {
        Confidence::High => 1,
        Confidence::Medium => 0,
    }
}

fn overlaps_any(start: usize, end: usize, spans: &[(usize, usize)]) -> bool {
    spans.iter().any(|&(s, e)| start < e && s < end)
}

/// Convert a list of **monotonic non-decreasing** byte offsets to char (scalar) offsets in a
/// single left-to-right walk — O(n) total instead of O(boundaries · n).
fn byte_to_char_offsets(text: &str, sorted_bytes: &[usize]) -> Vec<u32> {
    let mut out = Vec::with_capacity(sorted_bytes.len());
    let mut chars = text.char_indices();
    // Count in `usize` and saturate to `u32` on push. A text longer than `u32::MAX` scalars
    // (~4.3e9 — unreachable for a clipboard item, but the FFI accepts arbitrary input) must
    // neither panic (debug overflow check) nor silently wrap (release) into a corrupt span; it
    // clamps to `u32::MAX` instead. Normal inputs are unaffected.
    let mut char_idx = 0usize;
    let mut next = chars.next();
    for &target in sorted_bytes {
        while let Some((byte, _)) = next {
            if byte >= target {
                break;
            }
            char_idx += 1;
            next = chars.next();
        }
        out.push(u32::try_from(char_idx).unwrap_or(u32::MAX));
    }
    out
}
