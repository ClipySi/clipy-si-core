//! High-entropy string detection — the precision-first fallback for unstructured secrets.
//!
//! A candidate is a maximal run of base64-ish characters. Separators that appear in ordinary
//! identifiers/paths/UUIDs (`-`, `_`, `/`, `.`, `:`) are **not** run bytes, so snake_case
//! constants, file paths and UUIDs fragment into short sub-runs that never qualify. A run is
//! reported only when it is long enough, mixes character classes, is not a plain hex digest,
//! clears an absolute Shannon-entropy floor **and** reaches a high fraction of the maximum
//! entropy possible for its length (the latter rejects long camelCase identifiers and base64
//! of ordinary prose, whose entropy is well below random). Masking is ON by default, so these
//! guards exist to keep false positives — visible, whole-clip masks — rare.

use super::detector::RawMatch;
use super::rules::MaskConfig;
use super::{Confidence, SecretKind};

/// A qualifying run must reach this fraction of the maximum entropy possible for its length.
/// Random tokens sit near 1.0; English/camelCase/base64-of-text sit well below. Tuned (0.85)
/// so genuinely-random ≥24-char tokens flag while camelCase identifiers and base64-of-prose
/// do not — see `tests/review_fixes.rs`.
const ENTROPY_RATIO: f64 = 0.85;
/// Cap the entropy reference at the base64 alphabet size (~64 symbols => 6 bits) so very long
/// random strings are not penalised by `log2(len)` exceeding what the alphabet can provide.
const ENTROPY_REF_CAP: f64 = 6.0;

/// Append high-entropy matches that do not overlap an already-claimed `occupied` span.
pub(crate) fn high_entropy_matches(
    text: &str,
    config: &MaskConfig,
    occupied: &[(usize, usize)],
    out: &mut Vec<RawMatch>,
) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !is_token_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_token_byte(bytes[i]) {
            i += 1;
        }
        let end = i;
        // The run is pure ASCII, so the byte slice is valid UTF-8 and len == char count.
        let run = &text[start..end];
        // `occupied` includes data: URI base64 payload spans (added by the caller), so inline
        // blobs — whose `/` would otherwise fragment them into qualifying runs — are skipped.
        if qualifies(run, config) && !overlaps_any(start, end, occupied) {
            out.push(RawMatch {
                start,
                end,
                kind: SecretKind::HighEntropyString,
                confidence: Confidence::Medium,
            });
        }
    }
}

/// Run alphabet: base64 standard letters/digits plus `+`/`=`. Deliberately excludes the
/// separators `-` `_` `/` `.` `:` so identifiers, paths and UUIDs fragment.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'=')
}

fn qualifies(run: &str, config: &MaskConfig) -> bool {
    let len = run.chars().count();
    if (len as u32) < config.min_entropy_len {
        return false;
    }
    if is_plain_hex(run) {
        return false; // MD5/SHA digests, git SHAs etc. — common and not secrets.
    }
    if class_count(run) < 3 {
        return false; // single-case words, decimal ids, hyphen-stripped UUID halves, etc.
    }
    let h = shannon_entropy(run);
    if h < config.entropy_bits {
        return false;
    }
    let reference = (len as f64).log2().min(ENTROPY_REF_CAP);
    h >= ENTROPY_RATIO * reference
}

fn is_plain_hex(run: &str) -> bool {
    run.chars().all(|c| c.is_ascii_hexdigit())
}

/// Distinct character classes among {lowercase, uppercase, digit, base64-special (`+ =`)}.
fn class_count(run: &str) -> u32 {
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut special = false;
    for c in run.chars() {
        match c {
            'a'..='z' => lower = true,
            'A'..='Z' => upper = true,
            '0'..='9' => digit = true,
            '+' | '=' => special = true,
            _ => {}
        }
    }
    u32::from(lower) + u32::from(upper) + u32::from(digit) + u32::from(special)
}

/// Shannon entropy in bits per character.
pub(crate) fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = f64::from(total);
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / total;
            -p * p.log2()
        })
        .sum()
}

fn overlaps_any(start: usize, end: usize, spans: &[(usize, usize)]) -> bool {
    spans.iter().any(|&(s, e)| start < e && s < end)
}
