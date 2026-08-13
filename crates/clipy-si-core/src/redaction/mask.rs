//! Mask rendering. Operates on the whole text per [`MaskStyle`] (see its docs for why the
//! whole value is hidden rather than just the matched span).

use super::detector::is_secret;
use super::rules::{MaskConfig, MaskStyle};

const BULLET: char = '\u{2022}'; // •

/// One-pass verdict + display for a single text (M-UI.11 P1-R).
///
/// `#[non_exhaustive]` so future fields (e.g. a dominant [`super::SecretKind`]) are additive.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MaskEvaluation {
    /// A secret was detected. Like [`is_secret`], this ignores `config.enabled` — the verdict
    /// is still needed (sensitivity flags, auth gates) when masked *display* is off.
    pub is_secret: bool,
    /// What to render: `text` unchanged when `config.enabled == false` or no secret was
    /// detected, otherwise `config.style` applied to the whole string. Identical to [`mask`].
    pub display: String,
}

/// Evaluate `text` once: the detector runs a single time and both the verdict and the
/// display string are derived from that one result.
///
/// Equivalent to `(is_secret(text, config), mask(text, config))`, which runs the detector
/// twice; [`mask`] delegates here so the equivalence is by construction, not by parallel
/// implementations.
pub fn evaluate(text: &str, config: &MaskConfig) -> MaskEvaluation {
    let is_secret = is_secret(text, config);
    let display = if !config.enabled || !is_secret {
        text.to_string()
    } else {
        let len = text.chars().count();
        match config.style {
            MaskStyle::Full => bullets(len),
            MaskStyle::Prefix2 => keep_prefix(text, 2, len),
            MaskStyle::Suffix4 => keep_suffix(text, 4, len),
        }
    };
    MaskEvaluation { is_secret, display }
}

/// Return a display-safe rendering of `text`.
///
/// - `config.enabled == false` → `text` unchanged.
/// - No secret detected → `text` unchanged (a false-positive-free string stays readable).
/// - Otherwise apply `config.style` to the whole string.
pub fn mask(text: &str, config: &MaskConfig) -> String {
    if !config.enabled {
        // Preserve the historical zero-cost path: disabled display never runs the detector
        // here (callers that also need the verdict use `evaluate`/`is_secret`).
        return text.to_string();
    }
    evaluate(text, config).display
}

fn bullets(n: usize) -> String {
    let mut s = String::with_capacity(n * BULLET.len_utf8());
    for _ in 0..n {
        s.push(BULLET);
    }
    s
}

// NOTE: keep_prefix/keep_suffix keep `keep` Unicode scalars, not grapheme clusters, so a
// kept edge could in theory split an emoji ZWJ sequence or combining mark. Acceptable for the
// non-default Prefix2/Suffix4 styles (the default Full masks everything); revisit with
// grapheme segmentation if these styles graduate from "reveal a hint" to a primary mode.
fn keep_prefix(text: &str, keep: usize, len: usize) -> String {
    if len <= keep {
        return bullets(len);
    }
    let head: String = text.chars().take(keep).collect();
    head + &bullets(len - keep)
}

fn keep_suffix(text: &str, keep: usize, len: usize) -> String {
    if len <= keep {
        return bullets(len);
    }
    let tail: String = text.chars().skip(len - keep).collect();
    bullets(len - keep) + &tail
}
