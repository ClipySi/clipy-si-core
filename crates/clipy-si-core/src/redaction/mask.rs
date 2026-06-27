//! Mask rendering. Operates on the whole text per [`MaskStyle`] (see its docs for why the
//! whole value is hidden rather than just the matched span).

use super::detector::detect_secrets;
use super::rules::{MaskConfig, MaskStyle};

const BULLET: char = '\u{2022}'; // •

/// Return a display-safe rendering of `text`.
///
/// - `config.enabled == false` → `text` unchanged.
/// - No secret detected → `text` unchanged (a false-positive-free string stays readable).
/// - Otherwise apply `config.style` to the whole string.
pub fn mask(text: &str, config: &MaskConfig) -> String {
    if !config.enabled || detect_secrets(text, config).is_empty() {
        return text.to_string();
    }
    let len = text.chars().count();
    match config.style {
        MaskStyle::Full => bullets(len),
        MaskStyle::Prefix2 => keep_prefix(text, 2, len),
        MaskStyle::Suffix4 => keep_suffix(text, 4, len),
    }
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
