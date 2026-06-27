//! Configuration types and ruleset versioning.

/// Version of the detection ruleset. **Bump whenever detection or mask output changes**
/// so KAT regressions catch drift and cross-binding consumers can pin behaviour.
pub const RULES_VERSION: u32 = 1;

/// How a detected-secret string is rendered for display.
///
/// All styles operate on the **whole** text (not just the matched span): when any secret
/// is present the safe default is to hide the entire value. Span-level partial masking is
/// a future option.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MaskStyle {
    /// Default: replace every character with a bullet (hides the whole value).
    #[default]
    Full,
    /// Keep the first two characters, mask the rest.
    Prefix2,
    /// Keep the last four characters, mask the rest.
    Suffix4,
}

/// A user-supplied detection rule.
///
/// A `regex` that fails to compile is **non-fatal**: the rule is skipped and its `name` is
/// reported by [`super::user_rule_errors`]. `kind_label` is a display label only — it must
/// never carry a matched value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRule {
    pub name: String,
    pub regex: String,
    pub kind_label: String,
}

/// Configuration for detection + masking. Build from [`default_config`] and adjust.
#[derive(Clone, Debug, PartialEq)]
pub struct MaskConfig {
    /// When `false`, [`mask`](super::mask) returns the text unchanged. Detection queries
    /// ([`detect_secrets`](super::detect_secrets) / [`is_secret`](super::is_secret)) ignore
    /// this flag and always report the truth.
    pub enabled: bool,
    pub style: MaskStyle,
    /// Minimum length (in Unicode scalars) for a high-entropy candidate.
    pub min_entropy_len: u32,
    /// Shannon-entropy threshold (bits/char) for a high-entropy candidate.
    pub entropy_bits: f64,
    pub user_rules: Vec<UserRule>,
}

impl Default for MaskConfig {
    fn default() -> Self {
        default_config()
    }
}

/// The default configuration: masking **ON**, style **Full**, entropy heuristics tuned for
/// precision (few false positives). Each OS `registerDefaults` mirrors these values.
///
/// `min_entropy_len`/`entropy_bits` are raised above the original design draft (20 / 3.5)
/// after the M8.1 adversarial review found 3.5 bits/char admits ordinary camelCase/English
/// text; see `entropy.rs` for the additional normalized-entropy guard.
pub fn default_config() -> MaskConfig {
    MaskConfig {
        enabled: true,
        style: MaskStyle::Full,
        min_entropy_len: 24,
        entropy_bits: 4.0,
        user_rules: Vec::new(),
    }
}

/// The detection ruleset version. See [`RULES_VERSION`].
pub fn rules_version() -> u32 {
    RULES_VERSION
}
