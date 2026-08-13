//! Secret-redaction (masking) for the shared core.
//!
//! Pipeline: [`detect_secrets`] enumerates secret spans (provider tokens, URL/key-value
//! secrets, high-entropy strings, user rules) → [`mask`] renders a display-safe string per
//! [`MaskStyle`]. [`is_secret`] is the fast yes/no used by the UI to mark a row masked.
//! [`evaluate`] returns both in one detector pass (M-UI.11 P1-R).

mod detector;
mod entropy;
mod mask;
mod patterns;
mod rules;

pub use detector::{
    detect_secrets, is_secret, user_rule_errors, Confidence, SecretKind, SecretMatch,
};
pub use mask::{evaluate, mask, MaskEvaluation};
pub use rules::{default_config, rules_version, MaskConfig, MaskStyle, UserRule, RULES_VERSION};
