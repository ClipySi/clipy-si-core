//! High-confidence literal patterns (provider/format tokens, connection-string, URL/key-value
//! and bearer secrets) plus user rules. Each helper appends byte-offset [`RawMatch`]es; overlap
//! resolution and the char-index conversion happen in [`super::detector`].
//!
//! Structurally-ambiguous shapes (kv, URL query, connection-string userinfo, Authorization
//! header) capture their *value* and pass it through [`looks_like_secret_value`] so ordinary
//! code/config/prose (`password: string`, `?token=getting-started`, `postgres://USER:PASSWORD@`)
//! is not masked. Pure provider tokens (GitHub/Stripe/…) are unambiguous by prefix+shape and
//! are not value-gated.

use std::sync::LazyLock;

use regex::Regex;

use super::detector::RawMatch;
use super::rules::MaskConfig;
use super::{Confidence, SecretKind};

// --- Provider / format tokens (all High confidence, no value gating) ---------------------

static GITHUB_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgh[posru]_[A-Za-z0-9]{36,255}\b").unwrap());
static GITHUB_PAT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{40,255}\b").unwrap());
static OPENAI_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b").unwrap());
static STRIPE_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b").unwrap());
static GITLAB_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bglpat-[A-Za-z0-9_-]{20,}\b").unwrap());
static AWS_ACCESS_KEY_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b").unwrap()
});
// JWT: three base64url segments; the leading `eyJ` ( == `{"` ) makes false matches rare.
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}").unwrap()
});
// Slack: bot/user/app/refresh tokens (xox[bapsre]-) and app-level tokens (xapp-).
static SLACK_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:xox[baprse]|xapp)-[A-Za-z0-9-]{10,}\b").unwrap());
static SLACK_WEBHOOK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}")
        .unwrap()
});
static GOOGLE_API_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAIza[A-Za-z0-9_-]{35}\b").unwrap());
// Google OAuth client secret (GOCSPX-…). Reuses the GoogleApiKey kind.
static GOOGLE_OAUTH_SECRET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b").unwrap());
static SENDGRID_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b").unwrap());
static NPM_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bnpm_[A-Za-z0-9]{36}\b").unwrap());
static PRIVATE_KEY_BLOCK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----").unwrap());

// --- Value-gated structural secrets ------------------------------------------------------

// scheme://user:pass@host — password in URI userinfo (DB/broker connection strings). Scheme is
// restricted to a known set and the password is value-gated (rejects placeholder/default creds).
static CONNECTION_STRING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:https?|postgres|postgresql|mysql|mariadb|mongodb|mongodb\+srv|redis|rediss",
        r"|amqp|amqps|ftp|ftps|sftp|ssh|smtp|smtps|imap|imaps|ldap|ldaps|kafka|nats|mqtt|mqtts)",
        r"://[^/\s:@]*:(?P<val>[^/\s:@]+)@"
    ))
    .unwrap()
});

// HTTP Authorization header carrying a bearer/basic/token credential. Anchored on the header
// name; the credential is a credential-shaped token (no spaces) and value-gated, so prose like
// "Authorization: basic understanding" or "Bearer YOUR_TOKEN" / "{{token}}" does not match.
static AUTHZ_BEARER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\b(?:proxy-)?authorization\s*:\s*(?:bearer|basic|token)\s+",
        r"(?P<val>[A-Za-z0-9._~+/=-]{8,})"
    ))
    .unwrap()
});

// A URL carrying a sensitive query parameter (value-gated). Bare/generic params (key/sig/auth)
// and the public `client_id` are deliberately excluded.
static URL_EMBEDDED_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\bhttps?://[^\s]*[?&]",
        r"(?:access_token|refresh_token|id_token|auth_token|token|api[_-]?key",
        r"|client_secret|password|passwd|pwd|signature)",
        r"=(?P<val>[^\s&#]{3,})"
    ))
    .unwrap()
});

// key=value / key: value secrets outside a URL (value-gated). The leading anchor allows a
// preceding `_` so SCREAMING_SNAKE env vars (DB_PASSWORD=…) are caught.
static KEY_VALUE_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)(?:^|[^A-Za-z0-9])(?:password|passwd|pwd|secret|api[_-]?key|client_secret"#,
        r#"|secret_key|access_key|aws_secret_access_key|private_key|auth_token)"#,
        r#"\s*[:=]\s*["']?(?P<val>[^\s"']{4,})"#
    ))
    .unwrap()
});

// `data:[mediatype];base64,<payload>` — an inline blob (often an image). Used to exclude the
// whole payload from entropy scanning (the payload's `/` would otherwise fragment it).
static DATA_URI: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bdata:[^,\s]*;base64,[A-Za-z0-9+/=]+").unwrap());

// Unambiguous placeholder substrings (checked with `contains`, so suffixes like
// `changeme123` are caught).
const STRONG_PLACEHOLDER_FRAGMENTS: &[&str] = &[
    "changeme",
    "change_me",
    "change-me",
    "replaceme",
    "replace_me",
    "replace-me",
    "placeholder",
    "yourkey",
    "your_key",
    "your-key",
    "yourapikey",
    "your_api_key",
    "yoursecret",
    "your_secret",
    "examplekey",
    "example_key",
    "insertyour",
    "xxxxxxxx",
];

// Placeholder words matched only as a *whole* token (split on non-alphanumerics) so a real
// secret that merely contains one as a substring (e.g. `hunter2NONEzzz`) is not dropped.
const PLACEHOLDER_WORDS: &[&str] = &[
    "your",
    "yours",
    "replace",
    "example",
    "sample",
    "placeholder",
    "todo",
    "fixme",
    "dummy",
    "redacted",
    "none",
    "null",
    "nil",
    "undefined",
    "here",
    "change",
    "changeme",
    "username",
    "password",
    "passwd",
    "user",
    "pass",
    "host",
    "secret",
    "test",
    "foo",
    "bar",
    "baz",
    "xxx",
    "xxxx",
];

/// Append all ungated provider/format token matches.
pub(crate) fn provider_matches(text: &str, out: &mut Vec<RawMatch>) {
    push_all(&GITHUB_TOKEN, text, SecretKind::GithubToken, out);
    push_all(&GITHUB_PAT, text, SecretKind::GithubToken, out);
    push_all(&OPENAI_KEY, text, SecretKind::OpenAiKey, out);
    push_all(&STRIPE_KEY, text, SecretKind::StripeKey, out);
    push_all(&GITLAB_TOKEN, text, SecretKind::GitlabToken, out);
    push_all(&AWS_ACCESS_KEY_ID, text, SecretKind::AwsAccessKeyId, out);
    push_all(&JWT, text, SecretKind::Jwt, out);
    push_all(&SLACK_TOKEN, text, SecretKind::SlackToken, out);
    push_all(&SLACK_WEBHOOK, text, SecretKind::SlackToken, out);
    push_all(&GOOGLE_API_KEY, text, SecretKind::GoogleApiKey, out);
    push_all(&GOOGLE_OAUTH_SECRET, text, SecretKind::GoogleApiKey, out);
    push_all(&SENDGRID_KEY, text, SecretKind::ApiToken, out);
    push_all(&NPM_TOKEN, text, SecretKind::ApiToken, out);
    push_all(&PRIVATE_KEY_BLOCK, text, SecretKind::PrivateKeyBlock, out);
}

/// Append value-gated connection-string + Authorization-header matches.
pub(crate) fn gated_literal_matches(text: &str, out: &mut Vec<RawMatch>) {
    push_gated(&CONNECTION_STRING, text, SecretKind::UrlEmbeddedSecret, out);
    push_gated(&AUTHZ_BEARER, text, SecretKind::BearerToken, out);
}

/// Append value-gated URL-embedded-secret matches.
pub(crate) fn url_matches(text: &str, out: &mut Vec<RawMatch>) {
    push_gated(
        &URL_EMBEDDED_SECRET,
        text,
        SecretKind::UrlEmbeddedSecret,
        out,
    );
}

/// Append value-gated key-value-secret matches.
pub(crate) fn kv_matches(text: &str, out: &mut Vec<RawMatch>) {
    push_gated(&KEY_VALUE_SECRET, text, SecretKind::KeyValueSecret, out);
}

/// Byte spans of `data:…;base64,<payload>` blobs (excluded from entropy scanning).
pub(crate) fn data_uri_spans(text: &str) -> Vec<(usize, usize)> {
    DATA_URI
        .find_iter(text)
        .map(|m| (m.start(), m.end()))
        .collect()
}

/// Append user-rule matches. Rules whose regex fails to compile are silently skipped here
/// (reported separately by [`user_rule_errors`]).
//
// NOTE: user rules are (re)compiled on each call. Built-ins are LazyLock-cached; user rules are
// not, because MaskConfig is a value type recreated across the FFI boundary every call. For the
// common case (no user rules) this is free; a compiled-rules handle is a future optimization if
// large user-rule sets land.
//
// SECURITY/PERF: the `regex` crate matches in guaranteed linear time (finite automata, no
// backtracking) and enforces a default compiled-program size limit, so an adversarial user
// pattern cannot cause ReDoS or unbounded memory here — only compile cost, which the size limit
// bounds. As of M8 no UI populates `user_rules`, so this path is dormant; the future rule editor
// should still validate `Regex::new` at edit time and surface failures via `user_rule_errors`.
pub(crate) fn user_matches(text: &str, config: &MaskConfig, out: &mut Vec<RawMatch>) {
    for rule in &config.user_rules {
        if let Ok(re) = Regex::new(&rule.regex) {
            push_all(&re, text, SecretKind::UserDefined, out);
        }
    }
}

/// Names of user rules whose regex failed to compile (values never included).
pub(crate) fn user_rule_errors(config: &MaskConfig) -> Vec<String> {
    config
        .user_rules
        .iter()
        .filter(|rule| Regex::new(&rule.regex).is_err())
        .map(|rule| rule.name.clone())
        .collect()
}

/// Reject placeholder/example/benign values so structural matches don't mask ordinary
/// code/config/prose. A value qualifies as secret-like when it is long enough, not a path, not
/// a placeholder, and carries a non-dictionary signal (a digit, an uppercase letter, or a
/// base64 special) rather than being a single lowercase word/type-name.
fn looks_like_secret_value(value: &str) -> bool {
    let trimmed = value.trim_matches(|c| c == '"' || c == '\'');
    if trimmed.chars().count() < 8 {
        return false;
    }
    if is_pathlike(trimmed) {
        return false; // file paths (but keep base64 secrets that merely contain '/')
    }
    // SCREAMING_SNAKE env-name placeholder — must contain '_' (so a real all-caps token without
    // separators is not wrongly rejected).
    if trimmed.contains('_')
        && trimmed
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if STRONG_PLACEHOLDER_FRAGMENTS
        .iter()
        .any(|frag| lower.contains(frag))
    {
        return false;
    }
    if lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| !tok.is_empty() && PLACEHOLDER_WORDS.contains(&tok))
    {
        return false;
    }
    // Require a non-dictionary signal: digit, uppercase, or base64 special.
    trimmed
        .chars()
        .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase() || matches!(c, '+' | '='))
}

/// `true` if `v` looks like a filesystem path rather than a credential. A leading path marker,
/// or a `/`-containing all-lowercase value (e.g. `etc/ssl/server.key`) is a path; a `/`-bearing
/// base64 secret (which carries digits/uppercase) is not.
fn is_pathlike(v: &str) -> bool {
    v.starts_with('/')
        || v.starts_with('~')
        || v.starts_with("./")
        || v.starts_with("../")
        || (v.contains('/')
            && !v
                .chars()
                .any(|c| c.is_ascii_digit() || c.is_ascii_uppercase()))
}

fn push_all(re: &Regex, text: &str, kind: SecretKind, out: &mut Vec<RawMatch>) {
    for m in re.find_iter(text) {
        // Skip empty matches defensively (a user rule like `a*` can match empty).
        if m.end() > m.start() {
            out.push(RawMatch {
                start: m.start(),
                end: m.end(),
                kind,
                confidence: Confidence::High,
            });
        }
    }
}

/// Like [`push_all`] but only when the named `val` capture passes [`looks_like_secret_value`].
fn push_gated(re: &Regex, text: &str, kind: SecretKind, out: &mut Vec<RawMatch>) {
    for caps in re.captures_iter(text) {
        let whole = caps.get(0).unwrap();
        let value = caps.name("val").map_or("", |m| m.as_str());
        if looks_like_secret_value(value) {
            out.push(RawMatch {
                start: whole.start(),
                end: whole.end(),
                kind,
                confidence: Confidence::High,
            });
        }
    }
}
