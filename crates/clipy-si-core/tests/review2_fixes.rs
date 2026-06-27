//! Regression tests for the SECOND adversarial review (workflow m8-1-review2) of the
//! post-hardening detector. Pins the new precision fixes (value-gated structural matches,
//! data-URI exclusion, env-var recall) so they cannot silently regress.

use clipy_si_core::{default_config, detect_secrets, is_secret, SecretKind};

fn secret(t: &str) -> bool {
    is_secret(t, &default_config())
}

fn kinds(t: &str) -> Vec<SecretKind> {
    detect_secrets(t, &default_config())
        .iter()
        .map(|m| m.kind)
        .collect()
}

// --- AUTHZ_BEARER no longer over-matches prose / placeholders ----------------------------

#[test]
fn authorization_header_prose_not_masked() {
    assert!(!secret("Authorization: basic understanding required"));
    assert!(!secret(
        "X-Authorization: token endpoints documented somewhere"
    ));
    assert!(!secret("authorization: bearer shareholders meeting notes"));
    assert!(!secret("Authorization: basic authentication is deprecated"));
    assert!(!secret(
        "Proxy-Authorization: token validation happens server-side"
    ));
}

#[test]
fn authorization_header_placeholders_not_masked() {
    assert!(!secret("Authorization: Bearer YOUR_ACCESS_TOKEN"));
    assert!(!secret("Authorization: Bearer {{token}}"));
    assert!(!secret("Authorization: Bearer $ACCESS_TOKEN"));
}

#[test]
fn real_authorization_credentials_still_detected() {
    assert!(secret("Authorization: Bearer mF_9.B5f-4.1JqM"));
    assert!(kinds("Authorization: Bearer ya29.A0ARrdaM9xKp2Qm").contains(&SecretKind::BearerToken));
}

// --- KeyValueSecret value gate no longer masks code/config/prose -------------------------

#[test]
fn key_value_code_and_config_not_masked() {
    assert!(!secret("interface X { password: string; secret: number }"));
    assert!(!secret("password: string"));
    assert!(!secret("secret: this_is_documentation_text"));
    assert!(!secret("private_key: /etc/ssl/private/server.key"));
    assert!(!secret("secret: my-app-tls-certificate"));
    assert!(!secret("access_key: enabled"));
    assert!(!secret("secret_key: development"));
    assert!(!secret("password: correct horse battery staple"));
}

#[test]
fn real_key_values_still_detected() {
    assert!(kinds("password=hunter2zzzz").contains(&SecretKind::KeyValueSecret));
    // all-caps WITHOUT underscores is a real secret, not an env-name placeholder (#8)
    assert!(kinds("secret_key=ABCD1234EFGH5678").contains(&SecretKind::KeyValueSecret));
    // base64 secret containing '/' is kept (path gate must not eat it)
    assert!(kinds("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG1bPxRfi")
        .contains(&SecretKind::KeyValueSecret));
}

#[test]
fn placeholder_substring_in_real_secret_not_dropped() {
    // values that merely CONTAIN a placeholder word as a substring are still secrets (#9/#15)
    assert!(secret("password=hunter2NONEzzz"));
    assert!(secret("secret=reSampleDataXYZ9"));
}

#[test]
fn env_var_password_detected() {
    // leading anchor allows a preceding '_' so SCREAMING_SNAKE env vars are caught (#5)
    assert!(secret("DB_PASSWORD=s3cr3tDbPassXY"));
    assert!(secret("export STRIPE_SECRET_KEY=rk2LiveValueABC9"));
}

// --- URL / connection-string gating ------------------------------------------------------

#[test]
fn benign_url_token_and_client_id_not_masked() {
    assert!(!secret(
        "https://help.site/page?token=getting-started-guide"
    ));
    assert!(!secret(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id=12345.apps.googleusercontent.com"
    ));
}

#[test]
fn connection_string_placeholders_and_defaults_not_masked() {
    assert!(!secret("amqp://guest:guest@localhost:5672")); // RabbitMQ default demo creds
    assert!(!secret("ftp://anonymous:guest@ftp.example.com/pub"));
    assert!(!secret("postgres://USERNAME:PASSWORD@HOST:5432/DB")); // doc template
    assert!(!secret("Visit foo://x:y@z please")); // unknown scheme + short value
}

// --- data: URI image payloads (containing '/') no longer flag ----------------------------

#[test]
fn data_uri_with_slash_not_masked() {
    assert!(!secret(
        "data:image/png;base64,iVBORw0KGgo/AAANSUhEUg//AAAAEAA+AAABCAYAAAAf/FcSJ123XyZ=="
    ));
}

// --- new provider literals ---------------------------------------------------------------

#[test]
fn additional_provider_tokens_detected() {
    // SendGrid SG.<22>.<43>
    assert!(
        kinds("SG.0123456789abcdefABCDEF.0123456789012345678901234567890123456789abc")
            .contains(&SecretKind::ApiToken)
    );
    // npm npm_<36>
    assert!(kinds("npm_0123456789abcdefghijklmnopqrstuvwxyz").contains(&SecretKind::ApiToken));
    // Slack app-level token
    assert!(
        kinds("xapp-1-A012345678-0123456789-abcdef0123456789").contains(&SecretKind::SlackToken)
    );
}
