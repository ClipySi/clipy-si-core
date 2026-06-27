//! Regression tests for the M8.1 adversarial-review findings (workflow m8-redaction-review).
//! Each test pins a confirmed false-negative now caught or a confirmed false-positive now
//! suppressed, so the precision/recall tuning cannot silently regress.

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

// --- false negatives now caught (High-confidence literals) -------------------------------

#[test]
fn connection_string_credentials_detected() {
    assert!(secret(
        "postgres://admin:S3cr3tPass@db.example.com:5432/mydb"
    ));
    assert!(secret(
        "mongodb+srv://dbuser:Pa55w0rd!@cluster0.abcd.mongodb.net/test"
    ));
    assert!(secret("redis://:authpassword123@redis.example.com:6379/0")); // empty username
    assert!(kinds("postgres://admin:S3cr3tPass@db/x").contains(&SecretKind::UrlEmbeddedSecret));
}

#[test]
fn host_port_and_scp_are_not_connection_secrets() {
    assert!(!secret("https://example.com:8080/path")); // host:port, no user:pass@
    assert!(!secret("git@github.com:user/repo.git")); // scp-style, no scheme://
    assert!(!secret("ssh://git@github.com/owner/repo")); // user but no password
}

#[test]
fn slack_webhook_detected() {
    let url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
    assert!(kinds(url).contains(&SecretKind::SlackToken));
}

#[test]
fn google_oauth_client_secret_detected() {
    assert!(kinds("GOCSPX-1234567890abcdefghijklmn").contains(&SecretKind::GoogleApiKey));
}

#[test]
fn bearer_authorization_header_detected() {
    assert!(secret("Authorization: Bearer mF_9.B5f-4.1JqM"));
    assert!(secret("curl -H 'Authorization: Bearer a1b2c3d4e5f6g7h8'"));
    assert!(kinds("Authorization: Bearer mF_9.B5f-4.1JqM").contains(&SecretKind::BearerToken));
}

#[test]
fn bearer_word_in_prose_not_detected() {
    assert!(!secret(
        "the bearer responsibilities are described in section three"
    ));
}

#[test]
fn stripe_secret_keys_detected() {
    assert!(kinds("sk_live_4eC39HqLyjWDarjtT1zdp7dc").contains(&SecretKind::StripeKey));
    assert!(kinds("rk_live_4eC39HqLyjWDarjtT1zdp7dc").contains(&SecretKind::StripeKey));
}

#[test]
fn gitlab_pat_detected() {
    assert!(kinds("glpat-ABCDEFGHIJ1234567890").contains(&SecretKind::GitlabToken));
}

// --- false positives now suppressed ------------------------------------------------------

#[test]
fn snake_case_identifiers_not_masked() {
    assert!(!secret("get_user_by_id_and_organization_2024"));
    assert!(!secret("DEFAULT_TIMEOUT_IN_MILLISECONDS_30000"));
    assert!(!secret("MyApp_SessionIdentifier_2024_v3_ProductionBuild"));
}

#[test]
fn camelcase_identifiers_not_masked() {
    assert!(!secret("ThisIsAVeryLongCamelCaseIdentifier2024WithNumbers"));
    assert!(!secret("configurationManagerImplementation2"));
}

#[test]
fn placeholder_key_values_not_masked() {
    assert!(!secret("apiKey = \"TODO\""));
    assert!(!secret("password = \"changeme123\""));
    assert!(!secret("api_key: REPLACE_ME_WITH_REAL_KEY"));
    assert!(!secret("api_key=YOUR_API_KEY_HERE"));
}

#[test]
fn benign_url_query_params_not_masked() {
    assert!(!secret(
        "https://fonts.googleapis.com/css?family=Roboto&key=display"
    ));
    assert!(!secret(
        "https://cdn.example.com/app.css?key=v2BuildHash20240607release"
    ));
    assert!(!secret("https://cdn.test/img.png?sig=deadbeef"));
    assert!(!secret("https://x.test/p?auth=true&next=home"));
}

#[test]
fn file_paths_not_masked() {
    assert!(!secret(
        "/Users/alice/Library/Developer/Xcode/DerivedData/MyApp-fghijklmnopqrstuvwxyzABCDEFGHIJ/Build/Products/Debug/MyApp.app"
    ));
    assert!(!secret("src/components/UserProfile/UserProfileView_v2.tsx"));
}

#[test]
fn base64_of_ordinary_data_not_masked() {
    // base64 of plain prose (entropy below random)
    assert!(!secret(
        "TG9yZW1JcHN1bURvbG9yU2l0QW1ldENvbnNlY3RldHVyQWRpcGlzY2luZ0VsaXQ="
    ));
    // data: URI image payload is explicitly skipped
    assert!(!secret(
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    ));
}

// --- existing positives preserved --------------------------------------------------------

#[test]
fn real_key_value_and_high_entropy_still_detected() {
    assert!(kinds("password=hunter2zzzz").contains(&SecretKind::KeyValueSecret));
    assert!(kinds("VRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2")
        .contains(&SecretKind::HighEntropyString));
}
