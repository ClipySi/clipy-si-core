//! Bundled UniFFI binding generator. Run in library mode:
//!   cargo run --bin uniffi-bindgen -- generate --library <dylib> --language swift --out-dir <dir>
fn main() {
    uniffi::uniffi_bindgen_main()
}
