//! Frozen format versions (M10 foundation freeze).
//!
//! Bumping any of these is a breaking change: it must add KAT vectors (never delete the old ones)
//! and `decode_*` must reject an unknown version with [`crate::CoreError::UnsupportedFormat`]
//! rather than misparse it.

/// `RecordEnvelope` / `.cclip` wire version.
pub const RECORD_FORMAT_VERSION: u32 = 1;
/// `VaultManifest` / `vault.json` version.
pub const VAULT_FORMAT_VERSION: u32 = 1;
/// `DeviceDescriptor` version.
pub const DEVICE_FORMAT_VERSION: u32 = 1;
