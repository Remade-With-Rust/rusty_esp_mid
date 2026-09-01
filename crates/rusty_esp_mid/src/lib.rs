#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `rusty_esp_mid` — MATA mID on the chip: a device DID with its key at rest in encrypted NVS/eFuse, signed assertions, capability verification, owner adoption (bind-to-this-hub as a signed grant) and a signed capability manifest. Replaces vendor provisioning and cloud claiming. Memory safe, no_std core.
//!
//! This is the facade: it re-exports the `no_std` core and exposes the
//! chip backends under [`esp`]. Depend on this crate; reach into the
//! sub-crates only when you are building a backend.
//!
//! Part of Janus (Remade With Rust). Plan: `docs/plans/rusty_esp_mid.md`.

pub use rusty_esp_mid_core::*;

/// Chip backends (`esp-hal` for Track B, `esp-idf` for Track A).
pub mod esp {
    pub use rusty_esp_mid_esp::*;
}

/// The names a sketch or firmware wants in scope.
pub mod prelude {
    pub use rusty_esp_mid_core::prelude::*;
}
