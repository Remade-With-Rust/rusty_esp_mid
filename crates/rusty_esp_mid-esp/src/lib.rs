#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
//! `rusty_esp_mid-esp` — chip backends for `rusty_esp_mid`.
//!
//! This is the **wrap** crate of the package: where the silicon must be
//! touched, it calls the esp-rs HAL (Track B, `esp-hal`) or ESP-IDF (Track A,
//! `esp-idf`) and exposes the core crate's seams over it — `Kv` for the key's
//! home, `Rng` for the entropy the key is born from. Nothing identity-specific
//! lives here; that is the core's job.
//!
//! `unsafe` is denied crate-wide; a backend that must use it at an FFI
//! boundary opts in per block with `#[allow(unsafe_code)]` and a `// SAFETY:`
//! comment stating the invariant.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "esp-hal", feature = "esp-idf"))]
compile_error!("enable exactly one track: `esp-hal` (no_std) or `esp-idf` (std)");

pub use rusty_esp_mid_core as core;

/// Which track this build of the backend crate was compiled for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    /// No chip backend compiled in: host build, traits only.
    Host,
    /// Track B — bare metal, esp-hal + Embassy.
    EspHal,
    /// Track A — std on ESP-IDF.
    EspIdf,
}

/// The track this crate was built with.
pub const TRACK: Track = if cfg!(feature = "esp-hal") {
    Track::EspHal
} else if cfg!(feature = "esp-idf") {
    Track::EspIdf
} else {
    Track::Host
};

#[cfg(feature = "esp-hal")]
pub mod hal {
    //! Track B backends. Drivers land here with their esp-hal pin.
}

#[cfg(feature = "esp-idf")]
pub mod idf {
    //! Track A backends over esp-idf-svc 0.52.
    pub mod nvs;
    pub mod rng;
    pub use nvs::{EspNvsKv, Protection};
    pub use rng::EspRng;
}
