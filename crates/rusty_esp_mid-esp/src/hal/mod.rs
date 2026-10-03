//! Track B backends: the seams over `esp-hal` and `esp-storage`, no ESP-IDF.
//!
//! - [`PartitionFlash`]: one partition of the chip's SPI flash as the seam
//!   crate's `nvs::Flash`, so `rusty_esp_core::nvs::NvsKv` — the NVS format
//!   in Rust — is the [`Kv`](rusty_esp_mid_core::esp_core::hal::Kv) a device
//!   key lives behind, on the `identity` partition ESP-IDF's backend uses
//!   too. The two tracks read each other's partitions.
//! - [`find_partition`]: the partition table at `0x8000`, by label.
//! - [`EspHalRng`]: the chip's hardware generator behind `Rng`.
//! - [`SharedPartition`] / [`open_shared`] / [`Store`]: several partitions
//!   (the owner's settings, the identity) open at once on one flash, as the
//!   setup session holds them.
//!
//! What this cannot say is whether the partition is encrypted: that is an
//! eFuse's truth (`esp_hal::efuse::flash_encryption()`), and a device key
//! belongs in a plaintext partition only on a development board that says
//! so — the same rule the ESP-IDF backend enforces with `Protection`.

pub mod flash;
pub mod partitions;
pub mod rng;
pub mod shared;

pub use flash::PartitionFlash;
pub use partitions::{Partition, find_partition};
pub use rng::EspHalRng;
pub use shared::{SharedFlash, SharedNvs, SharedPartition, Store, open_shared};
