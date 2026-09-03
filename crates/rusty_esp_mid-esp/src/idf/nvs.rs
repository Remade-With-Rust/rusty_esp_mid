//! Track A: `EspNvsKv`, ESP-IDF NVS behind the `Kv` seam, with the check the
//! plan demands — **a device key is never stored in a plaintext partition**.
//!
//! What "encrypted" means here, stated exactly: the firmware was configured
//! with NVS encryption (`CONFIG_NVS_ENCRYPTION`, XTS-AES keys in the
//! `nvs_keys` partition) **and** flash encryption
//! (`CONFIG_SECURE_FLASH_ENC_ENABLED`, which makes the bootloader encrypt the
//! flash and the `nvs_keys` partition on first boot), so neither a flash dump
//! nor a plaintext `nvs_keys` partition yields the key. Anything less is
//! [`Protection::Plaintext`], and [`EspNvsKv::open`] refuses it unless the
//! crate is built with `allow-insecure-dev` — the tier a development board
//! runs at, recorded in the ledger, never shipped.
//!
//! Both facts come from `sdkconfig` at build time (esp-idf-sys exposes every
//! `CONFIG_*` as a `cfg`), so no FFI is needed. The eFuse *runtime* truth —
//! did the bootloader actually burn the keys — is the M3 secure-boot work,
//! read through `esp_efuse` when the Digital Signature path lands.

use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::sys::EspError;
use rusty_esp_mid_core::esp_core::error::{Error, Result};
use rusty_esp_mid_core::esp_core::hal::{Kv, check_key};

/// How well the partition protects what is written to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// NVS encryption and flash encryption are both configured.
    Encrypted,
    /// At least one of them is off: a flash dump reveals the values.
    Plaintext,
}

/// Whether this firmware was configured with NVS encryption.
pub const NVS_ENCRYPTION: bool = cfg!(esp_idf_nvs_encryption);
/// Whether this firmware was configured with flash encryption.
pub const FLASH_ENCRYPTION: bool = cfg!(esp_idf_secure_flash_enc_enabled);

/// ESP-IDF's answer for this build.
#[must_use]
pub const fn protection() -> Protection {
    if NVS_ENCRYPTION && FLASH_ENCRYPTION {
        Protection::Encrypted
    } else {
        Protection::Plaintext
    }
}

/// An NVS namespace as a [`Kv`].
pub struct EspNvsKv {
    nvs: EspNvs<NvsDefault>,
    protection: Protection,
}

impl core::fmt::Debug for EspNvsKv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EspNvsKv")
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}

fn map(e: EspError) -> Error {
    match e.code() {
        esp_idf_svc::sys::ESP_ERR_NVS_NOT_FOUND => Error::Corrupt,
        esp_idf_svc::sys::ESP_ERR_NVS_INVALID_LENGTH
        | esp_idf_svc::sys::ESP_ERR_NVS_INVALID_NAME => Error::InvalidFormat,
        esp_idf_svc::sys::ESP_ERR_NVS_NOT_ENOUGH_SPACE => Error::BufferTooSmall { needed: 0 },
        _ => Error::Hardware,
    }
}

impl EspNvsKv {
    /// Open `namespace` on the default NVS partition for secrets. Refuses a
    /// plaintext partition with `Err(Denied)` unless built with
    /// `allow-insecure-dev`.
    pub fn open(partition: EspDefaultNvsPartition, namespace: &str) -> Result<Self> {
        let protection = protection();
        if protection == Protection::Plaintext && !cfg!(feature = "allow-insecure-dev") {
            return Err(Error::Denied);
        }
        Self::open_unchecked(partition, namespace)
    }

    /// Open `namespace` for values that are **not** secrets (counters,
    /// settings); no protection check.
    pub fn open_unchecked(partition: EspDefaultNvsPartition, namespace: &str) -> Result<Self> {
        let nvs = EspNvs::new(partition, namespace, true).map_err(map)?;
        Ok(EspNvsKv {
            nvs,
            protection: protection(),
        })
    }

    /// What this partition protects.
    #[must_use]
    pub fn protection(&self) -> Protection {
        self.protection
    }
}

impl Kv for EspNvsKv {
    fn get(&self, key: &str, out: &mut [u8]) -> Result<Option<usize>> {
        check_key(key)?;
        let Some(len) = self.nvs.blob_len(key).map_err(map)? else {
            return Ok(None);
        };
        if out.len() < len {
            return Err(Error::BufferTooSmall { needed: len });
        }
        match self.nvs.get_blob(key, out).map_err(map)? {
            Some(v) => Ok(Some(v.len())),
            None => Ok(None),
        }
    }

    fn put(&mut self, key: &str, value: &[u8]) -> Result<()> {
        check_key(key)?;
        self.nvs.set_blob(key, value).map_err(map)
    }

    fn remove(&mut self, key: &str) -> Result<bool> {
        check_key(key)?;
        self.nvs.remove(key).map_err(map)
    }
}
