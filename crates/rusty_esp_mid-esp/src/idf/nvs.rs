//! Track A: `EspNvsKv`, ESP-IDF NVS behind the `Kv` seam, with the check the
//! plan demands — **a device key is never stored in a plaintext partition**.
//!
//! What "encrypted" means here, stated exactly: NVS encryption
//! (`CONFIG_NVS_ENCRYPTION`, XTS-AES keys in the `nvs_keys` partition) is on
//! **and** flash encryption is enabled on this chip
//! (`esp_flash_encryption_enabled()`), so neither a flash dump nor a
//! plaintext `nvs_keys` partition yields the key. Anything less is
//! [`Protection::Plaintext`], and [`EspNvsKv::open`] refuses it unless the
//! crate is built with `allow-insecure-dev` — the tier a development board
//! runs at, recorded in the ledger, never shipped.

use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use esp_idf_svc::sys::EspError;
use rusty_esp_mid_core::esp_core::error::{Error, Result};
use rusty_esp_mid_core::esp_core::hal::{check_key, Kv};

/// How well the partition protects what is written to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// NVS encryption and flash encryption are both on.
    Encrypted,
    /// At least one of them is off: a flash dump reveals the values.
    Plaintext,
}

/// Read ESP-IDF's answer for this build and this chip.
#[must_use]
pub fn protection() -> Protection {
    let nvs_encryption = cfg!(esp_idf_nvs_encryption);
    // SAFETY: a plain query of the eFuse-backed flash-encryption state; no
    // pointers, no preconditions, always safe to call after boot.
    #[allow(unsafe_code)]
    let flash_encryption = unsafe { esp_idf_svc::sys::esp_flash_encryption_enabled() };
    if nvs_encryption && flash_encryption {
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
        esp_idf_svc::sys::ESP_ERR_NVS_INVALID_LENGTH | esp_idf_svc::sys::ESP_ERR_NVS_INVALID_NAME => Error::InvalidFormat,
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
