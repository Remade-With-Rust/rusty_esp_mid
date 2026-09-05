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
//!
//! **Which partition.** The owner's settings (Wi-Fi, name, maker) live in
//! the default `nvs` partition, which a provisioning tool rewrites whole.
//! The device's key must not share it: on 2026-09-05 an ESP32-CAM minted a
//! new DID at every settings rewrite until the key moved. The identity
//! belongs in its own NVS partition — the espino tables call it
//! `identity` — opened with [`EspNvsKv::open_custom`] /
//! [`EspNvsKv::open_custom_unchecked`]; the default-partition constructors
//! stay for values that are the owner's.

use esp_idf_svc::nvs::{
    EspCustomNvsPartition, EspDefaultNvsPartition, EspNvs, EspNvsPartition, NvsCustom, NvsDefault,
    NvsPartitionId,
};
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

/// The label of the partition a device's identity lives in, as the espino
/// tables spell it. Never the owner's `nvs`.
pub const IDENTITY_PARTITION: &str = "identity";

/// An NVS namespace as a [`Kv`], on the default partition or a named one.
pub struct EspNvsKv<T: NvsPartitionId = NvsDefault> {
    nvs: EspNvs<T>,
    protection: Protection,
}

impl<T: NvsPartitionId> core::fmt::Debug for EspNvsKv<T> {
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

fn refuse_plaintext() -> Result<()> {
    if protection() == Protection::Plaintext && !cfg!(feature = "allow-insecure-dev") {
        return Err(Error::Denied);
    }
    Ok(())
}

impl<T: NvsPartitionId> EspNvsKv<T> {
    /// Open `namespace` on `partition` for secrets. Refuses a plaintext
    /// partition with `Err(Denied)` unless built with `allow-insecure-dev`.
    pub fn open_in(partition: EspNvsPartition<T>, namespace: &str) -> Result<Self> {
        refuse_plaintext()?;
        Self::open_unchecked_in(partition, namespace)
    }

    /// Open `namespace` on `partition` with no protection check — for values
    /// that are not secrets, or for a development board that says so.
    pub fn open_unchecked_in(partition: EspNvsPartition<T>, namespace: &str) -> Result<Self> {
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

impl EspNvsKv<NvsDefault> {
    /// Open `namespace` on the default `nvs` partition for secrets. Refuses a
    /// plaintext partition with `Err(Denied)` unless built with
    /// `allow-insecure-dev`.
    pub fn open(partition: EspDefaultNvsPartition, namespace: &str) -> Result<Self> {
        Self::open_in(partition, namespace)
    }

    /// Open `namespace` on the default partition for values that are **not**
    /// secrets (counters, settings); no protection check.
    pub fn open_unchecked(partition: EspDefaultNvsPartition, namespace: &str) -> Result<Self> {
        Self::open_unchecked_in(partition, namespace)
    }
}

impl EspNvsKv<NvsCustom> {
    /// Open `namespace` on the partition labelled `label` for secrets —
    /// [`IDENTITY_PARTITION`] for the device key. Initialises the partition
    /// on first use. Refuses a plaintext partition unless built with
    /// `allow-insecure-dev`; `Err(Corrupt)` when the table has no such
    /// partition.
    pub fn open_custom(label: &str, namespace: &str) -> Result<Self> {
        refuse_plaintext()?;
        Self::open_custom_unchecked(label, namespace)
    }

    /// [`Self::open_custom`] without the protection check.
    pub fn open_custom_unchecked(label: &str, namespace: &str) -> Result<Self> {
        let partition = EspCustomNvsPartition::take(label).map_err(map)?;
        Self::open_unchecked_in(partition, namespace)
    }
}

impl<T: NvsPartitionId> Kv for EspNvsKv<T> {
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
