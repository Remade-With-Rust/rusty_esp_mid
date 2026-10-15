//! The sealing key for [`SealedKv`](rusty_esp_mid_core::seal::SealedKv):
//! HMAC-SHA-256 over [`KEY_LABEL`] under an eFuse key block burned with the
//! `HMAC_UP` purpose, computed by the chip's HMAC peripheral.
//!
//! The eFuse key is read-protected when it is burned: software can ask the
//! peripheral for an HMAC under it, never for the key itself. So the sealing
//! key exists only while the firmware runs, is the same on every boot, and
//! differs on every chip whose key block was burned with its own random key.
//! A flash read off one board opens nowhere.
//!
//! Burned at the factory (`espefuse.py burn_key BLOCK_KEYn key.bin
//! HMAC_UP`, a fresh random key per chip). A chip without one answers
//! `None`, and a firmware runs with its secrets in the clear and says so.
//!
//! Chips with an HMAC peripheral only (the ESP32-C3, -C6, -H2, -S2 and -S3);
//! the `seal-hmac` feature is the firmware's to turn on.

use esp_hal::hmac::{Hmac, HmacPurpose, KeyId};
use esp_hal::peripherals::HMAC;
use rusty_esp_mid_core::seal::KEY_LABEL;

/// The sealing key under eFuse key block `block`, or `None` when that block
/// holds no key burned for `HMAC_UP`.
pub fn seal_key(hmac: HMAC<'_>, block: KeyId) -> Option<[u8; 32]> {
    let mut h = Hmac::new(hmac);
    h.init();
    nb::block!(h.configure(HmacPurpose::ToUser, block)).ok()?;
    let mut rest = KEY_LABEL;
    while !rest.is_empty() {
        rest = nb::block!(h.update(rest)).ok()?;
    }
    let mut key = [0u8; 32];
    nb::block!(h.finalize(&mut key)).ok()?;
    Some(key)
}
