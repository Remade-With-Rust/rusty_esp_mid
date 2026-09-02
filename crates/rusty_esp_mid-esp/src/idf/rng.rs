//! Track A: the hardware RNG behind the `Rng` seam.
//!
//! ESP-IDF's `esp_fill_random` reads the chip's hardware RNG. It is a true
//! random source **only while the RF subsystem (Wi-Fi or Bluetooth) is
//! running, or the bootloader's RNG enable is still in effect**; otherwise it
//! degrades to a pseudo-random source the documentation warns about. This
//! type therefore refuses to hand out bytes until the caller has vouched that
//! the radio is up ([`EspRng::after_radio_start`]) — the seam's contract is
//! "never silently fall back to a predictable generator".

use rusty_esp_mid_core::esp_core::error::{Error, Result};
use rusty_esp_mid_core::esp_core::hal::Rng;

/// The chip RNG.
#[derive(Debug, Clone, Copy)]
pub struct EspRng {
    armed: bool,
}

impl EspRng {
    /// Construct **after** Wi-Fi or Bluetooth has started, which is what makes
    /// the hardware RNG a true one on ESP32-class chips.
    #[must_use]
    pub fn after_radio_start() -> Self {
        EspRng { armed: true }
    }

    /// A generator that refuses every request: for code paths that must
    /// carry an `Rng` before the radio is up.
    #[must_use]
    pub fn unarmed() -> Self {
        EspRng { armed: false }
    }
}

impl Rng for EspRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        if !self.armed {
            return Err(Error::Busy);
        }
        if buf.is_empty() {
            return Ok(());
        }
        // SAFETY: `esp_fill_random` writes exactly `len` bytes starting at
        // `buf`, which is a live, writable, correctly sized slice for the
        // duration of the call; it has no other preconditions.
        #[allow(unsafe_code)]
        unsafe {
            esp_idf_svc::sys::esp_fill_random(buf.as_mut_ptr().cast(), buf.len());
        }
        Ok(())
    }
}
