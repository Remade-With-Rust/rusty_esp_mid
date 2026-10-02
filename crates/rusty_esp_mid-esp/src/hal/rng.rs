//! The chip's hardware random number generator behind the `Rng` seam.
//!
//! `esp-hal`'s `Trng` is the true generator: it needs a `TrngSource` alive
//! (the RNG peripheral with an ADC channel feeding it entropy), which the
//! firmware creates and keeps. This wraps the `Trng` it hands out; the
//! device key is born from these words and nothing else.

use esp_hal::rng::Trng;
use rusty_esp_mid_core::esp_core::error::Result;
use rusty_esp_mid_core::esp_core::hal::Rng;

/// The hardware generator as an [`Rng`].
pub struct EspHalRng(pub Trng);

impl core::fmt::Debug for EspHalRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EspHalRng")
    }
}

impl Rng for EspHalRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        for chunk in buf.chunks_mut(4) {
            let word = self.0.random().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}
