//! Secrets at rest: a [`Kv`] whose values are sealed under a device key.
//!
//! **Why.** Flash encryption protects the app slots, but a settings or
//! identity partition in NVS format is not encrypted with them (ESP-IDF's own
//! NVS takes a separate key for that), so the device key and the network
//! passphrase sit in the clear on a dumped flash. [`SealedKv`] seals every
//! value it stores with AES-256-GCM under a key the chip derives and never
//! stores: on the ESP32-C6, an HMAC over a fixed label with an eFuse key
//! block that software cannot read back (`rusty_esp_mid-esp`'s
//! `seal_key`). Anyone holding the flash holds ciphertext.
//!
//! **The format.** `MAGIC (4) || nonce (12) || ciphertext || tag (16)`. The
//! nonce is fresh from the [`Rng`] on every write, and the value's own key
//! name is the additional data, so a sealed value moved under another name
//! does not open. `MAGIC` begins with a NUL, which no setting string holds:
//! a value written in the clear before sealing existed (a board provisioned
//! from a computer, say) still reads, and [`SealedKv::seal_in_place`] seals
//! it where it lies.
//!
//! **No key, no sealing.** Built with `None` -- the chip has no key burned
//! -- it passes every value through unchanged, and [`SealedKv::sealing`]
//! says so, so a firmware can say so too. Nothing pretends.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::{Kv, Rng};

/// What marks a sealed value. The NUL first: no setting string holds one.
pub const MAGIC: [u8; 4] = [0, b'J', b'S', 1];
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Bytes a sealed value takes beyond its plaintext.
pub const OVERHEAD: usize = MAGIC.len() + NONCE_LEN + TAG_LEN;
/// The longest value sealed: settings and keys, not files.
pub const MAX_VALUE: usize = 256;

/// The label the device's sealing key is derived under; a new label is a
/// new key, and every sealed value would need sealing again.
pub const KEY_LABEL: &[u8] = b"janus-seal-v1";

/// A [`Kv`] that seals what it stores (see the module docs).
pub struct SealedKv<K, R> {
    inner: K,
    rng: R,
    cipher: Option<Aes256Gcm>,
}

impl<K, R> core::fmt::Debug for SealedKv<K, R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedKv")
            .field("sealing", &self.cipher.is_some())
            .finish_non_exhaustive()
    }
}

impl<K: Kv, R: Rng> SealedKv<K, R> {
    /// Over `inner`, sealing under `key`; with `None`, values pass through
    /// in the clear.
    pub fn new(inner: K, rng: R, key: Option<&[u8; 32]>) -> Self {
        Self {
            inner,
            rng,
            cipher: key.map(|k| Aes256Gcm::new(k.into())),
        }
    }

    /// Whether values are sealed (a key was given).
    #[must_use]
    pub const fn sealing(&self) -> bool {
        self.cipher.is_some()
    }

    /// The store underneath.
    pub fn into_inner(self) -> K {
        self.inner
    }

    /// Whether `key`'s stored value is sealed; `None` when it is absent.
    pub fn is_sealed(&self, key: &str) -> Result<Option<bool>> {
        let mut raw = [0u8; MAX_VALUE + OVERHEAD];
        match self.inner.get(key, &mut raw) {
            Ok(Some(n)) => Ok(Some(raw[..n].starts_with(&MAGIC))),
            Ok(None) => Ok(None),
            // too long to be one of ours
            Err(Error::BufferTooSmall { .. }) => Ok(Some(false)),
            Err(e) => Err(e),
        }
    }

    /// Seal, where it lies, each of `keys` still stored in the clear.
    /// Returns how many were sealed. Without a key it seals nothing.
    pub fn seal_in_place(&mut self, keys: &[&str]) -> Result<usize> {
        if self.cipher.is_none() {
            return Ok(0);
        }
        let mut sealed = 0;
        for key in keys {
            if self.is_sealed(key)? == Some(false) {
                let mut plain = [0u8; MAX_VALUE];
                let Some(n) = self.inner.get(key, &mut plain)? else {
                    continue;
                };
                self.put(key, &plain[..n])?;
                plain.fill(0);
                sealed += 1;
            }
        }
        Ok(sealed)
    }
}

impl<K: Kv, R: Rng> Kv for SealedKv<K, R> {
    fn get(&self, key: &str, out: &mut [u8]) -> Result<Option<usize>> {
        let mut raw = [0u8; MAX_VALUE + OVERHEAD];
        let n = match self.inner.get(key, &mut raw) {
            Ok(Some(n)) => n,
            Ok(None) => return Ok(None),
            // a value too long to be sealed is one stored in the clear
            Err(Error::BufferTooSmall { .. }) => return self.inner.get(key, out),
            Err(e) => return Err(e),
        };
        let raw = &mut raw[..n];
        if !raw.starts_with(&MAGIC) {
            // stored in the clear, before sealing (or with no key)
            let dst = out
                .get_mut(..n)
                .ok_or(Error::BufferTooSmall { needed: n })?;
            dst.copy_from_slice(raw);
            return Ok(Some(n));
        }
        // a sealed value with no key to open it: say so, never guess
        let cipher = self.cipher.as_ref().ok_or(Error::Crypto)?;
        if n < OVERHEAD {
            return Err(Error::Corrupt);
        }
        let (head, rest) = raw.split_at_mut(MAGIC.len() + NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = head[MAGIC.len()..].try_into().map_err(|_| Error::Corrupt)?;
        let (body, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
        let tag: [u8; TAG_LEN] = (&*tag).try_into().map_err(|_| Error::Corrupt)?;
        cipher
            .decrypt_in_place_detached(&Nonce::from(nonce), key.as_bytes(), body, &Tag::from(tag))
            .map_err(|_| Error::Crypto)?;
        let len = body.len();
        let result = match out.get_mut(..len) {
            Some(dst) => {
                dst.copy_from_slice(body);
                Ok(Some(len))
            }
            None => Err(Error::BufferTooSmall { needed: len }),
        };
        body.fill(0);
        result
    }

    fn put(&mut self, key: &str, value: &[u8]) -> Result<()> {
        let Some(cipher) = self.cipher.as_ref() else {
            return self.inner.put(key, value);
        };
        if value.len() > MAX_VALUE {
            return Err(Error::Unsupported);
        }
        let mut raw = [0u8; MAX_VALUE + OVERHEAD];
        raw[..MAGIC.len()].copy_from_slice(&MAGIC);
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce)?;
        raw[MAGIC.len()..MAGIC.len() + NONCE_LEN].copy_from_slice(&nonce);
        let start = MAGIC.len() + NONCE_LEN;
        let end = start + value.len();
        raw[start..end].copy_from_slice(value);
        let tag = cipher
            .encrypt_in_place_detached(&Nonce::from(nonce), key.as_bytes(), &mut raw[start..end])
            .map_err(|_| Error::Crypto)?;
        raw[end..end + TAG_LEN].copy_from_slice(&tag);
        self.inner.put(key, &raw[..end + TAG_LEN])
    }

    fn remove(&mut self, key: &str) -> Result<bool> {
        self.inner.remove(key)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};

    const KEY: [u8; 32] = [7; 32];

    fn sealed() -> SealedKv<MemoryKv, InsecureTestRng> {
        SealedKv::new(MemoryKv::default(), InsecureTestRng::seeded(1), Some(&KEY))
    }

    fn raw(kv: &SealedKv<MemoryKv, InsecureTestRng>, key: &str) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 512];
        let n = kv.inner.get(key, &mut buf).unwrap().unwrap();
        buf[..n].to_vec()
    }

    fn get(kv: &impl Kv, key: &str) -> Result<Option<std::vec::Vec<u8>>> {
        let mut buf = [0u8; 512];
        Ok(kv.get(key, &mut buf)?.map(|n| buf[..n].to_vec()))
    }

    #[test]
    fn a_value_reads_back_and_is_not_on_the_flash_in_the_clear() {
        let mut kv = sealed();
        kv.put("wifi.psk", b"correct horse battery").unwrap();
        assert_eq!(
            get(&kv, "wifi.psk").unwrap().unwrap(),
            b"correct horse battery"
        );
        let stored = raw(&kv, "wifi.psk");
        assert!(stored.starts_with(&MAGIC));
        assert_eq!(stored.len(), 21 + OVERHEAD);
        assert!(
            !stored.windows(5).any(|w| w == b"horse"),
            "no plaintext at rest"
        );
        assert_eq!(kv.is_sealed("wifi.psk").unwrap(), Some(true));
        assert_eq!(kv.is_sealed("absent").unwrap(), None);
        assert!(get(&kv, "absent").unwrap().is_none());
    }

    #[test]
    fn the_same_value_twice_is_two_different_ciphertexts() {
        let mut kv = sealed();
        kv.put("a", b"same").unwrap();
        let first = raw(&kv, "a");
        kv.put("a", b"same").unwrap();
        assert_ne!(first, raw(&kv, "a"), "a fresh nonce every write");
    }

    #[test]
    fn a_flipped_bit_a_moved_value_or_the_wrong_key_does_not_open() {
        let mut kv = sealed();
        kv.put("wifi.psk", b"secret").unwrap();
        let good = raw(&kv, "wifi.psk");
        for i in [MAGIC.len(), MAGIC.len() + NONCE_LEN, good.len() - 1] {
            let mut bad = good.clone();
            bad[i] ^= 1;
            kv.inner.put("wifi.psk", &bad).unwrap();
            assert_eq!(get(&kv, "wifi.psk"), Err(Error::Crypto), "byte {i} flipped");
        }
        // the same sealed bytes filed under another name
        kv.inner.put("name", &good).unwrap();
        assert_eq!(get(&kv, "name"), Err(Error::Crypto), "the name is bound in");
        // the right name, another device's key
        let mut other = SealedKv::new(
            MemoryKv::default(),
            InsecureTestRng::seeded(2),
            Some(&[8; 32]),
        );
        other.inner.put("wifi.psk", &good).unwrap();
        assert_eq!(get(&other, "wifi.psk"), Err(Error::Crypto));
        // and a sealed value with no key at all is refused, not returned raw
        let mut keyless = SealedKv::new(MemoryKv::default(), InsecureTestRng::seeded(3), None);
        keyless.inner.put("wifi.psk", &good).unwrap();
        assert_eq!(get(&keyless, "wifi.psk"), Err(Error::Crypto));
        // a truncated one is corrupt
        kv.inner.put("wifi.psk", &good[..OVERHEAD - 1]).unwrap();
        assert_eq!(get(&kv, "wifi.psk"), Err(Error::Corrupt));
    }

    #[test]
    fn a_board_provisioned_in_the_clear_is_sealed_where_it_lies() {
        let mut kv = sealed();
        kv.inner.put("wifi.ssid", b"home").unwrap();
        kv.inner.put("wifi.psk", b"hunter22").unwrap();
        assert_eq!(
            get(&kv, "wifi.psk").unwrap().unwrap(),
            b"hunter22",
            "still reads"
        );
        assert_eq!(kv.is_sealed("wifi.psk").unwrap(), Some(false));
        assert_eq!(
            kv.seal_in_place(&["wifi.ssid", "wifi.psk", "absent"])
                .unwrap(),
            2
        );
        assert_eq!(kv.is_sealed("wifi.psk").unwrap(), Some(true));
        assert_eq!(get(&kv, "wifi.psk").unwrap().unwrap(), b"hunter22");
        assert_eq!(get(&kv, "wifi.ssid").unwrap().unwrap(), b"home");
        assert_eq!(
            kv.seal_in_place(&["wifi.ssid", "wifi.psk"]).unwrap(),
            0,
            "once"
        );
    }

    #[test]
    fn with_no_key_nothing_is_sealed_and_it_says_so() {
        let mut kv = SealedKv::new(MemoryKv::default(), InsecureTestRng::seeded(1), None);
        assert!(!kv.sealing());
        kv.put("wifi.psk", b"plain").unwrap();
        assert_eq!(raw_of(&kv), b"plain");
        assert_eq!(kv.seal_in_place(&["wifi.psk"]).unwrap(), 0);
        assert!(sealed().sealing());

        fn raw_of(kv: &SealedKv<MemoryKv, InsecureTestRng>) -> std::vec::Vec<u8> {
            let mut buf = [0u8; 64];
            let n = kv.inner.get("wifi.psk", &mut buf).unwrap().unwrap();
            buf[..n].to_vec()
        }
    }

    #[test]
    fn sizes_are_refused_not_truncated() {
        let mut kv = sealed();
        assert_eq!(
            kv.put("big", &[1u8; MAX_VALUE + 1]),
            Err(Error::Unsupported)
        );
        kv.put("max", &[2u8; MAX_VALUE]).unwrap();
        assert_eq!(get(&kv, "max").unwrap().unwrap().len(), MAX_VALUE);
        kv.put("k", b"twelve bytes").unwrap();
        let mut small = [0u8; 4];
        assert_eq!(
            kv.get("k", &mut small),
            Err(Error::BufferTooSmall { needed: 12 })
        );
        // a value stored in the clear, longer than any sealed one, still reads
        kv.inner.put("legacy", &[3u8; 400]).unwrap();
        let mut big = [0u8; 400];
        assert_eq!(kv.get("legacy", &mut big), Ok(Some(400)));
    }
}
