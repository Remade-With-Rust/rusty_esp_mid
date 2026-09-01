//! The device key: generated once from the chip's TRNG, persisted through the
//! `Kv` seam, never leaving the process in plaintext except to that seam.
//!
//! The `-esp` backend states what the `Kv` partition actually guarantees
//! (NVS encryption on, key-encryption key in eFuse); this module does not
//! encrypt. A backend with a secure element implements [`DeviceSigner`]
//! directly and never constructs a `DeviceKey` at all.

use core::fmt;

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::{Kv, Rng};

use crate::did::Did;
use crate::signer::DeviceSigner;

/// Longest device id, in bytes. Matched against a roster entry's `device_id`.
pub const MAX_DEVICE_ID_LEN: usize = 32;

/// The default device id a Janus firmware uses when a maker sets none.
pub const DEFAULT_DEVICE_ID: &str = "janus";

/// A short, stable, ASCII identifier for the signing device — the string
/// `DeviceSigner::device_id` returns and the roster lists.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceId {
    bytes: [u8; MAX_DEVICE_ID_LEN],
    len: u8,
}

impl DeviceId {
    /// Validate and store a device id: 1–32 bytes of `[A-Za-z0-9_.-]`.
    pub fn new(id: &str) -> Result<Self> {
        let ok = !id.is_empty()
            && id.len() <= MAX_DEVICE_ID_LEN
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-');
        if !ok {
            return Err(Error::InvalidFormat);
        }
        let mut bytes = [0u8; MAX_DEVICE_ID_LEN];
        bytes[..id.len()].copy_from_slice(id.as_bytes());
        Ok(DeviceId {
            bytes,
            len: id.len() as u8,
        })
    }

    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or(DEFAULT_DEVICE_ID)
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The device's P-256 signing key and its id.
///
/// `Debug` is redacted. The secret is zeroized on drop by `p256`.
pub struct DeviceKey {
    key: SigningKey,
    device_id: DeviceId,
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceKey({}, {})", self.device_id.as_str(), self.did())
    }
}

impl DeviceKey {
    /// The `Kv` key under which the 32-byte secret is stored.
    pub const KV_KEY: &'static str = "mid.devkey";

    /// Attempts before giving up on an entropy source that keeps producing
    /// out-of-range scalars (probability per draw is ~2^-32; eight tries is
    /// a defect report, not bad luck).
    const GENERATE_ATTEMPTS: usize = 8;

    /// Generate a fresh key from the chip's TRNG.
    pub fn generate(rng: &mut impl Rng, device_id: &str) -> Result<Self> {
        let device_id = DeviceId::new(device_id)?;
        let mut secret = [0u8; 32];
        for _ in 0..Self::GENERATE_ATTEMPTS {
            rng.fill(&mut secret)?;
            if let Ok(key) = SigningKey::from_bytes(&secret.into()) {
                return Ok(DeviceKey { key, device_id });
            }
        }
        Err(Error::Crypto)
    }

    /// Rebuild from a stored 32-byte secret scalar.
    pub fn from_secret(secret: &[u8; 32], device_id: &str) -> Result<Self> {
        let device_id = DeviceId::new(device_id)?;
        let key = SigningKey::from_bytes(&(*secret).into()).map_err(|_| Error::Crypto)?;
        Ok(DeviceKey { key, device_id })
    }

    /// The secret scalar, for the storage seam only. Zeroize the copy.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    /// The device id.
    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// The identity this key certifies.
    #[must_use]
    pub fn did(&self) -> Did {
        Did::from_verifying_key(self.key.verifying_key())
    }

    /// The verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.key.verifying_key()
    }

    /// The 65-byte SEC1-uncompressed public key — the form a roster entry holds.
    #[must_use]
    pub fn pubkey_sec1_uncompressed(&self) -> [u8; 65] {
        let point = self.key.verifying_key().to_encoded_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// Load the key from `kv`, or `Ok(None)` when none is stored.
    pub fn load(kv: &impl Kv, device_id: &str) -> Result<Option<Self>> {
        let mut secret = [0u8; 32];
        match kv.get(Self::KV_KEY, &mut secret)? {
            None => Ok(None),
            Some(32) => Self::from_secret(&secret, device_id).map(Some),
            Some(_) => Err(Error::Corrupt),
        }
    }

    /// Store the secret under [`Self::KV_KEY`].
    pub fn store(&self, kv: &mut impl Kv) -> Result<()> {
        kv.put(Self::KV_KEY, &self.secret_bytes())
    }

    /// Load the key, or generate and store one. This is what a firmware
    /// calls at boot: the DID is stable across reboots and reflashes for
    /// as long as the `Kv` partition survives.
    pub fn load_or_generate(kv: &mut impl Kv, rng: &mut impl Rng, device_id: &str) -> Result<Self> {
        if let Some(key) = Self::load(kv, device_id)? {
            return Ok(key);
        }
        let key = Self::generate(rng, device_id)?;
        key.store(kv)?;
        Ok(key)
    }

    /// Raw ECDH shared secret (the x-coordinate) with another `did:mata`.
    /// Callers derive session keys from it with HKDF and a context string;
    /// never use the raw secret as a key.
    pub fn shared_secret(&self, their: &Did) -> Result<[u8; 32]> {
        let their_pk =
            p256::PublicKey::from_sec1_bytes(their.pubkey()).map_err(|_| Error::Crypto)?;
        let shared = p256::ecdh::diffie_hellman(self.key.as_nonzero_scalar(), their_pk.as_affine());
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes());
        Ok(out)
    }

    /// Deterministic key for tests, derived like `mid`'s own test helpers:
    /// SHA-256 over the seed plus a fixed suffix.
    #[doc(hidden)]
    #[must_use]
    pub fn from_seed_for_tests(seed: &str, device_id: &str) -> Self {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(seed.as_bytes());
        h.update(b"-rusty-esp-mid-test-seed");
        let secret: [u8; 32] = h.finalize().into();
        Self::from_secret(&secret, device_id)
            .expect("hash output is a valid scalar with overwhelming odds")
    }
}

impl DeviceSigner for DeviceKey {
    fn device_id(&self) -> &str {
        self.device_id.as_str()
    }

    fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64] {
        let raw: Signature = self
            .key
            .sign_prehash(prehash)
            .expect("sign_prehash over 32 bytes cannot fail for a valid key");
        // Canonical low-s: the verifier rejects the high-s twin.
        let sig = raw.normalize_s().unwrap_or(raw);
        let mut out = [0u8; 64];
        out.copy_from_slice(&sig.to_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::verify_prehash;
    use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};

    #[test]
    fn generate_store_load_is_stable() {
        let mut rng = InsecureTestRng::seeded(42);
        let mut kv = MemoryKv::new();
        let a = DeviceKey::load_or_generate(&mut kv, &mut rng, "cam-1").unwrap();
        let b = DeviceKey::load_or_generate(&mut kv, &mut rng, "cam-1").unwrap();
        assert_eq!(a.did(), b.did());
        assert_eq!(a.secret_bytes(), b.secret_bytes());
        assert_eq!(kv.len(), 1);
    }

    #[test]
    fn signatures_are_low_s_and_verify() {
        let k = DeviceKey::from_seed_for_tests("k", "dev");
        let prehash = crate::sha256(b"hello");
        let sig = k.sign_prehash(&prehash);
        verify_prehash(k.did().pubkey(), &prehash, &sig).unwrap();
        let mut other = prehash;
        other[0] ^= 1;
        assert_eq!(
            verify_prehash(k.did().pubkey(), &other, &sig),
            Err(Error::Crypto)
        );
    }

    #[test]
    fn device_id_rules() {
        assert!(DeviceId::new("cam-1.a_b").is_ok());
        assert_eq!(DeviceId::new(""), Err(Error::InvalidFormat));
        assert_eq!(DeviceId::new("has space"), Err(Error::InvalidFormat));
        assert_eq!(
            DeviceId::new("012345678901234567890123456789012"),
            Err(Error::InvalidFormat)
        );
    }

    #[test]
    fn corrupt_store_is_reported() {
        let mut kv = MemoryKv::new();
        kv.put(DeviceKey::KV_KEY, &[1, 2, 3]).unwrap();
        assert_eq!(DeviceKey::load(&kv, "dev").err(), Some(Error::Corrupt));
    }

    #[test]
    fn ecdh_agrees_both_ways() {
        let a = DeviceKey::from_seed_for_tests("a", "a");
        let b = DeviceKey::from_seed_for_tests("b", "b");
        assert_eq!(
            a.shared_secret(&b.did()).unwrap(),
            b.shared_secret(&a.did()).unwrap()
        );
    }
}
