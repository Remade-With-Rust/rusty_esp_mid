//! The device key: generated once from the chip's TRNG, persisted through the
//! `Kv` seam, never leaving the process in plaintext except to that seam.
//!
//! The `-esp` backend states what the `Kv` partition actually guarantees
//! (NVS encryption on, key-encryption key in eFuse); this module does not
//! encrypt. A backend with a secure element implements [`DeviceSigner`]
//! directly and never constructs a `DeviceKey` at all.

use core::fmt;

use ecdsa::hazmat::{SignPrimitive, bits2field};
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::ff::PrimeField as _;
use p256::elliptic_curve::zeroize::Zeroize;
use p256::{NistP256, NonZeroScalar, PublicKey};
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
/// `Debug` is redacted. The secret is zeroized on drop.
///
/// The secret scalar and the public key are held apart, not as a
/// `p256::ecdsa::SigningKey`, because that type derives the public key when
/// it is built -- a scalar multiplication, 222 ms on an ESP32-S3 at 80 MHz
/// and so on every boot. [`DeviceKey::load_cached`] takes the public key
/// from beside the secret instead; signing is the same RFC 6979 call
/// `SigningKey` makes, so every signature is the one it would have made
/// (round 2, R7; the tests pin both).
pub struct DeviceKey {
    secret: NonZeroScalar,
    public: VerifyingKey,
    device_id: DeviceId,
}

impl Drop for DeviceKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// The scalar and its public key, when `secret` is a valid scalar (not zero,
/// below the group order -- what `SigningKey::from_bytes` accepts).
fn derive(secret: &[u8; 32]) -> Option<(NonZeroScalar, VerifyingKey)> {
    let nz: NonZeroScalar = Option::from(NonZeroScalar::from_repr((*secret).into()))?;
    let public = VerifyingKey::from(PublicKey::from_secret_scalar(&nz));
    Some((nz, public))
}

/// HMAC-SHA256 under a 32-byte key (RFC 2104), over the parts in order.
fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let mut h = sha2::Sha256::new();
    h.update(ipad);
    for part in parts {
        h.update(part);
    }
    let inner = h.finalize();
    let mut h = sha2::Sha256::new();
    h.update(opad);
    h.update(inner);
    ipad.zeroize();
    opad.zeroize();
    h.finalize().into()
}

/// The cache entry's binding: only a holder of the secret can write a
/// public key that [`DeviceKey::load_cached`] will take.
const PUB_DOMAIN: &[u8] = b"rusty_esp_mid devpub v1";

/// The binding of a remembered signature ([`DeviceKey::sign_prehash_cached`]).
const SIG_DOMAIN: &[u8] = b"rusty_esp_mid sigcache v1";

/// Equal without an early exit.
fn ct_eq32(a: &[u8; 32], b: &[u8]) -> bool {
    let mut diff = (b.len() != 32) as u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
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
            if let Some((secret_scalar, public)) = derive(&secret) {
                secret.zeroize();
                return Ok(DeviceKey {
                    secret: secret_scalar,
                    public,
                    device_id,
                });
            }
        }
        secret.zeroize();
        Err(Error::Crypto)
    }

    /// Rebuild from a stored 32-byte secret scalar.
    pub fn from_secret(secret: &[u8; 32], device_id: &str) -> Result<Self> {
        let device_id = DeviceId::new(device_id)?;
        let (secret, public) = derive(secret).ok_or(Error::Crypto)?;
        Ok(DeviceKey {
            secret,
            public,
            device_id,
        })
    }

    /// The secret scalar, for the storage seam only. Zeroize the copy.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_repr().into()
    }

    /// The device id.
    #[must_use]
    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// The identity this key certifies.
    #[must_use]
    pub fn did(&self) -> Did {
        Did::from_verifying_key(&self.public)
    }

    /// The verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.public
    }

    /// The 65-byte SEC1-uncompressed public key — the form a roster entry holds.
    #[must_use]
    pub fn pubkey_sec1_uncompressed(&self) -> [u8; 65] {
        let point = self.public.to_encoded_point(false);
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

    /// The `Kv` key of the public-key cache beside the secret: the 65-byte
    /// SEC1-uncompressed key, then an HMAC-SHA256 of it under the secret.
    pub const KV_PUB: &'static str = "mid.devpub";

    /// [`Self::load`] without the scalar multiplication: the public key is
    /// taken from [`Self::KV_PUB`] when that entry is there and its HMAC
    /// under this secret holds. Otherwise the public key is derived, as
    /// `load` derives it, and the entry is written for the next boot (a
    /// failed write is not an error: the key is still right, the next boot
    /// only pays again). A secret replaced under the same key has a
    /// different HMAC, so a stale entry is never taken.
    ///
    /// The same key in every respect as `load` returns: the public key is
    /// checked to be a point on the curve, and a wrong one could only have
    /// been written by a holder of the secret.
    pub fn load_cached(kv: &mut impl Kv, device_id: &str) -> Result<Option<Self>> {
        let mut secret = [0u8; 32];
        let got = kv.get(Self::KV_KEY, &mut secret);
        let out = match got {
            Ok(None) => Ok(None),
            Ok(Some(32)) => Self::from_secret_cached(kv, &secret, device_id).map(Some),
            Ok(Some(_)) => Err(Error::Corrupt),
            Err(e) => Err(e),
        };
        secret.zeroize();
        out
    }

    fn from_secret_cached(kv: &mut impl Kv, secret: &[u8; 32], device_id: &str) -> Result<Self> {
        let id = DeviceId::new(device_id)?;
        let scalar: NonZeroScalar =
            Option::from(NonZeroScalar::from_repr((*secret).into())).ok_or(Error::Crypto)?;
        let mut entry = [0u8; 97];
        if let Ok(Some(97)) = kv.get(Self::KV_PUB, &mut entry) {
            let (point, tag) = entry.split_at(65);
            let want = hmac_sha256(secret, &[PUB_DOMAIN, point]);
            let mut diff = 0u8;
            for (a, b) in want.iter().zip(tag) {
                diff |= a ^ b;
            }
            if core::hint::black_box(diff) == 0 {
                if let Ok(public) = VerifyingKey::from_sec1_bytes(point) {
                    return Ok(DeviceKey {
                        secret: scalar,
                        public,
                        device_id: id,
                    });
                }
            }
        }
        let key = DeviceKey {
            public: VerifyingKey::from(PublicKey::from_secret_scalar(&scalar)),
            secret: scalar,
            device_id: id,
        };
        key.store_pub(kv, secret);
        Ok(key)
    }

    /// [`DeviceSigner::sign_prehash`], remembered under `name` in `kv`: the
    /// prehash, the signature and an HMAC of both under this key's secret.
    /// When the entry holds this prehash and its HMAC holds, its signature
    /// is returned and nothing is signed; otherwise the prehash is signed
    /// and the entry written (best effort, as [`Self::load_cached`] writes).
    ///
    /// ECDSA here is deterministic (RFC 6979: k is a function of the key
    /// and the prehash), so a remembered signature is the one signing
    /// would have made, byte for byte. For what a firmware signs at every
    /// boot unchanged: its capability manifest, 265 ms a signature on an
    /// ESP32-S3 at 80 MHz (round 2, R8). Not for anything signed once.
    pub fn sign_prehash_cached(
        &self,
        kv: &mut impl Kv,
        name: &str,
        prehash: &[u8; 32],
    ) -> [u8; 64] {
        let mut secret = self.secret_bytes();
        let mut entry = [0u8; 128];
        if let Ok(Some(128)) = kv.get(name, &mut entry) {
            let (head, tag) = entry.split_at(96);
            if ct_eq32(prehash, &head[..32])
                && ct_eq32(&hmac_sha256(&secret, &[SIG_DOMAIN, head]), tag)
            {
                secret.zeroize();
                let mut sig = [0u8; 64];
                sig.copy_from_slice(&head[32..96]);
                return sig;
            }
        }
        let sig = self.sign_prehash(prehash);
        entry[..32].copy_from_slice(prehash);
        entry[32..96].copy_from_slice(&sig);
        let tag = hmac_sha256(&secret, &[SIG_DOMAIN, &entry[..96]]);
        entry[96..].copy_from_slice(&tag);
        secret.zeroize();
        let _ = kv.put(name, &entry);
        sig
    }

    /// Write the public-key cache entry; best effort.
    fn store_pub(&self, kv: &mut impl Kv, secret: &[u8; 32]) {
        let point = self.pubkey_sec1_uncompressed();
        let mut entry = [0u8; 97];
        entry[..65].copy_from_slice(&point);
        entry[65..].copy_from_slice(&hmac_sha256(secret, &[PUB_DOMAIN, &point]));
        let _ = kv.put(Self::KV_PUB, &entry);
    }

    /// [`Self::load_or_generate`] through [`Self::load_cached`]: what a
    /// firmware calls at boot to pay for the public key once per board.
    pub fn load_or_generate_cached(
        kv: &mut impl Kv,
        rng: &mut impl Rng,
        device_id: &str,
    ) -> Result<Self> {
        if let Some(key) = Self::load_cached(kv, device_id)? {
            return Ok(key);
        }
        let key = Self::generate(rng, device_id)?;
        key.store(kv)?;
        let mut secret = key.secret_bytes();
        key.store_pub(kv, &secret);
        secret.zeroize();
        Ok(key)
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
        let shared = p256::ecdh::diffie_hellman(self.secret, their_pk.as_affine());
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
        // `SigningKey::sign_prehash`, step for step: the prehash as a field
        // element, k by RFC 6979 over SHA-256 with no extra data.
        let z = bits2field::<NistP256>(prehash).expect("a 32-byte prehash is a field element");
        let (raw, _): (Signature, _) = self
            .secret
            .try_sign_prehashed_rfc6979::<sha2::Sha256>(&z, &[])
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
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};

    #[test]
    fn signatures_and_keys_are_signing_keys_own() {
        // the representation changed (R7); every byte out must not have
        for seed in 0..24u32 {
            let key = DeviceKey::from_seed_for_tests(&std::format!("r7-{seed}"), "x");
            let secret = key.secret_bytes();
            let sk = SigningKey::from_bytes(&secret.into()).unwrap();
            assert_eq!(key.verifying_key(), sk.verifying_key());
            assert_eq!(
                key.did(),
                Did::from_verifying_key(sk.verifying_key()),
                "seed {seed}"
            );
            for m in 0..8u8 {
                let prehash = [m.wrapping_mul(37).wrapping_add(seed as u8); 32];
                let raw: Signature = sk.sign_prehash(&prehash).unwrap();
                let want = raw.normalize_s().unwrap_or(raw);
                assert_eq!(
                    key.sign_prehash(&prehash)[..],
                    want.to_bytes()[..],
                    "seed {seed} m {m}"
                );
            }
        }
    }

    #[test]
    fn a_remembered_signature_is_the_signature_and_a_wrong_entry_is_not_used() {
        let key = DeviceKey::from_seed_for_tests("r8", "c");
        let mut kv = MemoryKv::new();
        let a = [3u8; 32];
        let b = [4u8; 32];
        // first: signed and written; second: read back; both the signature
        assert_eq!(
            key.sign_prehash_cached(&mut kv, "mid.sig", &a),
            key.sign_prehash(&a)
        );
        assert_eq!(
            key.sign_prehash_cached(&mut kv, "mid.sig", &a),
            key.sign_prehash(&a)
        );
        // another prehash replaces the entry and is not answered from it
        assert_eq!(
            key.sign_prehash_cached(&mut kv, "mid.sig", &b),
            key.sign_prehash(&b)
        );
        assert_eq!(
            key.sign_prehash_cached(&mut kv, "mid.sig", &a),
            key.sign_prehash(&a)
        );
        // a tampered signature byte, with the tag left alone: not used
        let mut entry = [0u8; 128];
        assert_eq!(kv.get("mid.sig", &mut entry).unwrap(), Some(128));
        entry[40] ^= 1;
        kv.put("mid.sig", &entry).unwrap();
        assert_eq!(
            key.sign_prehash_cached(&mut kv, "mid.sig", &a),
            key.sign_prehash(&a)
        );
        // another key's entry for the same prehash: not used
        let other = DeviceKey::from_seed_for_tests("r8-other", "c");
        let _ = other.sign_prehash_cached(&mut kv, "mid.sig", &a);
        assert_eq!(
            key.sign_prehash_cached(&mut kv, "mid.sig", &a),
            key.sign_prehash(&a)
        );
    }

    #[test]
    fn the_hmac_is_rfc_2104() {
        // Python: hmac.new(bytes(range(32)), b"rusty_esp_mid devpub v1" + bytes(range(65)), sha256)
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let point: [u8; 65] = core::array::from_fn(|i| i as u8);
        let want = "995344122d0856813204d39680b03b01c1e2c654e80a4d06986d7f20f0760221";
        let got = hmac_sha256(&key, &[PUB_DOMAIN, &point]);
        let hex: std::string::String = got.iter().map(|b| std::format!("{b:02x}")).collect();
        assert_eq!(hex, want);
    }

    #[test]
    fn the_cached_load_is_the_same_key_and_refuses_a_stale_cache() {
        let mut kv = MemoryKv::new();
        let mut rng = InsecureTestRng::seeded(7);
        let first = DeviceKey::load_or_generate_cached(&mut kv, &mut rng, "c").unwrap();
        // the cache was written beside the secret
        let mut entry = [0u8; 97];
        assert_eq!(kv.get(DeviceKey::KV_PUB, &mut entry).unwrap(), Some(97));
        assert_eq!(entry[..65], first.pubkey_sec1_uncompressed()[..]);
        // a cached load and a plain load agree with the first
        let cached = DeviceKey::load_cached(&mut kv, "c").unwrap().unwrap();
        let plain = DeviceKey::load(&kv, "c").unwrap().unwrap();
        assert_eq!(cached.did(), first.did());
        assert_eq!(plain.did(), first.did());
        assert_eq!(cached.sign_prehash(&[9; 32]), plain.sign_prehash(&[9; 32]));
        // a forged public key (another key's, its HMAC under that key) is
        // not taken: the secret here does not match the tag
        let other = DeviceKey::from_seed_for_tests("other", "c");
        let mut forged = [0u8; 97];
        forged[..65].copy_from_slice(&other.pubkey_sec1_uncompressed());
        forged[65..].copy_from_slice(&hmac_sha256(
            &other.secret_bytes(),
            &[PUB_DOMAIN, &other.pubkey_sec1_uncompressed()],
        ));
        kv.put(DeviceKey::KV_PUB, &forged).unwrap();
        let again = DeviceKey::load_cached(&mut kv, "c").unwrap().unwrap();
        assert_eq!(again.did(), first.did());
        // ... and the entry was rewritten to the right one
        assert_eq!(kv.get(DeviceKey::KV_PUB, &mut entry).unwrap(), Some(97));
        assert_eq!(entry[..65], first.pubkey_sec1_uncompressed()[..]);
        // a flipped tag bit, a short entry: derived again, same key
        entry[96] ^= 1;
        kv.put(DeviceKey::KV_PUB, &entry).unwrap();
        assert_eq!(
            DeviceKey::load_cached(&mut kv, "c").unwrap().unwrap().did(),
            first.did()
        );
        kv.put(DeviceKey::KV_PUB, &entry[..40]).unwrap();
        assert_eq!(
            DeviceKey::load_cached(&mut kv, "c").unwrap().unwrap().did(),
            first.did()
        );
        // no secret: none, and nothing written
        let mut empty = MemoryKv::new();
        assert!(DeviceKey::load_cached(&mut empty, "c").unwrap().is_none());
        assert!(empty.is_empty());
    }

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
