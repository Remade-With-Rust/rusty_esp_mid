//! The signing seam — **byte-for-byte** the trait `mid`'s `kms-client` defines.
//!
//! It is copied rather than depended on because `kms-client` today drags
//! `reqwest` and tokio into any crate that names the trait. When `mid`
//! extracts it into a leaf crate, this module becomes a re-export and no call
//! site changes.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rusty_esp_core::error::{Error, Result};

/// The abstract capability every signer provides: a stable id and a
/// canonical (low-s) ECDSA P-256 signature over a 32-byte prehash.
///
/// Implementations: [`crate::DeviceKey`] (software key in encrypted NVS),
/// and in the `-esp` crate a secure-element or eFuse-backed signer.
pub trait DeviceSigner {
    /// Stable identifier of this signing device. Matched against a
    /// `device_id` in the roster.
    fn device_id(&self) -> &str;

    /// Sign a 32-byte SHA-256 prehash. Returns the canonical (low-s)
    /// 64-byte `r || s` representation.
    fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64];
}

/// Verify a 64-byte `r || s` P-256 signature over `prehash` under a 33-byte
/// compressed public key, **rejecting high-s** (the malleability defence
/// every MATA verifier applies).
pub fn verify_prehash(pubkey_sec1: &[u8], prehash: &[u8; 32], signature: &[u8; 64]) -> Result<()> {
    let key = VerifyingKey::from_sec1_bytes(pubkey_sec1).map_err(|_| Error::Crypto)?;
    let sig = Signature::from_slice(signature).map_err(|_| Error::Crypto)?;
    if sig.normalize_s().is_some() {
        return Err(Error::Crypto);
    }
    key.verify_prehash(prehash, &sig).map_err(|_| Error::Crypto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;

    #[test]
    fn high_s_is_rejected() {
        let k = DeviceKey::from_seed_for_tests("s", "dev");
        let prehash = crate::sha256(b"x");
        let low = k.sign_prehash(&prehash);
        // Flip to the high-s twin: s' = n - s.
        let sig = Signature::from_slice(&low).unwrap();
        let (r, s) = sig.split_scalars();
        let high_s = -*s;
        let high = Signature::from_scalars(r, high_s).unwrap();
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&high.to_bytes());
        assert_eq!(
            verify_prehash(k.did().pubkey(), &prehash, &bytes),
            Err(Error::Crypto)
        );
        assert!(verify_prehash(k.did().pubkey(), &prehash, &low).is_ok());
    }
}
