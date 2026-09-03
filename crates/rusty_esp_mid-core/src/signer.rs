//! The signing seam — upstream `mid-signer`'s [`DeviceSigner`], re-exported,
//! plus the family's verifier.
//!
//! This module used to carry a byte-for-byte copy of the trait because
//! `kms-client` dragged `reqwest` and tokio into any crate that named it.
//! The leaf exists now (`mid-signer`, `no_std` without an allocator), so the
//! copy is gone and every implementation here — [`crate::DeviceKey`] in
//! software, a secure element or eFuse key in the `-esp` crate — implements
//! the one upstream trait.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rusty_esp_core::error::{Error, Result};

pub use mid_signer::{DeviceSigner, canonical_bytes};

/// Verify a 64-byte `r || s` P-256 signature over `prehash` under a 33-byte
/// compressed public key, **rejecting high-s** — the malleability defence
/// every Janus verifier applies (they all route through here; the plan's M4
/// audit table lists them). Upstream `mid-verify` verifies the scalars as
/// given today; the oracle test pins that so the difference is never silent.
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
