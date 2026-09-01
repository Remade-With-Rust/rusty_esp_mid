//! Signing the `rusty_esp_core` capability manifest.
//!
//! The manifest's canonical encoding is deterministic, so the device signs
//! `sha256("janus-manifest-v1\n" || manifest_bytes)` once and the home
//! computer's catalog can trust the claims came from the DID that made them.
//! A maker signature over `{model, firmware}` (the `Certified` tier) is the
//! same operation with the maker's key and [`MAKER_DOMAIN`].

use rusty_esp_core::capability::Manifest;
use rusty_esp_core::error::Result;

use crate::signer::{DeviceSigner, verify_prehash};

/// Domain separator for a device's manifest signature.
pub const MANIFEST_DOMAIN: &[u8] = b"janus-manifest-v1\n";

/// Domain separator for a maker's attestation of `model` + `firmware`.
pub const MAKER_DOMAIN: &[u8] = b"janus-maker-v1\n";

fn prehash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}

/// Sign already-encoded manifest bytes ([`Manifest::encode`] output).
#[must_use]
pub fn sign_manifest_bytes(manifest_bytes: &[u8], signer: &impl DeviceSigner) -> [u8; 64] {
    signer.sign_prehash(&prehash(MANIFEST_DOMAIN, manifest_bytes))
}

/// Encode `manifest` into `out` and sign it; returns `(encoded_len, signature)`.
pub fn sign_manifest(
    manifest: &Manifest<'_>,
    signer: &impl DeviceSigner,
    out: &mut [u8],
) -> Result<(usize, [u8; 64])> {
    let n = manifest.encode(out)?;
    Ok((n, sign_manifest_bytes(&out[..n], signer)))
}

/// Verify a manifest signature under a 33-byte compressed device key.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature: &[u8; 64],
    device_pubkey: &[u8],
) -> Result<()> {
    verify_prehash(
        device_pubkey,
        &prehash(MANIFEST_DOMAIN, manifest_bytes),
        signature,
    )
}

/// A maker's attestation over `model` and `firmware`: `len16(model) model
/// len16(firmware) firmware`, under [`MAKER_DOMAIN`].
#[must_use]
pub fn maker_prehash(model: &str, firmware: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(MAKER_DOMAIN);
    h.update((model.len() as u16).to_be_bytes());
    h.update(model.as_bytes());
    h.update((firmware.len() as u16).to_be_bytes());
    h.update(firmware.as_bytes());
    h.finalize().into()
}

/// Verify a maker attestation.
pub fn verify_maker(
    model: &str,
    firmware: &str,
    signature: &[u8; 64],
    maker_pubkey: &[u8],
) -> Result<()> {
    verify_prehash(maker_pubkey, &maker_prehash(model, firmware), signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;
    use rusty_esp_core::capability::{Capability, Chip, Declared};
    use rusty_esp_core::error::Error;

    #[test]
    fn manifest_signature_round_trip_and_tamper() {
        let k = DeviceKey::from_seed_for_tests("m", "cam-1");
        let declared = [
            Declared::available(Capability::ImageJpeg, "rusty_esp_image"),
            Declared::preview(Capability::MidDevice, "rusty_esp_mid"),
        ];
        let m = Manifest {
            model: "acme/doorbell-2",
            firmware: "1.4.0",
            chip: Chip::Esp32S3,
            declared: &declared,
        };
        let mut buf = [0u8; 512];
        let (n, sig) = sign_manifest(&m, &k, &mut buf).unwrap();
        verify_manifest(&buf[..n], &sig, k.did().pubkey()).unwrap();
        buf[n - 2] ^= 1;
        assert_eq!(
            verify_manifest(&buf[..n], &sig, k.did().pubkey()),
            Err(Error::Crypto)
        );
    }

    #[test]
    fn maker_attestation() {
        let maker = DeviceKey::from_seed_for_tests("maker", "factory");
        let sig = maker.sign_prehash(&maker_prehash("acme/doorbell-2", "1.4.0"));
        verify_maker("acme/doorbell-2", "1.4.0", &sig, maker.did().pubkey()).unwrap();
        assert_eq!(
            verify_maker("acme/doorbell-2", "1.4.1", &sig, maker.did().pubkey()),
            Err(Error::Crypto)
        );
    }
}
