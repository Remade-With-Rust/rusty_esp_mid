//! The setup session's identity pieces (enc-ble; the protocol is the Janus
//! umbrella's `docs/setup-protocol.md`, v1): the device's signature over a
//! session's Reply, and the names the session's two records are stored under.
//!
//! The session itself (SPAKE2+, the sealing, the window) is
//! `rusty_esp_signal-core::setup`; what it asks of identity is here, in this
//! crate's discipline: a domain separator, a length prefix, SHA-256, low-s
//! ECDSA P-256 by the device's own key through [`DeviceSigner`], verified
//! against the `did:mata` the browser was shown.

use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::Kv;
use sha2::{Digest, Sha256};

use crate::signer::{verify_prehash, DeviceSigner};

/// The Reply signature's domain separator.
pub const REPLY_DOMAIN: &[u8] = b"janus-setup-v1/reply\n";

/// Bytes of a share: an uncompressed P-256 point.
pub const SHARE_LEN: usize = 65;

/// Bytes of a confirmation (HMAC-SHA256).
pub const CONFIRM_LEN: usize = 32;

/// Where the verifier is stored, in the owner's settings namespace (`janus`):
/// written by the portal at flash time, read by the session.
pub const KV_SETUP_VERIFIER: &str = "setup.v";

/// Bytes of the stored verifier (`0x01 || w0 || L || salt || iterations`).
pub const SETUP_VERIFIER_LEN: usize = 118;

/// Where the consecutive failure count is kept, one byte, same namespace.
pub const KV_SETUP_FAILURES: &str = "setup.fail";

/// The prehash the device signs (protocol section 5.3):
/// `SHA-256("janus-setup-v1/reply\n" || u16be(len(context)) || context ||
/// shareP || shareV || confirmV)`. A context longer than 65,535 bytes is
/// `InvalidFormat` (a session's is at most 64).
pub fn reply_prehash(
    context: &[u8],
    share_p: &[u8; SHARE_LEN],
    share_v: &[u8; SHARE_LEN],
    confirm_v: &[u8; CONFIRM_LEN],
) -> Result<[u8; 32]> {
    let len = u16::try_from(context.len()).map_err(|_| Error::InvalidFormat)?;
    let mut h = Sha256::new();
    h.update(REPLY_DOMAIN);
    h.update(len.to_be_bytes());
    h.update(context);
    h.update(share_p);
    h.update(share_v);
    h.update(confirm_v);
    Ok(h.finalize().into())
}

/// The device's signature over a Reply: `signer.sign_prehash(prehash)`, low-s
/// `r || s`. On the chip `signer` is the device key; the session never holds
/// it.
pub fn sign_reply(signer: &impl DeviceSigner, prehash: &[u8; 32]) -> [u8; 64] {
    signer.sign_prehash(prehash)
}

/// The browser's check of a Reply signature against the device it was shown
/// (`device_pubkey`, the compressed key its `did:mata` is made of). A key that
/// is not a point, a signature that does not decode, a high-s signature, or
/// one that does not verify: `Crypto`.
pub fn verify_reply(
    device_pubkey: &[u8; 33],
    prehash: &[u8; 32],
    signature: &[u8; 64],
) -> Result<()> {
    verify_prehash(device_pubkey, prehash, signature)
}

/// The stored verifier, if any. Stored at another length is `Corrupt`.
pub fn load_verifier(kv: &impl Kv) -> Result<Option<[u8; SETUP_VERIFIER_LEN]>> {
    let mut buf = [0u8; SETUP_VERIFIER_LEN];
    match kv.get(KV_SETUP_VERIFIER, &mut buf) {
        Ok(None) => Ok(None),
        Ok(Some(SETUP_VERIFIER_LEN)) => Ok(Some(buf)),
        Ok(Some(_)) | Err(Error::BufferTooSmall { .. }) => Err(Error::Corrupt),
        Err(e) => Err(e),
    }
}

/// Stores a verifier, replacing any before it (the code rotates).
pub fn store_verifier(kv: &mut impl Kv, record: &[u8; SETUP_VERIFIER_LEN]) -> Result<()> {
    kv.put(KV_SETUP_VERIFIER, record)
}

/// The consecutive failure count; absent is 0. Stored at another length is
/// `Corrupt`: the session reads that as locked (it fails closed).
pub fn load_failures(kv: &impl Kv) -> Result<u8> {
    let mut b = [0u8; 1];
    match kv.get(KV_SETUP_FAILURES, &mut b) {
        Ok(None) => Ok(0),
        Ok(Some(1)) => Ok(b[0]),
        Ok(Some(_)) | Err(Error::BufferTooSmall { .. }) => Err(Error::Corrupt),
        Err(e) => Err(e),
    }
}

/// Stores the consecutive failure count.
pub fn store_failures(kv: &mut impl Kv, count: u8) -> Result<()> {
    kv.put(KV_SETUP_FAILURES, &[count])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;
    use rusty_esp_core::hal::host::MemoryKv;

    fn h<const N: usize>(s: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    /// The Reply of `rusty_esp_signal`'s golden session
    /// (`tools/setup_golden.py`, an independent Python oracle with its own
    /// RFC 6979 ECDSA; the lines are copied into this crate's fixture): the
    /// prehash and this crate's signature, byte for byte, and the refusals.
    #[test]
    fn golden_reply() {
        let f = include_str!("../tests/fixtures/setup-reply-v1.txt");
        let get = |k: &str| {
            let line = f
                .lines()
                .find(|l| l.starts_with(&(k.to_string() + " = ")))
                .unwrap();
            line.split(" = ").nth(1).unwrap().to_string()
        };
        let context: std::vec::Vec<u8> = (0..get("context").len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&get("context")[i..i + 2], 16).unwrap())
            .collect();
        let prehash = reply_prehash(
            &context,
            &h::<65>(&get("shareP")),
            &h::<65>(&get("shareV")),
            &h::<32>(&get("confirmV")),
        )
        .unwrap();
        assert_eq!(prehash, h::<32>(&get("reply_prehash")));
        let key = DeviceKey::from_secret(&h::<32>(&get("device_secret")), "setup-golden").unwrap();
        let sig = sign_reply(&key, &prehash);
        assert_eq!(sig, h::<64>(&get("reply_sig")));
        let devpub = h::<33>(&get("devpub"));
        verify_reply(&devpub, &prehash, &sig).unwrap();
        // another session's prehash, another key, a high-s twin: refused
        let mut other = prehash;
        other[31] ^= 1;
        assert_eq!(verify_reply(&devpub, &other, &sig), Err(Error::Crypto));
        let impostor = DeviceKey::from_secret(&[7; 32], "impostor").unwrap();
        assert_eq!(
            verify_reply(impostor.did().pubkey(), &prehash, &sig),
            Err(Error::Crypto)
        );
        assert_eq!(
            verify_reply(&devpub, &prehash, &high_s(&sig)),
            Err(Error::Crypto)
        );
    }

    /// `s` replaced by `n - s`: the same point, the other half of the range.
    fn high_s(sig: &[u8; 64]) -> [u8; 64] {
        let n = h::<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        let mut out = *sig;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(n[i]) - i16::from(sig[32 + i]) - borrow;
            borrow = i16::from(d < 0);
            out[32 + i] = (d + if d < 0 { 256 } else { 0 }) as u8;
        }
        out
    }

    #[test]
    fn the_stored_records() {
        let mut kv = MemoryKv::new();
        assert_eq!(load_verifier(&kv), Ok(None));
        assert_eq!(load_failures(&kv), Ok(0));
        let record = [0x5A; SETUP_VERIFIER_LEN];
        store_verifier(&mut kv, &record).unwrap();
        assert_eq!(load_verifier(&kv), Ok(Some(record)));
        store_failures(&mut kv, 3).unwrap();
        assert_eq!(load_failures(&kv), Ok(3));
        kv.put(KV_SETUP_VERIFIER, &[1; 117]).unwrap();
        assert_eq!(load_verifier(&kv), Err(Error::Corrupt));
        kv.put(KV_SETUP_VERIFIER, &[1; 200]).unwrap();
        assert_eq!(load_verifier(&kv), Err(Error::Corrupt));
        kv.put(KV_SETUP_FAILURES, &[1, 2]).unwrap();
        assert_eq!(load_failures(&kv), Err(Error::Corrupt));
    }

    #[test]
    fn a_context_too_long_for_its_prefix() {
        let big = [0u8; 70_000];
        assert_eq!(
            reply_prehash(&big, &[4; 65], &[4; 65], &[0; 32]),
            Err(Error::InvalidFormat)
        );
    }
}
