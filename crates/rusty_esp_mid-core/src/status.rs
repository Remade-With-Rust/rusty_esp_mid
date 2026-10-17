//! **The signed status** — how a device proves, on a local network, who it is
//! and who it belongs to, in answer to a verifier's fresh nonce.
//!
//! A home's hub (Apollo's server, or the MATA box) finds a device and asks
//! `GET /v1/status?nonce=<64 lowercase hex>`. The device answers with its
//! claims and a signature, by its own key, over this message:
//!
//! ```text
//! "janus-status-v1\n"
//! version (1)                       = 1
//! nonce (32)                        the verifier's, raw
//! len16(device_did)    device_did
//! len16(owner_did)     owner_did    empty when not adopted
//! len16(adoption_kind) adoption_kind
//!                                   "janus-adoption-v1" | "mata-statement-v1" | empty
//! adoption_hash (32)                sha256 of the adoption's decoded bytes (the
//!                                   v1 envelope, or the statement container's
//!                                   UTF-8 JSON);
//!                                   32 zero bytes when not adopted
//! ```
//!
//! `len16` is a 2-byte big-endian length, as in the adoption envelope. The
//! signature is [`DeviceSigner::sign_prehash`] over `sha256(message)`: P-256,
//! 64-byte `r || s`, low-s, RFC 6979 deterministic. A verifier must reject
//! high-s, which [`verify_prehash`] (and so [`StatusProof::verify`]) does.
//!
//! One signature covers the adoption too, through its hash: the verifier
//! checks the adoption itself (its owner's signature) and that its hash and
//! owner match what the device signed, so a device cannot sign for one owner
//! while carrying another's grant.
//!
//! No allocation: the message is hashed as it is laid out, and written out in
//! full only when asked ([`StatusProof::write`]).

use rusty_esp_core::error::{Error, Result};
use sha2::Digest;

use crate::did::Did;
use crate::signer::{DeviceSigner, verify_prehash};

/// Domain separator.
pub const STATUS_DOMAIN: &[u8] = b"janus-status-v1\n";

/// The layout's version byte.
pub const STATUS_VERSION: u8 = 1;

/// `adoption_kind` for a raw `janus-adoption-v1` envelope.
pub const KIND_ADOPTION_V1: &str = "janus-adoption-v1";

/// `adoption_kind` for a MATA wallet signed statement: base64url of the JSON
/// container `{"content":…,"jws":…}` (the wallet's `signStatement`, context
/// `janus-adoption-v1`).
pub const KIND_MATA_STATEMENT: &str = "mata-statement-v1";

/// `adoption_hash` when the device holds no adoption.
pub const NO_ADOPTION: [u8; 32] = [0; 32];

/// The claims a device signs in answer to a nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusProof<'a> {
    /// The verifier's nonce.
    pub nonce: &'a [u8; 32],
    /// The device's own `did:mata`.
    pub device_did: &'a str,
    /// The owner as the device accepted it; empty when not adopted.
    pub owner_did: &'a str,
    /// [`KIND_ADOPTION_V1`], [`KIND_MATA_STATEMENT`], or empty when not adopted.
    pub adoption_kind: &'a str,
    /// `sha256` of the adoption's raw bytes, or [`NO_ADOPTION`].
    pub adoption_hash: [u8; 32],
}

impl<'a> StatusProof<'a> {
    /// A device that holds no adoption.
    #[must_use]
    pub const fn unadopted(nonce: &'a [u8; 32], device_did: &'a str) -> Self {
        Self {
            nonce,
            device_did,
            owner_did: "",
            adoption_kind: "",
            adoption_hash: NO_ADOPTION,
        }
    }

    /// A device adopted by `owner_did` through `adoption` (its decoded bytes:
    /// the v1 envelope, or the statement container's UTF-8 JSON) of
    /// `adoption_kind`.
    #[must_use]
    pub fn adopted(
        nonce: &'a [u8; 32],
        device_did: &'a str,
        owner_did: &'a str,
        adoption_kind: &'a str,
        adoption: &[u8],
    ) -> Self {
        Self {
            nonce,
            device_did,
            owner_did,
            adoption_kind,
            adoption_hash: crate::sha256(adoption),
        }
    }

    /// The message's length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        STATUS_DOMAIN.len()
            + 1
            + 32
            + 2
            + self.device_did.len()
            + 2
            + self.owner_did.len()
            + 2
            + self.adoption_kind.len()
            + 32
    }

    /// Never empty: the domain alone is 16 bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Lay the message out field by field, in order.
    fn fields(&self, mut put: impl FnMut(&[u8])) -> Result<()> {
        let str16 = |s: &str| -> Result<[u8; 2]> {
            let n = u16::try_from(s.len()).map_err(|_| Error::InvalidFormat)?;
            Ok(n.to_be_bytes())
        };
        let (dev, own, kind) = (
            str16(self.device_did)?,
            str16(self.owner_did)?,
            str16(self.adoption_kind)?,
        );
        put(STATUS_DOMAIN);
        put(&[STATUS_VERSION]);
        put(self.nonce);
        put(&dev);
        put(self.device_did.as_bytes());
        put(&own);
        put(self.owner_did.as_bytes());
        put(&kind);
        put(self.adoption_kind.as_bytes());
        put(&self.adoption_hash);
        Ok(())
    }

    /// Write the message into `out`; its length.
    pub fn write(&self, out: &mut [u8]) -> Result<usize> {
        let needed = self.len();
        if out.len() < needed {
            return Err(Error::BufferTooSmall { needed });
        }
        let mut at = 0;
        self.fields(|b| {
            out[at..at + b.len()].copy_from_slice(b);
            at += b.len();
        })?;
        Ok(at)
    }

    /// `sha256(message)`, the prehash the device signs.
    pub fn prehash(&self) -> Result<[u8; 32]> {
        let mut h = sha2::Sha256::new();
        self.fields(|b| h.update(b))?;
        Ok(h.finalize().into())
    }

    /// The device's signature over the message.
    pub fn sign(&self, signer: &impl DeviceSigner) -> Result<[u8; 64]> {
        Ok(signer.sign_prehash(&self.prehash()?))
    }

    /// Verify `signature` under the key `device_did` names (high-s refused).
    pub fn verify(&self, signature: &[u8; 64]) -> Result<()> {
        let did = Did::parse(self.device_did)?;
        verify_prehash(did.pubkey(), &self.prehash()?, signature)
    }
}

/// The query's nonce: exactly 64 lowercase hex characters, to 32 bytes.
pub fn parse_nonce_hex(s: &str) -> Result<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return Err(Error::InvalidFormat);
    }
    let nibble = |c: u8| -> Result<u8> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(Error::InvalidFormat),
        }
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nibble(b[2 * i])? << 4) | nibble(b[2 * i + 1])?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;

    const NONCE: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    fn did_of(key: &DeviceKey) -> ([u8; 64], usize) {
        let mut buf = [0u8; 64];
        let n = key.did().write(&mut buf).expect("did fits").len();
        (buf, n)
    }

    /// The message laid out by hand, independently of `fields`.
    fn by_hand(device: &str, owner: &str, kind: &str, hash: &[u8; 32]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"janus-status-v1\n");
        m.push(1);
        m.extend_from_slice(&NONCE);
        for s in [device, owner, kind] {
            m.extend_from_slice(&(s.len() as u16).to_be_bytes());
            m.extend_from_slice(s.as_bytes());
        }
        m.extend_from_slice(hash);
        m
    }

    #[test]
    fn the_message_is_laid_out_as_the_contract_says() {
        let key = DeviceKey::from_seed_for_tests("status-vector-device", "dev-1");
        let (buf, n) = did_of(&key);
        let device = core::str::from_utf8(&buf[..n]).unwrap();
        let owner = "did:mata:owner-for-the-layout-test";
        let adoption = b"an adoption's raw bytes";
        let p = StatusProof::adopted(&NONCE, device, owner, KIND_ADOPTION_V1, adoption);
        let mut out = [0u8; 256];
        let len = p.write(&mut out).unwrap();
        assert_eq!(len, p.len());
        let expected = by_hand(device, owner, KIND_ADOPTION_V1, &crate::sha256(adoption));
        assert_eq!(&out[..len], &expected[..]);
        assert_eq!(p.prehash().unwrap(), crate::sha256(&expected));
    }

    #[test]
    fn unadopted_is_empty_strings_and_a_zero_hash() {
        let p = StatusProof::unadopted(&NONCE, "did:mata:x");
        let mut out = [0u8; 128];
        let len = p.write(&mut out).unwrap();
        assert_eq!(&out[..len], &by_hand("did:mata:x", "", "", &[0; 32])[..]);
        // not the hash of an empty adoption: "none" and "empty" never collide
        assert_ne!(NO_ADOPTION, crate::sha256(b""));
    }

    #[test]
    fn a_short_buffer_says_what_it_needed() {
        let p = StatusProof::unadopted(&NONCE, "did:mata:x");
        assert_eq!(
            p.write(&mut [0u8; 8]),
            Err(Error::BufferTooSmall { needed: p.len() })
        );
    }

    #[test]
    fn signed_by_the_device_verifies_and_nothing_else_does() {
        let key = DeviceKey::from_seed_for_tests("status-vector-device", "dev-1");
        let (buf, n) = did_of(&key);
        let device = core::str::from_utf8(&buf[..n]).unwrap();
        let p = StatusProof::adopted(&NONCE, device, "did:mata:o", KIND_MATA_STATEMENT, b"h.p.s");
        let sig = p.sign(&key).unwrap();
        assert_eq!(p.verify(&sig), Ok(()));
        // any field changed: refused
        let other_nonce = [9u8; 32];
        assert!(
            StatusProof {
                nonce: &other_nonce,
                ..p
            }
            .verify(&sig)
            .is_err()
        );
        assert!(
            StatusProof {
                owner_did: "did:mata:p",
                ..p
            }
            .verify(&sig)
            .is_err()
        );
        assert!(
            StatusProof {
                adoption_kind: KIND_ADOPTION_V1,
                ..p
            }
            .verify(&sig)
            .is_err()
        );
        assert!(
            StatusProof {
                adoption_hash: NO_ADOPTION,
                ..p
            }
            .verify(&sig)
            .is_err()
        );
        // another device's key: refused
        let other = DeviceKey::from_seed_for_tests("someone-else", "dev-2");
        assert!(p.verify(&p.sign(&other).unwrap()).is_err());
        // the high-s twin of a good signature: refused
        use p256::elliptic_curve::PrimeField;
        let mut high = sig;
        let mut s_bytes = p256::FieldBytes::default();
        s_bytes.copy_from_slice(&sig[32..]);
        let s = p256::Scalar::from_repr(s_bytes).into_option().unwrap();
        high[32..].copy_from_slice(&(-s).to_bytes());
        assert!(p.verify(&high).is_err());
    }

    #[test]
    fn the_nonce_is_64_lowercase_hex() {
        let hex: String = NONCE.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_nonce_hex(&hex), Ok(NONCE));
        assert!(parse_nonce_hex(&hex.to_uppercase()).is_err());
        assert!(parse_nonce_hex(&hex[..62]).is_err());
        assert!(parse_nonce_hex(&format!("{hex}00")).is_err());
        assert!(parse_nonce_hex(&format!("{}zz", &hex[..62])).is_err());
    }
}

#[cfg(test)]
mod vector {
    //! The vector both sides pin (`janus-status-v1`, Track 1 of Apollo's
    //! hard-toys): the chip's bytes, so a verifier's implementation is checked
    //! against them rather than against itself. Cross-checked 2026-10-17 with
    //! an independent ECDSA (Python `cryptography`): the message rebuilt from
    //! the contract by hand, the DID derived from the key, the signature low-s
    //! and verifying.
    use super::*;
    use crate::key::DeviceKey;

    /// The device's secret scalar (`DeviceKey::from_seed_for_tests(
    /// "janus-status-v1-vector", "vector")`).
    pub const SECRET: &str = "b2f00d8c0abf7e2cffa4dcad2d2b27cf47656e2b97eb19e787c5f69ec0572e67";
    pub const DEVICE_DID: &str = "did:mata:huF8W8oTSzSJybQztujeQc5BLiiMXYG7xUtXgkEkXjYj";
    /// Bytes 0..32.
    pub const NONCE: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    pub const OWNER_DID: &str = "did:mata:zOwnerForTheVector";
    /// The adoption's raw bytes the vector hashes (a stand-in, not an envelope).
    pub const ADOPTION: &[u8] = b"janus-adoption-v1 vector bytes";
    pub const MESSAGE: &str = "6a616e75732d7374617475732d76310a01000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00356469643a6d6174613a6875463857386f54537a534a7962517a74756a65516335424c69694d5859473778557458676b456b586a596a001b6469643a6d6174613a7a4f776e6572466f72546865566563746f7200116a616e75732d61646f7074696f6e2d7631cc0fe955facc03fe83d5c98365c445eea2f021139e78ec8cfbd120c991f9bb1e";
    pub const PREHASH: &str = "ff77b0f7d0d4433bac8c76ddafbb4c1f9257a803a59fdc4efb3622c5567079ba";
    pub const SIGNATURE: &str = "af346d509a8ec6e32161250a41c9ee4f88197c136c3f977132964f4d542a9ffb068d86182fafa42a2a44787f0c107f71ec553f1a0414292948848ae8bf4d25df";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn the_chip_produces_exactly_the_vector() {
        let key = DeviceKey::from_seed_for_tests("janus-status-v1-vector", "vector");
        assert_eq!(hex(&key.secret_bytes()), SECRET);
        let mut buf = [0u8; 64];
        assert_eq!(key.did().write(&mut buf).unwrap(), DEVICE_DID);
        let p = StatusProof::adopted(&NONCE, DEVICE_DID, OWNER_DID, KIND_ADOPTION_V1, ADOPTION);
        let mut out = [0u8; 256];
        let n = p.write(&mut out).unwrap();
        assert_eq!(hex(&out[..n]), MESSAGE);
        assert_eq!(hex(&p.prehash().unwrap()), PREHASH);
        // RFC 6979: the same key and message give the same signature
        let sig = p.sign(&key).unwrap();
        assert_eq!(hex(&sig), SIGNATURE);
        assert_eq!(p.verify(&sig), Ok(()));
    }
}
