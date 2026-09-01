//! The gateway handshake: a server-issued `NonceEnvelope`, signed by the
//! device into a `SignedAssertion`. Byte-identical to `kms-types`.
//!
//! The canonical form (what is signed) is
//!
//! ```text
//! sha256(
//!   "kms-nonce-v1\n" || envelope_version (1 byte) ||
//!   len16(nonce) || nonce || len16(did) || did || len16(audience) || audience ||
//!   len16(purpose) || purpose || issued_at (8 BE) || expires_at (8 BE) ||
//!   len16(issuer) || issuer
//! )
//! ```
//!
//! and needs no allocation: [`NonceEnvelopeRef`] borrows every field, so a
//! heapless firmware can sign a challenge it parsed into a stack buffer. The
//! owned, `serde` JSON shapes are behind `alloc`.

use rusty_esp_core::error::{Error, Result};
use sha2::Digest;

use crate::signer::DeviceSigner;

/// Domain separator of the nonce envelope's canonical form.
pub const NONCE_DOMAIN: &[u8] = b"kms-nonce-v1\n";

/// Current envelope version.
pub const ENVELOPE_VERSION: u8 = 1;

/// `envelope_type` of a nonce envelope.
pub const NONCE_TYPE: &str = "nonce";

/// `envelope_type` of a signed assertion.
pub const ASSERTION_TYPE: &str = "signed_assertion";

/// Hard upper bound on `expires_at - issued_at`, per the kms spec.
pub const MAX_TTL_SECS: u64 = 300;

/// A nonce envelope over borrowed fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceEnvelopeRef<'a> {
    /// Envelope version; always [`ENVELOPE_VERSION`].
    pub envelope_version: u8,
    /// 32 random bytes, single-use.
    pub nonce: &'a [u8],
    /// The DID the nonce is bound to.
    pub did: &'a str,
    /// The service that issued and will consume the nonce.
    pub audience: &'a str,
    /// The operation the nonce authorises.
    pub purpose: &'a str,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds.
    pub expires_at: u64,
    /// The service instance that minted the nonce.
    pub issuer: &'a str,
}

impl NonceEnvelopeRef<'_> {
    /// Shape validation, as `kms-types` does it.
    pub fn validate(&self) -> Result<()> {
        if self.envelope_version != ENVELOPE_VERSION {
            return Err(Error::Unsupported);
        }
        if self.nonce.len() != 32 {
            return Err(Error::InvalidFormat);
        }
        crate::did::Did::parse(self.did)?;
        if self.expires_at <= self.issued_at || self.expires_at - self.issued_at > MAX_TTL_SECS {
            return Err(Error::InvalidFormat);
        }
        for field in [self.did, self.audience, self.purpose, self.issuer] {
            if field.len() > u16::MAX as usize {
                return Err(Error::InvalidFormat);
            }
        }
        Ok(())
    }

    /// The 32-byte prehash the signature covers.
    #[must_use]
    pub fn canonical_bytes(&self) -> [u8; 32] {
        let mut h = sha2::Sha256::new();
        h.update(NONCE_DOMAIN);
        h.update([self.envelope_version]);
        lp(&mut h, self.nonce);
        lp(&mut h, self.did.as_bytes());
        lp(&mut h, self.audience.as_bytes());
        lp(&mut h, self.purpose.as_bytes());
        h.update(self.issued_at.to_be_bytes());
        h.update(self.expires_at.to_be_bytes());
        lp(&mut h, self.issuer.as_bytes());
        h.finalize().into()
    }

    /// Sign this envelope; returns the 64-byte low-s signature.
    pub fn sign(&self, signer: &impl DeviceSigner) -> Result<[u8; 64]> {
        self.validate()?;
        Ok(signer.sign_prehash(&self.canonical_bytes()))
    }
}

fn lp(h: &mut sha2::Sha256, bytes: &[u8]) {
    // Callers validate lengths ≤ u16::MAX; saturate rather than wrap so a
    // bug can never make two different messages hash alike by truncation.
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    h.update(len.to_be_bytes());
    h.update(bytes);
}

/// The owned, JSON-shaped envelopes.
#[cfg(feature = "alloc")]
pub mod json {
    use alloc::string::String;
    use alloc::vec::Vec;

    use rusty_esp_core::error::{Error, Result};
    use serde::{Deserialize, Serialize};

    use super::{ASSERTION_TYPE, ENVELOPE_VERSION, NONCE_TYPE, NonceEnvelopeRef};
    use crate::signer::DeviceSigner;

    /// `base64url` (no padding) adapter for byte fields, as `kms-types` uses.
    pub mod b64 {
        use alloc::string::String;
        use alloc::vec::Vec;

        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use serde::{Deserialize, Deserializer, Serializer};

        /// Serialize bytes as base64url without padding.
        pub fn serialize<S: Serializer>(
            bytes: &Vec<u8>,
            ser: S,
        ) -> core::result::Result<S::Ok, S::Error> {
            ser.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
        }

        /// Deserialize base64url without padding into bytes.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            de: D,
        ) -> core::result::Result<Vec<u8>, D::Error> {
            let s = String::deserialize(de)?;
            URL_SAFE_NO_PAD
                .decode(s.as_bytes())
                .map_err(serde::de::Error::custom)
        }
    }

    /// The nonce envelope as the gateway sends it. Field order matches
    /// `kms-types` so the JSON is byte-identical.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct NonceEnvelope {
        /// Always 1.
        pub envelope_version: u8,
        /// Always `"nonce"`.
        pub envelope_type: String,
        /// 32 random bytes.
        #[serde(with = "b64")]
        pub nonce: Vec<u8>,
        /// The DID the nonce is bound to.
        pub did: String,
        /// The consuming service.
        pub audience: String,
        /// The authorised operation.
        pub purpose: String,
        /// Unix seconds.
        pub issued_at: u64,
        /// Unix seconds.
        pub expires_at: u64,
        /// The minting service instance.
        pub issuer: String,
    }

    impl NonceEnvelope {
        /// Parse the gateway's JSON.
        pub fn from_json(json: &str) -> Result<Self> {
            let env: NonceEnvelope =
                serde_json::from_str(json).map_err(|_| Error::InvalidFormat)?;
            env.validate()?;
            Ok(env)
        }

        /// Serialize to JSON.
        #[must_use]
        pub fn to_json(&self) -> String {
            serde_json::to_string(self).expect("serializing plain fields cannot fail")
        }

        /// Borrow as the no-alloc form.
        #[must_use]
        pub fn as_ref(&self) -> NonceEnvelopeRef<'_> {
            NonceEnvelopeRef {
                envelope_version: self.envelope_version,
                nonce: &self.nonce,
                did: &self.did,
                audience: &self.audience,
                purpose: &self.purpose,
                issued_at: self.issued_at,
                expires_at: self.expires_at,
                issuer: &self.issuer,
            }
        }

        /// Shape validation, including the type discriminant.
        pub fn validate(&self) -> Result<()> {
            if self.envelope_type != NONCE_TYPE {
                return Err(Error::InvalidFormat);
            }
            self.as_ref().validate()
        }

        /// Sign into a [`SignedAssertion`].
        pub fn sign(&self, signer: &impl DeviceSigner) -> Result<SignedAssertion> {
            let signature = self.as_ref().sign(signer)?;
            Ok(SignedAssertion {
                envelope_version: ENVELOPE_VERSION,
                envelope_type: String::from(ASSERTION_TYPE),
                nonce_envelope: self.clone(),
                device_id: String::from(signer.device_id()),
                signature: signature.to_vec(),
            })
        }
    }

    /// The device's signed envelope, as the gateway verifies it.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SignedAssertion {
        /// Always 1.
        pub envelope_version: u8,
        /// Always `"signed_assertion"`.
        pub envelope_type: String,
        /// The envelope verbatim.
        pub nonce_envelope: NonceEnvelope,
        /// Which roster entry signed.
        pub device_id: String,
        /// 64-byte low-s `r || s`.
        #[serde(with = "b64")]
        pub signature: Vec<u8>,
    }

    impl SignedAssertion {
        /// Serialize to JSON — the body of the gateway request, or the
        /// `Resource-Assertion` header after base64url.
        #[must_use]
        pub fn to_json(&self) -> String {
            serde_json::to_string(self).expect("serializing plain fields cannot fail")
        }

        /// Parse JSON.
        pub fn from_json(json: &str) -> Result<Self> {
            serde_json::from_str(json).map_err(|_| Error::InvalidFormat)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;

    fn env<'a>(did: &'a str, nonce: &'a [u8; 32]) -> NonceEnvelopeRef<'a> {
        NonceEnvelopeRef {
            envelope_version: 1,
            nonce,
            did,
            audience: "home-computer",
            purpose: "janus.telemetry",
            issued_at: 1_716_583_200,
            expires_at: 1_716_583_230,
            issuer: "home-computer-gateway",
        }
    }

    #[test]
    fn canonical_is_deterministic_and_field_sensitive() {
        let k = DeviceKey::from_seed_for_tests("kms", "dev");
        let did = k.did().to_did_string();
        let nonce = [0xAB; 32];
        let a = env(&did, &nonce);
        let base = a.canonical_bytes();
        assert_eq!(base, a.canonical_bytes());
        let mut b = a;
        b.purpose = "janus.control";
        assert_ne!(base, b.canonical_bytes());
        let mut c = a;
        c.expires_at += 1;
        assert_ne!(base, c.canonical_bytes());
    }

    #[test]
    fn validate_rules() {
        let k = DeviceKey::from_seed_for_tests("kms", "dev");
        let did = k.did().to_did_string();
        let nonce = [1u8; 32];
        assert!(env(&did, &nonce).validate().is_ok());
        let mut bad = env(&did, &nonce);
        bad.expires_at = bad.issued_at + 301;
        assert_eq!(bad.validate(), Err(Error::InvalidFormat));
        let short = [1u8; 31];
        let mut bad = env(&did, &nonce);
        bad.nonce = &short;
        assert_eq!(bad.validate(), Err(Error::InvalidFormat));
        let mut bad = env(&did, &nonce);
        bad.envelope_version = 2;
        assert_eq!(bad.validate(), Err(Error::Unsupported));
    }
}
