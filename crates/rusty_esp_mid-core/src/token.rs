//! The self-issued mID token: what a device presents to any relying party
//! that runs `mid-verify` — including the home computer's sign-in kit.
//!
//! Payload field names are `mid-issuer`'s, exactly. A device is its own
//! genesis roster with no chain, so the token carries one verification
//! method and its size is the floor of what an mID token can be.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use rusty_esp_core::error::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::did::Did;
use crate::jws::build_jws_compact;
use crate::roster::{EmbeddedGenesisRoster, VerificationMethod, sign_genesis_roster};
use crate::signer::DeviceSigner;

/// Provenance of a claim. v1 has exactly one variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestedBy {
    /// Supplied by the identity itself, covered by the outer signature.
    #[serde(rename = "self")]
    SelfAttested,
}

/// A claim value with provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimValue {
    /// The value.
    pub value: serde_json::Value,
    /// Provenance.
    pub attested_by: AttestedBy,
    /// Only on `email`, only when verified at signup. Never set by a device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at_signup: Option<bool>,
    /// Only on derived claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computed_at: Option<u64>,
    /// Only on derived claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formula_version: Option<String>,
}

impl ClaimValue {
    /// A self-attested string claim.
    #[must_use]
    pub fn string(value: &str) -> Self {
        ClaimValue {
            value: serde_json::Value::String(String::from(value)),
            attested_by: AttestedBy::SelfAttested,
            verified_at_signup: None,
            computed_at: None,
            formula_version: None,
        }
    }
}

/// The current device's verification method, slim form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedVerificationMethod {
    /// `did:mata:…#<device_id>`.
    pub id: String,
    /// Always [`crate::VM_TYPE_ECDSA_P256`].
    #[serde(rename = "type")]
    pub vm_type: String,
    /// The controlling DID.
    pub controller: String,
    /// `z<base58>`.
    pub public_key_multibase: String,
}

impl From<VerificationMethod> for EmbeddedVerificationMethod {
    fn from(vm: VerificationMethod) -> Self {
        EmbeddedVerificationMethod {
            id: vm.id,
            vm_type: vm.vm_type,
            controller: vm.controller,
            public_key_multibase: vm.public_key_multibase,
        }
    }
}

/// The mID JWT payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MidJwtPayload {
    /// Issuer: the DID.
    pub iss: String,
    /// Subject: the DID.
    pub sub: String,
    /// The relying party's audience string (its origin).
    pub aud: String,
    /// Issued at, Unix seconds.
    pub iat: u64,
    /// Expiry, Unix seconds.
    pub exp: u64,
    /// The RP's single-use nonce, echoed.
    pub nonce: String,
    /// Consented claims.
    pub claims: BTreeMap<String, ClaimValue>,
    /// The self-signed genesis roster.
    pub embedded_genesis_roster: EmbeddedGenesisRoster,
    /// Roster mutations since genesis (none for a device).
    pub embedded_roster_chain: Vec<serde_json::Value>,
    /// The signing key's verification method.
    pub embedded_verification_method: EmbeddedVerificationMethod,
}

/// What a relying party asked for, minus the consent UI a device does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInRequest<'a> {
    /// The RP's audience (its exact origin).
    pub audience: &'a str,
    /// The RP-issued single-use nonce.
    pub nonce: &'a str,
}

/// Build a self-issued mID token for `did`, whose key is `signer`.
///
/// `iat` is the current Unix time (from the host or the hub; a device's own
/// clock is monotonic only), `ttl_secs` the validity window (mID ships ~1 h).
pub fn build_self_issued_token(
    did: &Did,
    signer: &impl DeviceSigner,
    request: &SignInRequest<'_>,
    iat: u64,
    ttl_secs: u64,
    claims: BTreeMap<String, ClaimValue>,
) -> Result<String> {
    if request.audience.is_empty() || request.nonce.is_empty() || ttl_secs == 0 {
        return Err(Error::InvalidFormat);
    }
    let genesis = sign_genesis_roster(did, signer, iat.saturating_sub(1).max(1));
    let vm = genesis
        .verification_methods
        .first()
        .cloned()
        .ok_or(Error::Corrupt)?;
    let did_s = did.to_did_string();
    let payload = MidJwtPayload {
        iss: did_s.clone(),
        sub: did_s,
        aud: String::from(request.audience),
        iat,
        exp: iat.saturating_add(ttl_secs),
        nonce: String::from(request.nonce),
        claims,
        embedded_genesis_roster: genesis,
        embedded_roster_chain: Vec::new(),
        embedded_verification_method: vm.into(),
    };
    let json = serde_json::to_vec(&payload).map_err(|_| Error::InvalidFormat)?;
    Ok(build_jws_compact(&json, signer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;

    #[test]
    fn token_has_three_segments_and_echoes_the_request() {
        let k = DeviceKey::from_seed_for_tests("tok", "cam-1");
        let mut claims = BTreeMap::new();
        claims.insert(String::from("name"), ClaimValue::string("acme doorbell"));
        let jwt = build_self_issued_token(
            &k.did(),
            &k,
            &SignInRequest {
                audience: "https://home.local",
                nonce: "n-1",
            },
            1_700_000_000,
            3600,
            claims,
        )
        .unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap();
        let p: MidJwtPayload = serde_json::from_slice(&payload).unwrap();
        assert_eq!(p.aud, "https://home.local");
        assert_eq!(p.nonce, "n-1");
        assert_eq!(p.iss, k.did().to_did_string());
        assert_eq!(p.exp - p.iat, 3600);
        assert!(p.embedded_roster_chain.is_empty());
    }

    #[test]
    fn rejects_empty_request() {
        let k = DeviceKey::from_seed_for_tests("tok", "cam-1");
        let r = build_self_issued_token(
            &k.did(),
            &k,
            &SignInRequest {
                audience: "",
                nonce: "n",
            },
            1,
            1,
            BTreeMap::new(),
        );
        assert_eq!(r.err(), Some(Error::InvalidFormat));
    }
}
