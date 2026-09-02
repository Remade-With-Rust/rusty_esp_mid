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

use crate::did::Did;
use crate::jws::build_jws_compact;
use crate::roster::{VerificationMethod, sign_genesis_roster};
use crate::signer::DeviceSigner;

/// Provenance of a claim. v1 has exactly one variant.
pub use mid_types::{
    AttestedBy, ClaimValue, EmbeddedRosterChainEntry, EmbeddedVerificationMethod, MidJwtPayload,
};

/// A self-attested string claim (what a device says about itself).
#[must_use]
pub fn self_attested(value: &str) -> ClaimValue {
    ClaimValue {
        value: serde_json::Value::String(String::from(value)),
        attested_by: AttestedBy::SelfAttested,
        verified_at_signup: None,
        computed_at: None,
        formula_version: None,
    }
}

/// The verification method as the token embeds it.
#[must_use]
pub fn embedded_vm(vm: VerificationMethod) -> EmbeddedVerificationMethod {
    EmbeddedVerificationMethod {
        id: vm.id,
        vm_type: vm.vm_type,
        controller: vm.controller,
        public_key_multibase: vm.public_key_multibase,
    }
}

/// What a relying party asks a device to sign in with: its audience and a
/// single-use nonce.
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
        embedded_verification_method: embedded_vm(vm),
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
        claims.insert(String::from("name"), self_attested("acme doorbell"));
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
