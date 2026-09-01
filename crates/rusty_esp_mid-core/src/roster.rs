//! The self-signed genesis roster — the identity proof embedded in a
//! self-issued mID token. Types, field names and the canonical byte form are
//! those of `mid-issuer`; the device's genesis roster has exactly one
//! verification method: itself.
//!
//! Canonical form (what the genesis signature covers):
//!
//! ```text
//! "mid-genesis-roster-v1" || version (8 BE) || len32(did) || did ||
//! vm_count (4 BE) || for each vm: len32(id) id len32(type) type
//!                                  len32(controller) controller len32(mb) mb ||
//! signed_at (8 BE)
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::did::Did;
use crate::signer::DeviceSigner;

/// Domain separator of the genesis roster envelope.
pub const GENESIS_DOMAIN: &[u8] = b"mid-genesis-roster-v1";

/// A public key bound to a DID — the W3C `verificationMethod` minimum form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// `did:mata:…#<device_id>`.
    pub id: String,
    /// Always [`crate::VM_TYPE_ECDSA_P256`].
    #[serde(rename = "type")]
    pub vm_type: String,
    /// The controlling DID.
    pub controller: String,
    /// `z<base58btc(33-byte compressed key)>`.
    pub public_key_multibase: String,
}

/// The genesis roster envelope, version 1, self-signed by the DID's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedGenesisRoster {
    /// Always 1.
    pub version: u64,
    /// The DID.
    pub did: String,
    /// The genesis verification methods (one, for a device).
    pub verification_methods: Vec<VerificationMethod>,
    /// Unix seconds.
    pub signed_at: u64,
    /// base64url `r || s` by the genesis key over [`genesis_canonical_bytes`].
    pub self_signed_by_genesis_key: String,
}

/// The canonical bytes the genesis signature covers (the signature field is
/// excluded).
#[must_use]
pub fn genesis_canonical_bytes(genesis: &EmbeddedGenesisRoster) -> Vec<u8> {
    let mut buf = Vec::with_capacity(GENESIS_DOMAIN.len() + 128);
    buf.extend_from_slice(GENESIS_DOMAIN);
    buf.extend_from_slice(&genesis.version.to_be_bytes());
    push_string(&mut buf, &genesis.did);
    buf.extend_from_slice(&(genesis.verification_methods.len() as u32).to_be_bytes());
    for vm in &genesis.verification_methods {
        push_string(&mut buf, &vm.id);
        push_string(&mut buf, &vm.vm_type);
        push_string(&mut buf, &vm.controller);
        push_string(&mut buf, &vm.public_key_multibase);
    }
    buf.extend_from_slice(&genesis.signed_at.to_be_bytes());
    buf
}

fn push_string(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

/// The verification method for `did`'s device `device_id`.
#[must_use]
pub fn verification_method(did: &Did, device_id: &str) -> VerificationMethod {
    let did_s = did.to_did_string();
    VerificationMethod {
        id: alloc::format!("{did_s}#{device_id}"),
        vm_type: String::from(crate::VM_TYPE_ECDSA_P256),
        controller: did_s,
        public_key_multibase: did.to_multibase_string(),
    }
}

/// Sign the device's one-entry genesis roster. `did` must be the signer's own
/// DID: the roster is self-certifying only because the signing key *is* the
/// key the DID encodes.
#[must_use]
pub fn sign_genesis_roster(
    did: &Did,
    signer: &impl DeviceSigner,
    signed_at: u64,
) -> EmbeddedGenesisRoster {
    let mut genesis = EmbeddedGenesisRoster {
        version: 1,
        did: did.to_did_string(),
        verification_methods: alloc::vec![verification_method(did, signer.device_id())],
        signed_at,
        self_signed_by_genesis_key: String::new(),
    };
    let prehash = crate::sha256(&genesis_canonical_bytes(&genesis));
    genesis.self_signed_by_genesis_key = URL_SAFE_NO_PAD.encode(signer.sign_prehash(&prehash));
    genesis
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;
    use crate::signer::verify_prehash;

    #[test]
    fn genesis_self_signature_verifies_under_the_did_key() {
        let k = DeviceKey::from_seed_for_tests("g", "cam-1");
        let g = sign_genesis_roster(&k.did(), &k, 1_700_000_000);
        assert_eq!(g.version, 1);
        assert_eq!(g.verification_methods.len(), 1);
        assert!(g.verification_methods[0].id.ends_with("#cam-1"));
        let sig: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&g.self_signed_by_genesis_key)
            .unwrap()
            .try_into()
            .unwrap();
        let prehash = crate::sha256(&genesis_canonical_bytes(&g));
        verify_prehash(k.did().pubkey(), &prehash, &sig).unwrap();
    }

    #[test]
    fn canonical_excludes_signature_and_starts_with_domain() {
        let k = DeviceKey::from_seed_for_tests("g", "cam-1");
        let mut g = sign_genesis_roster(&k.did(), &k, 1);
        let a = genesis_canonical_bytes(&g);
        g.self_signed_by_genesis_key = String::from("x");
        assert_eq!(a, genesis_canonical_bytes(&g));
        assert!(a.starts_with(GENESIS_DOMAIN));
    }
}
