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

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::did::Did;
use crate::signer::DeviceSigner;

/// Domain separator of the genesis roster envelope.
pub use mid_types::canonical::{genesis_canonical_bytes, GENESIS_DOMAIN};
pub use mid_types::{EmbeddedGenesisRoster, VerificationMethod};

/// The verification method a device publishes for its key: id `<did>#<device_id>`,
/// P-256, controlled by the DID, the key as multibase.
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
