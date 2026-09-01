#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `rusty_esp_mid-core` — MATA mID on the chip, the pure core.
//!
//! A Janus device is its own `did:mata`: a P-256 key generated on the chip,
//! whose compressed public key *is* the identifier. This crate holds
//! everything about that identity that needs no driver:
//!
//! | Module | Holds | Interoperates with |
//! |---|---|---|
//! | [`did`] | [`Did`] — `did:mata:<base58btc(33-byte SEC1)>`, no-alloc encode/parse | `mid-verify::did_from_pubkey` |
//! | [`key`] | [`DeviceKey`] — generate from a TRNG, persist through the `Kv` seam, ECDH | |
//! | [`signer`] | [`DeviceSigner`] — **byte-for-byte** the trait `mid`'s `kms-client` defines | `kms-client::DeviceSigner` |
//! | [`kms`] | the `NonceEnvelope` canonical form and the `SignedAssertion` a gateway verifies | `kms-types`, `kms-verifier` |
//! | [`jws`] · [`roster`] · [`token`] | JWS ES256, the self-signed genesis roster, the self-issued mID token | `mid-issuer`, `mid-verify` |
//! | [`cap`] | `component:action@scope` matching | `mata-cap` |
//! | [`adoption`] | the owner-signed **Adoption** grant: who this device answers to | (Janus-defined) |
//! | [`nonce`] | a bounded single-use nonce window | |
//! | [`manifest`] | signing the `rusty_esp_core` capability manifest | |
//!
//! Every canonical byte form that the `mid` repository defines is reproduced
//! here exactly and gated by tests against the real `mid` crates on the host
//! (`tests/oracle.rs`). Formats this crate *defines* (adoption, manifest
//! signature) use the same discipline: a domain separator, length prefixes,
//! big-endian integers, SHA-256, low-s ECDSA.
//!
//! Feature ladder: `std` ⊃ `alloc` ⊃ core-only. The core-only rung is what a
//! `no_std` firmware without a heap uses: keys, signatures, the borrowed kms
//! canonical form, adoption, the nonce window, manifest signing. `alloc` adds
//! the JSON envelopes, JWS and the self-issued token.
//!
//! What is deliberately not here: any driver, NVS encryption (the `-esp`
//! backend's guarantee to state), a roster-chain verifier (the upstream `mid`
//! no_std refactor's job), ed25519 (the family has none).

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod adoption;
pub mod cap;
pub mod did;
pub mod key;
pub mod kms;
pub mod manifest;
pub mod nonce;
pub mod signer;

#[cfg(feature = "alloc")]
pub mod jws;
#[cfg(feature = "alloc")]
pub mod roster;
#[cfg(feature = "alloc")]
pub mod token;

pub use adoption::{Adoption, AdoptionFields, OwnerPin};
pub use did::Did;
pub use key::{DeviceId, DeviceKey};
pub use nonce::NonceWindow;
pub use rusty_esp_core as esp_core;
pub use signer::{DeviceSigner, verify_prehash};

/// The names a firmware or a backend wants in scope.
pub mod prelude {
    pub use crate::adoption::{Adoption, AdoptionFields, OwnerPin};
    pub use crate::did::Did;
    pub use crate::key::{DeviceId, DeviceKey};
    pub use crate::nonce::NonceWindow;
    pub use crate::signer::DeviceSigner;
    pub use rusty_esp_core::prelude::*;
}

/// Crate version, for capability manifests and logs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The verification-method type string mID uses for every P-256 key.
pub const VM_TYPE_ECDSA_P256: &str = "EcdsaSecp256r1VerificationKey2019";

/// SHA-256 of `data`, the prehash every signature in this crate is over.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}
