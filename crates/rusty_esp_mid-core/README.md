# rusty_esp_mid-core

The pure `no_std` core of [`rusty_esp_mid`](https://crates.io/crates/rusty_esp_mid):
a P-256 `did:mata` device identity, the byte-identical `DeviceSigner`, kms
nonce assertions, JWS ES256, the self-issued mID token, capability matching,
the owner **Adoption** grant, a replay window and manifest signing.
`forbid(unsafe)`. No drivers.

Feature ladder: `std` ⊃ `alloc` ⊃ core-only. The core-only rung (keys,
signatures, the borrowed kms canonical form, adoption, the nonce window,
manifest signing) needs no heap; `alloc` adds the JSON envelopes, JWS and the
self-issued token.

Every canonical byte form from the `mid` repository is reproduced exactly and
gated in `tests/oracle.rs` against the real `mid-verify`, `mid-issuer`,
`kms-verifier` and `mata-cap` crates.

Part of Janus (Remade With Rust). Plan: `docs/plans/rusty_esp_mid.md` in the repo.
