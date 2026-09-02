# rusty_esp_mid

[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

MATA mID on the chip. A Janus device is its own `did:mata`: a P-256 key
generated on the device, whose compressed public key *is* the identifier. This
package gives that identity everything it needs to be a first-class MATA node —
signed assertions for the home computer's gateway, a self-issued sign-in token,
a signed capability manifest, and **adoption**: the owner-signed grant that
tells the device who it belongs to and who it may talk to.

It replaces vendor provisioning, cloud claiming and commissioning with the
identity model the MATA home computer already defines: *User ← Home Computer
(anchor) ← Device; every device has its own `did:mata`.*

Part of **Janus**, the Remade-With-Rust programme that rebuilds the Espressif
ESP32 and Arduino application portfolio in memory-safe Rust.

- This package's plan: [docs/plans/rusty_esp_mid.md](docs/plans/rusty_esp_mid.md)
- Numbers: [docs/LEDGER.md](docs/LEDGER.md)
- The family plan: Janus `docs/plans/janus-mission.md` (umbrella repo)

**Claims discipline:** every number in this README is in the ledger with the
run that produced it. Nothing here has run on a chip yet.

## Status

**M0 shipped on the host (2026-09-01); M1/M2 host halves done in J3** — the
Track A NVS key store with its encryption check and the TRNG seam are written
(`rusty_esp_mid-esp`), and adoption over the mesh is proven on the host in
`rusty_esp_iroh` (owner adopts, stranger denied, rotation backwards refused).

**M0 detail.** The core is complete for what a
device does with its identity, and it is gated against the real `mid`
crates: bytes this crate emits are accepted by `kms-verifier` and
`mid-verify`, and where the format is deterministic they are identical to
`mid`'s own output (signer, genesis roster, envelope JSON). 28 unit tests and
7 oracle tests pass; the core compiles for riscv32 bare metal with and
without `alloc`.

Not yet: the `-esp` backends (encrypted NVS, TRNG, eFuse-wrapped key,
secure element) — that is M1 and needs a board.

## What is in the core

| Module | What | Interoperates with |
|---|---|---|
| `did` | `Did`: `did:mata:<base58btc(33-byte SEC1)>`, encode and parse without `alloc` | `mid-verify` |
| `key` | `DeviceKey`: generate from the TRNG seam, persist through the `Kv` seam, ECDH for `rusty_esp_signal` | |
| `signer` | `DeviceSigner`: byte-for-byte the trait `mid`'s `kms-client` defines; `verify_prehash` with the low-s reject | `kms-client` |
| `kms` | the `NonceEnvelope` canonical form over borrowed fields and the `SignedAssertion` a gateway verifies | `kms-types`, `kms-verifier` |
| `jws`, `roster`, `token` | JWS ES256, the self-signed genesis roster, the self-issued mID token | `mid-issuer`, `mid-verify` |
| `cap` | `component:action@scope` matching | `mata-cap` |
| `adoption` | the **Adoption** grant: owner key pinned on first use (TOFU), rehome by the pinned owner, revocation by roster version; borrowed decode, no `alloc` | Janus-defined |
| `nonce` | a fixed-capacity single-use nonce window | |
| `manifest` | signing the `rusty_esp_core` capability manifest; the maker attestation | `rusty_esp_core` |

```rust
use rusty_esp_mid::prelude::*;

// boot: the DID is stable for as long as the Kv partition survives
let key = DeviceKey::load_or_generate(&mut nvs, &mut trng, "cam-1")?;
let did = key.did();                       // did:mata:…

// a gateway challenge arrives as JSON; sign it
let env = rusty_esp_mid::kms::json::NonceEnvelope::from_json(&challenge)?;
let assertion = env.sign(&key)?.to_json();

// an owner adopts the device; pin them
let adoption = Adoption::decode(&bytes)?;
let pin = adoption.accept(&did.to_did_string(), stored_pin.as_ref(), wall_clock)?;
```

## Sizes that shaped the design

| Token | Bytes |
|---|---|
| a device's self-issued mID token (1 verification method) | 1 511 |
| an owner's token, 8 devices | 4 562 |
| an owner's token, 64 devices (the roster cap) | 23 472 |
| an `Adoption` with two capabilities | ≈ 300 |

An owner token never crosses ESP-NOW or LoRa. Adoption does.

## Layout

```text
crates/rusty_esp_mid          facade
crates/rusty_esp_mid-core     no_std + alloc; forbid(unsafe); the identity core
crates/rusty_esp_mid-esp      the WRAP crate: `esp-hal` | `esp-idf` backends (M1)
docs/plans/rusty_esp_mid.md   the plan · docs/LEDGER.md the numbers
```

## Build

```sh
cargo test --workspace                                   # host, incl. the oracle tests against mid/kms
cargo check -p rusty_esp_mid-core --no-default-features --target riscv32imac-unknown-none-elf
cargo check -p rusty_esp_mid-core --no-default-features --features alloc --target riscv32imac-unknown-none-elf
```

## License

MIT OR Apache-2.0, at your option.
