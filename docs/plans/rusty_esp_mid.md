# rusty_esp_mid — mission plan

**One sentence:** MATA mID on the chip — a device `did:mata` whose P-256 key
rests in encrypted NVS or in the Digital-Signature peripheral, signed
assertions for the home computer's gateway, a signed capability manifest, and
**adoption** as a signed grant from the owner — replacing vendor provisioning,
cloud claiming and commissioning with the identity model the home computer
already defines.

Family plan: Janus `docs/plans/janus-mission.md` (§6 settles the identity
model). Layer 1 · connectivity. Depends on `rusty_esp_core` only; `rusty_esp_iroh`
and `rusty_esp_signal` depend on this crate.

Written 2026-09-01. Status: **M0 shipped on the host** (see §5 and `docs/LEDGER.md`); `-esp` backends are M1 and need a board.

---

## 1. Espressif map

| Espressif item | Job | Class | Janus |
|---|---|---|---|
| RainMaker claiming (`esp_rmaker_claim`), AWS IoT fleet provisioning, `esp_secure_cert_mgr` pre-provisioned X.509 | "prove this device is ours to the cloud" | **REPLACE** | a self-certifying `did:mata` + a maker-signed manifest; no CA, no cloud |
| Matter commissioning, DAC/PAI certificates | owner takes control of a device | **REPLACE** | `Adoption`: an owner-signed grant the device verifies and pins |
| `wifi_provisioning` security 1/2 (SRP6a + AES-CTR) | protect credentials in flight | REMAKE with mID | `rusty_esp_signal::ble::provisioning` carries credentials inside an adoption session |
| `esp_local_ctrl` | authenticated local control | REMAKE | `Assertion` verification on every control frame |
| `nvs_flash` + NVS encryption, flash encryption, secure boot v2 | keys at rest, code integrity | **WRAP** and require | `-esp` reports the partition's real guarantee; `Certified` tier requires all three on |
| eFuse key blocks, **Digital Signature peripheral** (`esp_ds`: RSA in hardware, key never readable), HMAC peripheral | hardware-bound keys | WRAP | `DsSigner` where the chip has it; see the P-256 note in §6 |
| ATECC608 (`esp-cryptoauthlib`) | secure element | WRAP | `AteccSigner` — the BYO-tier hardware path |

## 2. The identity model (settled by `mata-master`)

> User ← Home Computer (anchor) ← Device. **Every device has its own `did:mata`.**

- The device generates a **P-256** key once, from the `Rng` seam (a TRNG),
  and derives `did:mata:<base58btc(33-byte compressed pubkey)>` exactly as
  `mid-verify` does. Never ed25519, never secp256k1: the family interoperates
  with `mid` or it is not mID.
- The device is `DeviceClass::Other("janus:<kind>")`, tiered
  `Certified` when its maker manifest verifies, else `Byo`.
- **Adoption** is the Pi-mission bind record, signed:

```text
Adoption {
  device_did, owner_did, owner_genesis_pubkey,
  hub: { endpoint_id, relay: Option<Url>, host: Option<SocketAddr> },   // where to talk, and only there
  caps: [component:action@scope, …],                                     // mata-cap strings, matched locally
  roster_version, issued_at, expires_at,
  sig: ECDSA-P256 low-s by an owner roster key
}
```

  The device verifies the signature against `owner_genesis_pubkey`, **pins
  it on first adoption** (TOFU, the mesh notes' rule), stores the record under
  the `Kv` seam, and thereafter refuses any adoption not signed by the pinned
  owner. Rehome = a new adoption from the pinned owner (or a physical factory
  reset). Revocation = the owner rotates their roster; the device sees a
  `roster_version` it cannot accept and drops to unadopted. No "scan and pick
  a broker" path exists in a field build.

- **Signed manifest:** `rusty_esp_core::Manifest::encode` bytes, signed by
  the device key, plus a maker signature over `{model, firmware hash}` when
  the vendor ships one. The home computer's catalog ingests the first and
  tiers on the second.

## 3. Crate surface

### `rusty_esp_mid-core` (`no_std`, `forbid(unsafe)`) — as built in M0

```rust
pub struct Did { /* [u8; 33] compressed P-256 point */ }        // did:mata:<base58btc>; write/parse without alloc
pub struct DeviceKey { /* p256 SigningKey + DeviceId */ }        // generate(rng), load_or_generate(kv, rng), did(), shared_secret(their)
pub trait DeviceSigner { fn device_id(&self) -> &str; fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64]; }   // byte-for-byte kms-client's
pub fn verify_prehash(pubkey_sec1: &[u8], prehash: &[u8; 32], sig: &[u8; 64]) -> Result<()>;                    // low-s reject

pub mod kms      { NonceEnvelopeRef<'_>::{validate, canonical_bytes, sign}                // no alloc
                   json::{NonceEnvelope, SignedAssertion}::{from_json, to_json, sign} }   // alloc: serde + serde_json, field order = kms-types
pub mod jws      { build_jws_compact(payload_json, signer) -> String }                    // alloc
pub mod roster   { EmbeddedGenesisRoster, genesis_canonical_bytes, sign_genesis_roster }  // alloc; identical to mid-issuer
pub mod token    { MidJwtPayload, ClaimValue, build_self_issued_token(...) -> String }     // alloc; verifies in mid-verify
pub mod cap      { Cap::parse, grant_satisfies, any_satisfies }                          // mata-cap semantics, no alloc
pub mod adoption { AdoptionFields<'_>::{encode, sign_into}, Adoption<'_>::{decode, verify_signature, accept, grants}, OwnerPin }
pub struct NonceWindow<const N: usize>;                                                   // single-use nonces, bounded
pub mod manifest { sign_manifest, verify_manifest, maker_prehash, verify_maker }
```

Rules: `p256 0.13` with `default-features = false, features = ["ecdsa", "ecdh"]`
(the majors `mid` pins, so one P-256 in any graph); signatures are canonical
low-s and every verifier rejects high-s; `Debug` on the key is redacted and
`p256` zeroizes the scalar on drop; the **core-only rung has no JSON and no
heap** (keys, signatures, the borrowed kms canonical form, adoption, nonce
window, manifest signing); the `alloc` rung adds `serde` + `serde_json` in
`no_std` mode for the gateway's JSON envelopes and the token, with struct
field order matching `kms-types` so the JSON is byte-identical. All of it is
gated in `tests/oracle.rs` against the real `mid` crates.

### `rusty_esp_mid-esp`

| Feature | Backend |
|---|---|
| `esp-idf` | `EspNvs` behind the `Kv` seam with an **encrypted-partition check** (refuses to store a key in a plaintext partition unless `allow-insecure-dev` is on); `esp_random` as `Rng`; `DsSigner` over `esp_ds` where it applies; flash-encryption / secure-boot status in the manifest's telemetry |
| `esp-hal` | `esp_hal::rng::Trng`; `esp-storage` + a small NVS-like log behind `Kv`; HMAC/DS drivers as esp-hal exposes them |
| `atecc` | ATECC608 over I²C as `DeviceSigner` |

## 4. Where `mid` stands today, and the split

The `mid` repository is P-256 throughout and its verifier is a pure function,
but: nothing is `no_std`; every `p256` line pins `std`; `thiserror 1.x`;
`serde_json` in `std` mode; and **`mid-verify` drags `reqwest` + tokio
through `mid-issuer → kms-client`** for the two-method `DeviceSigner` trait.

| Work | Where | Who |
|---|---|---|
| Extract `DeviceSigner` into a leaf crate; drop `std` from `p256`; `thiserror 2`; `serde_json` `alloc`; `#![no_std]` on `mid-verify` and a shared wire-types crate | **upstream `mid`** (a 4–6 crate refactor, filed as a `mid` mission) | benefits the sidecar and every RP too |
| The device side (key, DID, signer, assertion, adoption, manifest signature) | **here**, on `p256` directly | ships without waiting |
| Owner-side verification of *device* assertions | `mid-verify` / `kms-verifier` on the host, unchanged | the oracle for this crate's tests |

Compact `Adoption` instead of a full mID JWT on the device is deliberate: a
sign-in JWT embeds the whole roster chain (cap 64 devices) and its size was
not stated anywhere in `mid`. **Measured 2026-09-01 (`docs/LEDGER.md`):
1 511 bytes at one device, 4 562 at eight, 23 472 at the 64-device cap.** An
owner token never crosses ESP-NOW (250-byte MTU) or LoRa; an adoption (≈ 300
bytes) does.

## 5. Milestones and kill tests

| # | Deliverable | Kill test |
|---|---|---|
| **M0** ✅ 2026-09-01 | core: key, DID, signer, assertion, adoption, nonce window, `cap::satisfies`, JWS, genesis roster, self-issued token, manifest signing; 28 unit + 7 oracle tests | **passed:** a device-signed assertion verifies in `kms-verifier` and a self-issued token in `mid-verify`; the signer and the genesis roster are byte-identical to `kms-client` / `mid-issuer`; `cap` agrees with `mata-cap` on 144/144 cases; riscv32 green with and without `alloc`; token sizes recorded in `docs/LEDGER.md` — **1 511 / 4 562 / 23 472 bytes** for 1 / 8 / 64 devices |
| **M1** (J3) ◐ host half 2026-09-01 | Track A on XIAO S3 Sense: key in encrypted NVS, DID on serial, signed manifest served over the sidecar RPC. **Written:** `-esp` `idf::EspNvsKv` (refuses a plaintext partition unless `allow-insecure-dev`; `Protection` reports NVS + flash encryption), `idf::EspRng` (armed only after the radio is up); the mesh firmware in `rusty_esp_iroh` loads the identity from NVS and serves the signed manifest over both `janus/rpc/1` and `mata-oem-sidecar/rpc/1` (host loopback: the manifest verifies under the DID) | the home computer's verifier accepts the assertion; the DID is stable across reflash; an NVS dump of a plaintext partition is refused by the backend — **needs the board** |
| **M2** (J3) ◐ host half 2026-09-01 | adoption over QR ticket with the home computer app; TOFU pin; rehome; revoke by roster rotation. **Done on the host** (in `rusty_esp_iroh`): the `janus1…` QR ticket, `Adopt` over `janus/rpc/1` gated by the caller assertion, the pin stored through `Kv`, a second owner and a backwards roster version refused | the J3 family kill test; a second owner's adoption is refused; a factory reset (strapping-pin hold) clears the pin and nothing else — **needs the board and the app** |
| **M2** (J3) | adoption over QR ticket with the home computer app; TOFU pin; rehome; revoke by roster rotation | the J3 family kill test; a second owner's adoption is refused; a factory reset (strapping-pin hold) clears the pin and nothing else |
| **M3** | `DsSigner` on S3/C6/P4 — key never readable; `Certified` tier | the signature verifies against the DID; the flash image contains no private key; secure boot + flash encryption + NVS encryption all reported on |
| **M4** | ATECC608 path; `use-protection-please` audit of the package | the audit table complete; every verifier has a low-s reject beside it |
| **M5** | `mid` upstream refactor merged; this core becomes a thin layer over `mid-verify`'s `no_std` types | byte-identical assertions before and after the switch |

## 6. A note on the DS peripheral

Espressif's Digital Signature peripheral signs **RSA**, not ECDSA P-256. The
honest mapping for the `Reference`/`Certified` tier is therefore: the P-256
device key is generated on-chip and stored in **encrypted NVS under a
key-encryption key that lives in an eFuse block** (HMAC peripheral, key never
readable), so the DID key never exists in plaintext outside RAM. A true
"key never leaves silicon" P-256 needs a secure element (ATECC608, which is
P-256 native) — that is the BYO-tier hardware path. The plan says which
guarantee each tier actually gives; the manifest reports it.

## 7. Measurement

- Signing and verification cycle counts per chip in `docs/LEDGER.md`.
- Token and adoption sizes in bytes, per roster size.
- A counter of refused adoptions/assertions by reason, exported as telemetry.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Hand-written JSON drifts from `mid`'s canonical bytes | byte-for-byte tests against `mid-issuer` output on the host, in CI, on every push |
| TOFU pin lost (NVS corruption) | the pin is written twice (NVS + a second key) and a mismatch fails closed to unadopted, never to "trust the next owner" |
| A plaintext-NVS dev board ships as a product | the backend refuses secret storage without encryption unless a loudly-named dev feature is on; the manifest says which |
| P-256 on Xtensa is slow | measure (M0 ledger); a signature per session, a MAC per frame (the signal plan) keeps it off the hot path |

## 9. Decision log

| Date | Decision |
|---|---|
| 2026-09-01 | The device has its own `did:mata` (P-256), per `maestro-edge`'s identity model. |
| 2026-09-01 | Adoption is a compact owner-signed grant with a TOFU pin, not a full mID JWT on the chip. |
| 2026-09-01 | `DeviceSigner` is copied byte-for-byte from `mid` so the upstream extraction is a rename. |
| 2026-09-01 | The `mid` `no_std` work is an upstream mission, not a fork. |
| 2026-09-01 | Tier truth: eFuse-wrapped NVS key on plain ESP32 parts; a secure element for "never leaves silicon". |
