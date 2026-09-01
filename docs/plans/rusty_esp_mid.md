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

Written 2026-09-01. Status: **scaffold.**

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

### `rusty_esp_mid-core` (`no_std`, `forbid(unsafe)`)

```rust
pub struct Did([u8; 33]);                       // compressed P-256 point; Display = did:mata:<base58btc>
pub struct DeviceKey { /* p256 SigningKey; zeroize on drop */ }
impl DeviceKey { fn generate(rng: &mut impl Rng) -> Result<Self>; fn did(&self) -> Did; fn to_kv / from_kv(kv: &impl Kv) }

/// Byte-for-byte the trait `mid`'s kms-client defines, so the upstream extraction is a rename.
pub trait DeviceSigner { fn device_id(&self) -> &str; fn sign_prehash(&self, prehash: &[u8; 32]) -> [u8; 64]; }

pub struct Assertion;          // nonce envelope → canonical bytes → SHA-256 → sign; emits the gateway's `Resource-Assertion` JSON with a hand-written writer (no serde)
pub struct SignedManifest<'a> { pub bytes: &'a [u8], pub sig: [u8; 64] }
pub struct Adoption<'a> { /* fields above; encode/decode without alloc; verify(owner_pin) */ }
pub struct OwnerPin { pub genesis_pubkey: [u8; 33], pub roster_version: u32 }   // Kv "mid.owner"
pub struct NonceWindow<const N: usize>;   // single-use nonces, bounded, replay-safe
pub mod cap { pub fn satisfies(grant: &str, request: &str) -> bool }   // mata-cap semantics, wire-identical, no_std
pub mod ecdh { pub fn session_key(my: &DeviceKey, their: &[u8; 33], context: &[u8]) -> [u8; 32] }   // for rusty_esp_signal
```

Rules: `p256` with `default-features = false, features = ["ecdsa"]`;
signatures are canonical low-s and verified with a low-s reject (the house
audit's most common finding); every secret is zeroized on every path; `Debug`
is redacted; `serde_json` is not a dependency — the two JSON shapes the
gateway expects are written by hand and tested byte-for-byte against `mid`.

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
sign-in JWT embeds the whole roster chain (cap 64 devices) and its size is
**not stated anywhere** in `mid`; milestone M1 measures it and the number
goes in the ledger before any radio link is asked to carry one.

## 5. Milestones and kill tests

| # | Deliverable | Kill test |
|---|---|---|
| **M0** | core: key, DID, signer, assertion, adoption, nonce window, `cap::satisfies`, host tests | a device-issued assertion **verifies with `kms-verifier` / `mid-verify` on the host** (the oracle); `cap::satisfies` matches `mata-cap` on a 200-case table; riscv32 green; JWT size for rosters of 1, 8, 64 recorded |
| **M1** (J3) | Track A on XIAO S3 Sense: key in encrypted NVS, DID on serial, signed manifest served over the sidecar RPC | the home computer's verifier accepts the assertion; the DID is stable across reflash; an NVS dump of a plaintext partition is refused by the backend |
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
