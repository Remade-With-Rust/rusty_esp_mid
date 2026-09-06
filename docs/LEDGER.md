# rusty_esp_mid — ledger

Every number this package quotes lives here with the run that produced it.
No number in a README or plan may be newer than its row.

## Sizes

| Date | Quantity | Value | Method |
|---|---|---|---|
| 2026-09-01 | mID token, JWS compact, no claims, **1 device** (a Janus device's self-issued token) | **1 511 bytes** | `cargo test -p rusty_esp_mid-core --test oracle token_size_ledger -- --nocapture`; token built by this crate, verified by `mid-verify` before measuring |
| 2026-09-01 | mID token, JWS compact, no claims, owner with **8 devices** (genesis + one chain entry) | **4 562 bytes** | same test; built with `mid-issuer` on the host, verified by `mid-verify` |
| 2026-09-01 | mID token, JWS compact, no claims, owner with **64 devices** (the roster cap) | **23 472 bytes** | same |
| 2026-09-01 | `Adoption` envelope, 2 capabilities, relay URL + host set | 64-byte signature + canonical bytes ≈ **300 bytes** | `adoption::tests::round_trip_and_accept` (fields of that test) |
| 2026-09-01 | `OwnerPin` | **37 bytes** | `OwnerPin::LEN` |

What the sizes decide: an owner token is fine over Wi-Fi and QUIC and is
never sent over ESP-NOW (250-byte MTU) or LoRa. Adoption and the
per-frame MAC of `rusty_esp_signal` are what cross constrained radios; the
token stays on the mesh side. This is the design the plan chose before the
measurement; the measurement confirms it by a factor of six at one device and
ninety at the roster cap.

## Correctness gates (host, 2026-09-01)

| Gate | Result |
|---|---|
| `Did` string and multibase equal `mid-verify::did_from_pubkey` / `multibase_from_pubkey`; `mid-verify::pubkey_from_did` recovers the key | pass |
| `DeviceKey::sign_prehash` bytes equal `kms-client::InMemoryDeviceSigner` for the same key (RFC 6979 determinism) | pass, 3 messages |
| Genesis roster JSON equals `mid-issuer::bootstrap::sign_genesis_roster` field for field, signature included | pass |
| Device-signed `SignedAssertion` verifies in `kms-verifier::Verifier::verify`; replay refused; envelope JSON byte-identical to `kms-types` | pass |
| Self-issued token verifies in `mid-verify::verify_mid_response`; wrong audience and wrong nonce refused; `check_rollback(None)` ok | pass |
| `cap::grant_satisfies` agrees with `mata-cap::Capability::satisfies` | pass, 144/144 cases |
| Unit tests (adoption TOFU, rollback, tamper, expiry; nonce window; manifest + maker signatures; key store/load; ECDH symmetry; low-s rejection) | 28 pass |
| `riscv32imac-unknown-none-elf`, `--no-default-features` (no alloc) and `--features alloc` | compile |

## Not yet measured

- Sign and verify cycle counts per chip (needs hardware; M1).
- Binary size contribution of the `alloc` rung on an ESP32-S3 (needs the
  firmware project; M1).

## The no-panic gate (host, 2026-09-02)

Every parser that takes bytes from a wire, a store or a bus must return an
error on bad input, never panic — the house rule made a test:
`tests/no_panic.rs` feeds each one random inputs from an LCG (the same corpus
on every machine) and mutations of a valid encoding (bit flips, overwrites,
truncation, extension, insertion, removal), under `catch_unwind` so a failure
names the parser and prints the input.

| covered | result |
|---|---|
| `Adoption::decode` + `verify_signature`, `OwnerPin::decode` (20 000), `Did::parse` / `parse_multibase`, `Cap::parse` (30 000 strings), `kms::json::{NonceEnvelope, SignedAssertion}::from_json` (20 000 mutated JSON documents) | no finding |

## The key store over any NVS partition (2026-09-05)

`EspNvsKv` is generic over the partition (`EspNvsKv<T: NvsPartitionId =
NvsDefault>`): `open` / `open_unchecked` keep their shape on the default
`nvs`, `open_in` / `open_unchecked_in` take any `EspNvsPartition<T>`, and
`open_custom` / `open_custom_unchecked(label, ns)` take a named partition
and initialise it — `IDENTITY_PARTITION` (`"identity"`) is the one the
espino tables give the device key. Why: on 2026-09-05 an ESP32-CAM minted a
new DID at every rewrite of the owner's `nvs`, because the key lived there.

| gate | result |
|---|---|
| host workspace (`cargo check`, fmt) | clean; the `esp-idf` module compiles only inside a firmware |
| the espino-generated C5 firmware, which opens `identity` through this crate | builds; on the board the DID was **identical** across a settings rewrite and a full reflash (`did:mata:fadpNPvVBiWW…`) — the first half of the **M1** row, measured (espino ledger) |

The encryption check is unchanged: `open_custom` refuses a plaintext
partition unless `allow-insecure-dev`, which the development boards run with
and the ledger says so.

## M1, the other half: what a P-256 signature costs an ESP32-S3 (2026-09-06)

The row above proved a DID survives a reflash. This is the price of using
it. `firmware/xiao-s3-keys` generates a key from the chip's own hardware
generator, then signs and verifies a hundred times each, on a Seeed XIAO
ESP32-S3 Sense over Track B (esp-hal 1.2.0, no ESP-IDF). It never touches
the identity partition, so a board carrying a device identity keeps it.

Method line: `board=xiao-esp32s3-sense opt-level=3 lto=fat metric=in-process-us
n=100 report=min/median/max work=100-signs-100-verifies-over-32-prehash-bytes
key=hardware-TRNG`. Minimum and median rather than mean: interrupts add time,
they never remove it, so the floor and the middle say more than the average.

| operation | 80 MHz (`Config::default()`) | 240 MHz (`CpuClock::max()`) |
|---|---:|---:|
| generate (n=1) | 224 130 us | **76 976 us** |
| sign, min | 264 953 us | **94 936 us** |
| sign, median | 264 954 us | 94 943 us |
| sign, max | 264 993 us | 94 993 us |
| verify, min | 442 138 us | **151 455 us** |
| verify, median | 442 410 us | 151 669 us |
| verify, max | 443 273 us | 152 675 us |
| `verify_ok` | 100/100 | 100/100 |

### The cross-checks

**Cycles, not just clocks.** The same work at two clocks should cost the
same cycles, and it nearly does: sign is 21.20 M cycles at 80 MHz and
22.78 M at 240 MHz, verify 35.37 M and 36.35 M. The 7.5 % and 2.8 % excess
at the higher clock is the shape of a memory wait that does not scale with
the core — tripling the clock bought 2.79x, not 3.00x. Two independent
clock domains agreeing to under 8 % on cycle count is the check that these
are real curve operations and not a mis-scaled timer.

**Three separate flash-and-boot cycles.** Sign's minimum read 94 936,
95 022 and 94 865 us across three independent flashes — a spread of
**0.17 %**. That is this measurement's noise floor, and it is far below
every difference the table reports.

### What it means for a device

A signature is **95 ms** and a verification is **151 ms** at full clock,
and verify costs **1.6x** what sign does. So a node that signs one assertion
per reading cannot do it at 10 Hz — 95 ms is nearly the whole budget — and a
mesh where every peer verifies every peer's message is bounded by the
verification, not the signature. Both numbers belong in the telemetry
design before it picks a rate.

## The `alloc` rung's price, in app bytes (2026-09-06)

Same firmware, built twice: `mid-core` at its core-only rung, then with
`alloc`. The difference is the rung.

| build | app bytes | ELF bytes |
|---|---:|---:|
| core-only | 220 464 | 357 432 |
| `alloc` | 229 568 | 372 488 |
| **delta** | **+9 104** | +15 056 |

**The first attempt measured nothing, and the failure mode is worth
keeping.** Enabling the feature produced two **byte-identical** ELFs at
357 432 bytes. The feature was on, and link-time optimisation dropped every
symbol it added because the firmware never called one. A rung you do not
exercise costs zero bytes and proves zero — codec-measurement 10's "prove
the fast path RAN", in its size form. The fix was to make the `alloc` build
do the rung's own work: sign a compact JWS, which is exactly the JSON
shapes, base64 and owned DID string the rung exists for.

With that call in place the rung also reports its runtime cost:

| | value |
|---|---:|
| `build_jws_compact`, n=1 | 95 863 us |
| compact JWS length | 144 bytes |
| owned DID string length | 53 bytes |

95.9 ms against a 94.9 ms signature: **the JSON, base64 and string work is
about 1 ms, roughly 1 % of the JWS**. On this chip a signed assertion costs
what its signature costs, and the rung's convenience is close to free in
time — the price is the 9 104 bytes above.
