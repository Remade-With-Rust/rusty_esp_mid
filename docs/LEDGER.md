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
