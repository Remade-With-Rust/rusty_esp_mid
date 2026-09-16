# rusty_esp_mid

[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/remade-with-rust) [![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network) [![crates.io](https://img.shields.io/crates/v/rusty_esp_mid.svg)](https://crates.io/crates/rusty_esp_mid) [![docs.rs](https://docs.rs/rusty_esp_mid/badge.svg)](https://docs.rs/rusty_esp_mid) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/rusty_esp_mid/blob/main/LICENSE-MIT)

Identity for an ESP32: every device mints its own P-256 `did:mata` into a
partition of its own, signs what it claims, and can be adopted by an owner it
then recognises and a stranger cannot impersonate. Pure Rust, no C, no FFI,
`no_std` by default.

* **The device owns its identity, and nothing can reach it.** The key is
  generated on the part, written to a partition no settings rewrite and no
  re-flash touches, and never leaves. One identity has now survived **six
  whole-image reflashes, a re-provisioning, and three flashes from another
  session**.
* **Adoption that refuses the two attacks that matter.** An adoption record is
  public the moment it is sent, so only the key named inside it may use it; and
  a superseded record must be rejected or rotating an owner's key revokes
  nothing. **Both refusals were measured on a chip**, at the first attempt.
* **Agreement with the wider MATA stack, byte for byte.** Signatures equal the
  reference signer for the same key; a device-signed assertion verifies in the
  reference verifier and a replay is refused; the capability check agrees with
  the reference implementation on **144 of 144 cases**.
* **Low-s enforced, everywhere.** A signature that is malleable is refused
  rather than accepted and normalised.

## What has run on hardware

| what | measured |
|---|---|
| identity across reflashes | one `did:mata` held through **six whole-image reflashes**, a re-provisioning and three foreign flashes |
| a signature | **95 ms** at full clock |
| a verification | **151 ms** — **1.6× a signature**, and 100 of 100 succeeded |
| the convenience layer | **9,104 bytes** of flash, about 1% of the time of a signed assertion |
| adoption on the chip | accepted; a stranger presenting the owner's own record **refused**; an older roster version **refused**; the owner then read private telemetry |

Both timings carry a design consequence no host could have suggested. A node
cannot sign once per reading at ten readings a second, because the signature is
most of that budget. And a mesh where every peer checks every peer's message is
bounded by the **verification**, not the signature, because checking costs more
than signing.

Two checks make those figures trustworthy rather than merely printed. Measured
again at a third of the clock, the cycle counts agree within 8%, which is what
a real computation looks like and a mis-scaled timer does not. Across three
separate flash-and-boot cycles the floor moved by less than a fifth of one
per cent.

**The first attempt measured nothing, and said so loudly:** building with the
convenience layer on and off produced two byte-identical files, because the
layer was enabled and never called, so the linker deleted it. A capability you
do not exercise costs nothing and proves nothing.

Every number, with the run that produced it:
[`docs/LEDGER.md`](https://github.com/Remade-With-Rust/rusty_esp_mid/blob/main/docs/LEDGER.md).

## Using it

```rust
use rusty_esp_mid::prelude::*;

// Minted on the part, into a partition a re-flash does not touch.
let identity = NodeIdentity::load_or_create(&mut kv, &mut rng, "janus")?;
println!("{}", identity.did_string());

// What the owner presents; the device checks the caller IS that owner.
let fields = AdoptionFields { device_did, owner_did, owner_genesis_pubkey, .. };
let n = fields.sign_into(&owner_key, &mut buf)?;
```

## Wire sizes

| what | bytes |
|---|---|
| a device's self-issued token | 1,511 |
| an owner with 8 devices | 4,562 |
| an owner at the 64-device roster cap | 23,472 |
| an adoption envelope, two capabilities | about 300 |
| the owner pin a device stores | 37 |

## Two tracks

| track | what it is | this crate |
|---|---|---|
| **A** | `std` on ESP-IDF — the entropy and key-value backends | `rusty_esp_mid-esp --features esp-idf` |
| **B** | `no_std` on `esp-hal` — the whole protocol | `rusty_esp_mid-core`, default |

## Part of Janus

**Janus** rebuilds the Espressif ESP32 and Arduino application portfolio as
independent, memory-safe Rust packages — so a hardware maker can ship a device
that the [MATA](https://www.mata.network) home computer discovers, catalogs honestly, adopts
under its own identity, and pays for. Ten packages, three layers, and the
dependency direction never reverses.

| layer | packages |
|---|---|
| **0 — the vocabulary** | [`rusty_esp_core`](https://crates.io/crates/rusty_esp_core) · [`rusty_esp_dsp`](https://crates.io/crates/rusty_esp_dsp) |
| **1 — the functions** | [`rusty_esp_image`](https://crates.io/crates/rusty_esp_image) · [`rusty_esp_video`](https://crates.io/crates/rusty_esp_video) · [`rusty_esp_audio`](https://crates.io/crates/rusty_esp_audio) · [`rusty_esp_signal`](https://crates.io/crates/rusty_esp_signal) · [`rusty_esp_mid`](https://crates.io/crates/rusty_esp_mid) · [`rusty_esp_iroh`](https://crates.io/crates/rusty_esp_iroh) |
| **2 — the surfaces** | [`rusty_esp_arduino`](https://crates.io/crates/rusty_esp_arduino) — the sketch facade · `espino` — the maker's CLI (not published) |

Every package is host-verified against an external oracle and keeps a ledger
in which no number appears without the run that produced it. **Five of seven
device profiles have now run their kill tests on real silicon**, three of them
over a Wi-Fi network the board hosts itself.

Also check out the rest of [Remade With Rust](https://github.com/remade-with-rust) — including
[`rusty_alloc`](https://crates.io/crates/rusty_alloc), the pure-Rust rebuild of
mimalloc that these firmwares run on, and
[`rusty_jpeg`](https://crates.io/crates/rusty_jpeg), the JPEG engine behind the
camera path — and our sister project
[remade_ffmpeg_rs](https://github.com/Remade-With-Rust/remade_ffmpeg_rs), a ground-up Rust rebuild of FFmpeg.

## About Mata Network

[Mata Network](https://www.mata.network) builds sovereign, self-hostable infrastructure.
**Remade With Rust** is our open-source home for the permissively-licensed
building blocks that work depends on.

## License

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](https://github.com/Remade-With-Rust/rusty_esp_mid/blob/main/LICENSE-MIT)
and [LICENSE-APACHE](https://github.com/Remade-With-Rust/rusty_esp_mid/blob/main/LICENSE-APACHE).
