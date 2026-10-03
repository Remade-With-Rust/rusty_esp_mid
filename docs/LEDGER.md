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

## M2 status: identity and adoption proven on silicon; encrypted-at-rest gated on an eFuse burn (2026-09-18)

What is proven on the XIAO ESP32-S3 (via the C2 cell and Run 5, this session):
- the device **mints its own** `did:mata:29qcqKb5kMT529GSNgfcUU2gSf4bpd7EWUDEj2Mq7cb9J`
  from a key created on first boot and **stable across reboots and reflashes**
  (the `identity` NVS partition survives a firmware reflash by design);
- it **signs its capability manifest on-chip** (the sidecar serves the manifest
  and its signature; a home computer verifies it);
- **adoption on silicon**: the owner pins the device with a signed grant, a
  stranger with the same record is refused, an older roster version is refused,
  and the device reports `pair_state=paired` in its own sidecar status.

On the host: `rusty_esp_mid-core` 28 + `-esp` 3 + integration 8 = **39 tests
pass** — the roster chain, token, capability and DeviceSigner logic.

**The one gap, and it is honestly gated.** `Protection::Encrypted` is returned
only when the firmware was built with **both** `CONFIG_NVS_ENCRYPTION` and
`CONFIG_SECURE_FLASH_ENC_ENABLED`; without them `protection()` is `Plaintext`
and `EspNvsKv::open` **refuses** the identity partition unless the
`allow-insecure-dev` feature opts in. The current firmware is Plaintext (flash
encryption is off), and the crate says so rather than pretending. Proving
**encrypted at rest** requires turning flash encryption on, which burns eFuses
— it needs a **sacrificial board**, tracked in `docs/plans/ap-remaking.md`. The
mechanism (the cfg gates, the refusal) is correct and host-checkable today; the
eFuse runtime truth is the only thing a board in hand cannot show without
committing that board permanently.

## X0 of the killing-C plan: the C census — 2026-09-30

`python tools/c-census.py build && python tools/c-census.py report --ledger` from the umbrella, so sibling crates are the checkouts beside this one: each firmware is linked `--release` with a linker map and `--emit-relocs`, and the two are read together. Every input section the linker kept is charged to the archive the map names for it, one owner per address; every FUNC and OBJECT symbol in the ELF to the archive whose section holds its address; and a mask-ROM routine counts when a kept relocation names it (a linker script defines every ROM symbol whether or not anything calls it). `image B` is code + data as flashed; bss is RAM only. `tools/c-census.py verify` is the gate: the bytes charged equal the bytes the ELF loads, and every symbol charged to a C archive is one `llvm-nm` finds defined in that archive; on an ESP-IDF build the image bytes of every archive also equal what Espressif's own `esp_idf_size` reports from the same map. Two limits: a string table the linker merged is shared by everything that contributed to it, so it is charged where the map puts it (GNU ld) or to the linker row (lld, which names no contributor); and with LTO the Rust side is one object, so its crates are not told apart. Where a firmware reads its network at compile time the build is given placeholders for all of it (`census` / `census-pass`, stream destinations in 192.0.2.0/24): a firmware given no destination compiles its networking out, and the census would measure an image nobody ships.

**What it says.** No C archive is linked. The 6 bytes are `crti.o`, the two
3-byte `.init`/`.fini` stubs the gcc driver adds to every bare-metal Xtensa
link. The 13 mask-ROM routines are all called from Rust — memory
copies, 64-bit division, the cache and clock setup `esp-hal` does at boot — so
an image that links no C still runs ROM code it did not bring.

### `xiao-s3-keys` — S3, Track B, `main@e153b46`

| origin | objects | symbols | code B | data B | bss B |
|---|---:|---:|---:|---:|---:|
| Rust | 2 | 372 | 160,427 | 13,296 | 65,630 |
| toolchain C runtime (libc, libgcc) | 1 | 2 | 6 | 0 | 0 |
| linker (merged constants, padding, reservations) | 1 | 0 | 946 | 44 | 273,610 |

**C in this image: 2 symbols, 6 B of 174,719 B (0.0%). The blob floor is 0 symbols in 0 archives.** The 2nd-stage bootloader that starts it is espflash 4.6.0's bundled `esp32s3-bootloader.bin`: 21,072 B of C outside this image.

Mask-ROM routines called: 13 — 0 from C, 13 from Rust: `Cache_Resume_DCache`, `Cache_Suspend_DCache`, `__udivdi3`, `__umoddi3`, `esp_rom_regi2c_read`, `ets_delay_us`, `ets_update_cpu_frequency`, `memcpy`, `memset`, `rom_config_data_cache_mode`, `rom_config_instruction_cache_mode`, `rom_i2c_writeReg`, `rtc_get_reset_reason`.

| C archive | origin | symbols | image B | bss B |
|---|---|---:|---:|---:|
| `crti.o` | toolchain | 2 | 6 | 0 |

## X4 of the killing-C plan: identity on Track B — the DID a Track A firmware minted, read by Rust with no ESP-IDF under it (2026-09-30)

### The NVS format, in the seam crate

`rusty_esp_core::nvs`: Espressif's NVS partition format in pure Rust, on
the core-only rung (no `alloc`; it compiles for `riscv32imac` with
`--no-default-features`). A reader for every value type — primitives,
strings, blobs assembled from their chunks, the old single-page blob —
from every page in sequence order, with the page and entry CRCs and the
data CRCs checked; a writer for blobs, creating namespaces as it needs
them, erasing in place, keeping one page in reserve as NVS requires, and
with no garbage collector (a page is never reclaimed; when the rest are
full `put` says `BufferTooSmall`, and the module says why that is the
right shape for an identity partition and the wrong one for a diary).
Under it the `Flash` trait: aligned words in, aligned words out, page
erase. Over it `NvsKv`: one namespace as the `Kv` seam — `get` any type,
`put` a blob (what ESP-IDF's `nvs_set_blob` leaves in flash, so the
tracks read each other), `remove`.

Host, 9 tests, against images `espino-nvs` wrote — and `espino-nvs` is
byte-identical to Espressif's `nvs_partition_gen.py`, which is what makes
them an oracle: a provisioning image read back key for key (`name`,
`wifi.ssid`, `wifi.psk`, `maker`, `blink_ms`, `fps`); the identity blob;
a 5,000-byte blob spanning two pages beside two namespaces and three
primitives. **The writer, given a blank 12 KB partition and the identity
blob, produces `espino-nvs`'s image byte for byte.** Replace, remove,
reopen, a blob larger than a page, the reserved page refusing the fourth
blob with the first three still readable, a flipped bit read as
`Corrupt` and not as a wrong key. Clippy `-D warnings`, fmt, the crate's
37 + 3 tests, both bare-metal checks.

### The Track B backends

`rusty_esp_mid-esp::hal` (feature `esp-hal`, and no `alloc` with it, so
the core-only rung underneath stays measurable): `PartitionFlash`, one
partition of the chip's flash through `esp-storage`'s `read_nor` /
`write_nor` / `erase` (four-byte words, 4 KB sectors, the ROM's SPI
routines with the cache held off), bounds-checked; `find_partition`, the
table at `0x8000` by label; `EspHalRng`, the TRNG behind `Rng`. Nothing
identity-specific, as the wrap crate's rule says.

### On the board

`firmware/xiao-s3-keys` gained the identity pass (feature `identity`,
on by default) ahead of its sign/verify bench: the partition table, the
`identity` partition at `0x7fd000` (12 KB), `NvsKv` on the `janus`
namespace, `DeviceKey::load` — and the key is minted and stored only on
a board that has none. The writer's proof below is the kill test's build
(`--features nvs-proof`): a firmware that writes the owner's partition on
every boot is not one to ship, so the default build reads and stops. This
board has an identity, and it printed:

> `KEY identity=loaded did=did:mata:29qcqKb5kMT529GSNgfcUU2gSf4bpd7EWUDEj2Mq7cb9J us=78145`

**The DID the Track A cell firmware minted through ESP-IDF's NVS on
2026-09-18 and has held since (M2), read back by the Rust reader with no
ESP-IDF in the image** — on three boots, with a full-image reflash between
the second and the third (each of the three full-image flashes of the afternoon timed out once and went through on the retry; the merged image ends at
`0x7fd000`, which is why the partition survives every reflash). The 78 ms
is the P-256 public key derived from the stored secret, not the flash: the
mint on the same boot costs 76.9. Before any of it, Espressif's
`nvs_tool.py` on a dump of the partition, values withheld: namespace
`janus`, two pages in use, CRC OK.

The writer, proved on the owner's `nvs` partition (blank on this board;
restored after): `put` 32 bytes 1.56 ms, `get` 0.66 ms (0.17 ms on the
next boot), a 100-byte blob put, read, removed; boot 2 finds boot 1's
blob. Then Espressif's tool on the dump: integrity OK, namespace `x4` at
index 1, `blob` written (`blob_data`, span 2, chunk 0; `blob_index`,
count 1, start 0), `big` written and erased — data and index both marked
`Erased`. **Espressif's own parser reads what the Rust writer wrote,
entry for entry.**

The bench that follows it, beside M1's baseline (240 MHz, the same
binary shape, three boots):

| operation | M1 (2026-09-06) | X4, boot 1 / 2 / 3 |
|---|---:|---:|
| generate | 76,976 us | 76,902 / 76,901 / 76,903 |
| sign, min / median | 94,936 / 94,943 us | 94,867 / 94,879 · 95,038 / 95,050 · 94,886 / 94,898 |
| verify, min / median | 151,455 / 151,669 us | 151,482 / 151,797 · 151,523 / 151,845 · 151,582 / 151,840 |
| `verify_ok` | 100/100 | 100/100 ×3 |
| heap used | — | 0 (the identity pass allocates nothing) |

Inside M1's 0.17 % noise floor on every row. Census of the default
build (`tools/c-census.py`, `verify` closes): **205,731 B image, 6 B of C
(`crti.o`), no archive** — 31.0 KB more image than the bench alone (the
kill test's `nvs-proof` build is 10 KB more again), and 19 ROM routines
called where it was 13: `esp-storage` reaches the flash through the mask
ROM's SPI routines, which is what "ROM only" means for a partition on
Track B.

### Found on the way

- A compressed full-image flash that times out (`FlashDeflData`, 27 s —
  four of seven `espino flash` tries between 14:16 and 14:31 on this
  bench, none of the three in the final run; the app-only `write-bin`
  never) has already erased the `nvs` region: a boot after one found no
  blob from the boot before. The script retries.
- Every `espflash` operation ends in a reset into the firmware, and the
  proof build's first act is to write `nvs` again — which is why the proof
  is a feature and not the default. The final run flashes the default
  build, boots it once (the DID, nothing written), erases the partition
  and reads it back: **restored byte for byte**.
- What this is not: encrypted at rest — unchanged from M2, and
  `esp_hal::efuse::flash_encryption()` is the eFuse's truth a Track B
  firmware can read; a garbage collector; a replace that keeps the old
  value until the new one is indexed (the module documents the window,
  which a once-written key never opens).

## Round 2: the boot's two scalar multiplications, cached (2026-10-01)

`DeviceKey` holds the secret scalar and the public key apart instead of a
`p256::ecdsa::SigningKey`, which derives the public key when it is built.
Signing is the RFC 6979 call `SigningKey` makes; host tests pin the DID and
the signatures to `SigningKey`'s for 24 keys x 8 prehashes.

- `load_cached` / `load_or_generate_cached` take the public key from
  `mid.devpub` beside the secret when its HMAC under the secret holds;
  otherwise they derive it and write the entry (best effort).
- `sign_prehash_cached` and `manifest::sign_manifest_cached` remember a
  signature under a name: deterministic ECDSA makes it the signature
  signing would produce, byte for byte.

| XIAO at 80 MHz (a test key, a RAM store) | ms |
|---|---:|
| `load` (derives the public key) | 222.7 |
| `load_cached` | **3.5** |
| `sign_prehash` | 264.8 |
| `sign_prehash_cached`, an unchanged prehash | **0.52** |

At the cells' 240 MHz that is about 160 ms a boot. espino's camera page
uses both. The `tests/oracle.rs` failure (`InMemoryDeviceSigner` has no
`sign_prehash`) predates this: the lock file carries two `mid-signer`
packages. dsp's ledger, "Round 2", has the method, every run and the refuted shapes.

## Round 3: p256 vendored, its arithmetic rewritten for a 32-bit core (2026-10-01)

`vendor/p256` (0.13.2) and `vendor/primeorder` (0.13.6) are RustCrypto's
crates with the changes below, each marked "Janus vendored (round 3)" where
it is made. A consumer takes them with `[patch.crates-io]` (the probe, and
espino's generated projects when the checkout has them). The representation,
the API and every value are upstream's: a fully reduced field element and an
inverse are unique, and every change is held to the upstream code it
replaces (kept in-tree as a test `reference` or a doc-hidden function).

| change | file | measured on the XIAO, 80 MHz | before | after |
|---|---|---|---:|---:|
| the base field on 32-bit limbs: a CIOS multiply using P-256's shape (`-p^-1 mod 2^32` is 1; the modulus words are all-ones, zero or one, so the reduction has no multiply), an SOS square, 32-bit carry chains. Upstream's 32-bit file was its 64-bit code emulating 128-bit products (`fe_mul` 2,864 instructions) | `field/field32.rs` | `fe_mul` | 38.1 us | 29.0 |
| the scalar field's Barrett reduction with b = 2^32 | `scalar/scalar32.rs` | a scalar multiply (same build, against p256 0.13.2's own copied into the probe) | 77.9 us | 58.0 |
| a fixed-base comb for the generator: signed 5-bit digits, 52 rows of 16 multiples (`gen_gtable.py`, exact integers), constant-time lookups, mixed additions, no doublings; `mul` takes it when the point is the generator constant, so `PublicKey::from_secret_scalar` gains too (primeorder's `PrimeCurveParams::GENERATOR_TABLE`, default `None`) | `generator_table.rs`, primeorder `projective.rs` | key derivation / sign | 160.1 / 189.9 ms | 38.6 / 68.1 (the 4-bit comb); signed 5-bit, later: 23.5 / 29.5 -> **19.4 / 25.4** |
| the field multiply in Xtensa asm, every carry by `saltu` (bytes: LLVM's assembler does not know it), `#[inline(never)]`; picked at run time by `const_eval_select`, so constants and every other target keep the Rust | `field/field32.rs` | `fe_mul` / `fe_square` | 29.0 / 29.3 us | 19.4 / 19.5 |
| constant-time safegcd inversion (libsecp256k1's `modinv32`, MIT, ported as a `const fn`) for both fields; Fermat kept as `invert_fermat` | `safegcd.rs` | field / scalar inverse | 5.07 / 24.47 ms | 0.71 / 0.70 |

All together, from upstream p256 to this crate, on the probe: the link's
handshake (both sides) **1,404 -> 526 ms**; a key derived 221.2 ->
19.4 ms; an ECDSA signature 260.1 -> 25.4 ms. At the
cells' 240 MHz, about a third of each.

**Held to upstream.** Host: proptests of every field and scalar operation
against the upstream code kept as `reference` (i686, x86_64); the comb
against the generic multiply (`tests/generator_table.rs`, every multiple in
four rows, edges, a proptest); safegcd against Fermat (2,000 per field in
the unit tests; 200,000 per field on both word sizes in
`tests/safegcd_bulk.rs`, `--ignored`). Chip: the asm against the Rust on
10,000 random pairs; the handshake's transcript, the key and the signature
checksums unchanged in every build. The two `tests/pkcs8.rs` failures on
Windows are upstream's: the PEM encoder writes CRLF there.

**The seven-times-slower build.** The asm multiply inlined into every caller
(a thousand instructions with thirteen registers pinned, thirteen of them in
a point doubling) overflowed the instruction cache: the handshake took 5.3 s
instead of 0.56. `#[inline(never)]` is why it is not.

**Refuted**: a product-scanning (FIPS) multiply and a flattened CIOS (34.5
and 34.9 us against the rolled CIOS's 29.0); crypto-bigint's constant-time
binary GCD for the base field (5.65 ms against Fermat's 5.07 once Fermat
rode the asm multiply -- it did win 4.3x on the scalar, before safegcd);
the field add and subtract in asm (`saltu` again: the add 4.17 -> 3.91 us,
the subtract 2.98 -> 3.11, the handshake 0.7 % -- an add's cost is its
call and its arrays, not its carries).

**On the board's flash**: the generator table is 53 (52 x 16 x 64 bytes) KB of rodata.

## Round 3 addendum: the asm multiply only where `saltu` exists (2026-10-02)

Found while reading enc-ble (C6 is an ESP32): the asm multiply was gated on
`target_arch = "xtensa"`, which takes in the ESP32's LX6 core. LX6 has no
`saltu`: the ESP32 toolchain decodes the same bytes as `lsi`, a float load
(the S2's and S3's decode them as `saltu`). An ESP32 cell built with the
vendored p256 would have computed garbage. `vendor/p256/build.rs` now sets
`janus_saltu` for `xtensa-esp32s2*` and `xtensa-esp32s3*` only, and the asm
and its feature gates hang on that. Checked: the S3 probe still links
`fe_mul_xtensa`; an `xtensa-esp32-none-elf` build of the crate has no such
symbol; the host tests pass. No ESP32 image was built with the old gate (the
only cell regenerated in round 3 is C14, an S3).

## enc-ble M3: the setup session's identity pieces (2026-10-02)

`rusty_esp_mid_core::setup`, what the setup session (the umbrella's
`docs/setup-protocol.md`; `rusty_esp_signal-core::setup`) asks of identity:

| item | what |
|---|---|
| `REPLY_DOMAIN`, `reply_prehash` | `SHA-256("janus-setup-v1/reply\n" || u16be(len(context)) || context || shareP || shareV || confirmV)` |
| `sign_reply` | the device's signature over it through `DeviceSigner` (the device key never leaves its signer) |
| `verify_reply` | the browser's check against the `did:mata` it was shown, through `verify_prehash`: **low-s only** |
| `KV_SETUP_VERIFIER`, `load_verifier`, `store_verifier` | the 118-byte verifier in the owner's settings namespace; another length is `Corrupt` |
| `KV_SETUP_FAILURES`, `load_failures`, `store_failures` | the consecutive failure count; another length is `Corrupt` (the session reads that as locked) |

**Held to.** `setup::tests::golden_reply`: the Reply of
`rusty_esp_signal`'s golden session (its independent Python oracle, with its
own RFC 6979 ECDSA; the lines copied into `tests/fixtures/setup-reply-v1.txt`)
-- the prehash and this crate's `DeviceKey` signature byte for byte; another
session's prehash, another key and the signature's high-s twin all refused.
35 library tests on i686 and x86_64; `no_std` builds for wasm32, the S3 and
the ESP32.

**Found on the way.** The session's first `verify_reply` (in signal) called
p256 directly and would have taken a high-s signature; this crate refuses
them. The session now verifies here.

`tests/oracle.rs` still does not compile (`InMemoryDeviceSigner` has no
`sign_prehash`: the lock file carries two `mid-signer` packages); that
predates this, as round 2's entry says.

**Not released yet:** the crate on crates.io is 0.1.0; this, with round 2's
and round 3's changes, is unpublished and uncommitted, waiting for the
owner's go.

**Released 2026-10-02** (an addendum to the entry above): with the owner's
go, four commits on `main` -- `6734eb7` (X0/X4 and round 2), `bdab711`
(round 3's vendored p256 and primeorder), `2fb8c45` (enc-ble M3), `139dcb3`
(0.1.1) -- pushed, and `rusty_esp_mid-core` 0.1.1 published to crates.io from
a fresh clone of `main` (no sibling patches; the package verified against
crates.io's own dependencies). `rusty_esp_mid-esp` and the `rusty_esp_mid`
facade are 0.1.1 in the repository but **not published**: the esp-hal
backend (X4) uses `rusty_esp_core::nvs`, and crates.io's `rusty_esp_core`
0.1.1 has no `nvs`; they follow a `rusty_esp_core` release that has it.

**enc-ble M5 (2026-10-02): `EspNvsKv` reads strings too.** Track A's `Kv`
read only blobs, so a key the portal's image writes as an NVS string
(`espino_nvs::janus`: `name`, `wifi.ssid`, `wifi.psk`, `maker`) read as
absent and the setup session's `boot` never found the flashed network.
`get` now falls back to the string, returned without its NUL (what Track B's
`rusty_esp_core::nvs::NvsKv` already did; the copy is wiped after), and
`put` removes a string under the same key before writing its blob (NVS keys
are typed). Built inside `xiao-s3-sense-idf-ble-provision`; not on a board
yet. Uncommitted.

**enc-ble M6 (2026-10-02): `hal::shared`.** `SharedPartition`,
`open_shared` and `Store`: several partitions open at once on one
`FlashStorage` (each operation borrows it through a `RefCell`), the owner's
settings and the identity as the setup session holds them. Moved here from
two signal firmwares' copies; C13 uses it on the XIAO. Uncommitted.
