//! M1 on real silicon: what a P-256 signature costs an ESP32-S3.
//!
//! The device key, its signature and its verifier have been exercised on a
//! host since the crate was written, and a chip run has only ever proved that
//! a DID is minted and survives a reflash. This says what it costs: a hundred
//! signatures and a hundred verifications, reported as minimum and median
//! rather than a mean, because a mean over a busy chip hides the floor.
//!
//! The key is generated from the chip's own hardware generator, so the number
//! is for a real key rather than a fixture. Nothing is stored: this firmware
//! never touches the identity partition, so a board carrying a device
//! identity keeps it.
//!
//! Lines are prefixed `KEY` so a monitor can parse them without guessing.

#![no_std]
#![no_main]

#[cfg(feature = "alloc-rung")]
extern crate alloc;

use esp_backtrace as _;
use esp_hal::time::Instant;
use esp_println::println;
use rusty_esp_core::hal::Rng;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_mid_core::signer::{verify_prehash, DeviceSigner};

esp_bootloader_esp_idf::esp_app_desc!();

/// Iterations per operation. The row asks for a hundred.
const ITERATIONS: usize = 100;

/// The chip's hardware generator behind the core's entropy seam.
struct ChipRng(esp_hal::rng::Trng);

impl Rng for ChipRng {
    fn fill(&mut self, buf: &mut [u8]) -> rusty_esp_core::error::Result<()> {
        for chunk in buf.chunks_mut(4) {
            let word = self.0.random().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}

/// X4: the identity partition through the Rust NVS module over esp-storage,
/// then the writer proved on the owner's `nvs` partition.
///
/// The identity is read and, on a board with none, minted and stored —
/// what a device does at boot. A board carrying one keeps it: nothing is
/// written to `identity` when a key is there. The writer's proof goes to
/// a namespace of this firmware's own on the `nvs` partition, where an
/// owner's provisioning image is rewritten whole anyway; the strings that
/// image holds are read through the same reader first (names and
/// presence, never a passphrase).
#[cfg(feature = "identity")]
mod identity {
    use esp_hal::time::Instant;
    use esp_println::println;
    use rusty_esp_core::hal::{Kv, Rng};
    use rusty_esp_core::nvs::NvsKv;
    use rusty_esp_mid_core::key::DeviceKey;
    use rusty_esp_mid_esp::hal::{find_partition, PartitionFlash};

    /// The namespace the identity lives in, on every track.
    const NAMESPACE: &str = "janus";
    /// This board, in the key store's terms; the DID depends on the key alone.
    const DEVICE_ID: &str = "xiao-s3";
    /// Where the writer is proved.
    #[cfg(feature = "nvs-proof")]
    const PROOF_NAMESPACE: &str = "x4";

    pub fn run(flash: esp_hal::peripherals::FLASH<'static>, rng: &mut impl Rng) {
        let mut storage = esp_storage::FlashStorage::new(flash);

        // ---- the identity partition ----------------------------------------
        let part = match find_partition(&mut storage, "identity") {
            Ok(Some(p)) => p,
            Ok(None) => {
                println!("KEY identity=no-partition");
                return;
            }
            Err(e) => {
                println!("KEY identity_table_error={e:?}");
                return;
            }
        };
        println!(
            "KEY partition=identity offset=0x{:x} len=0x{:x}",
            part.offset, part.len
        );
        {
            let started = Instant::now();
            let kv = PartitionFlash::new(&mut storage, part.offset, part.len)
                .and_then(|f| NvsKv::open(f, NAMESPACE));
            let mut kv = match kv {
                Ok(kv) => kv,
                Err(e) => {
                    println!("KEY identity_open_error={e:?}");
                    return;
                }
            };
            match DeviceKey::load(&kv, DEVICE_ID) {
                Ok(Some(key)) => println!(
                    "KEY identity=loaded did={} us={}",
                    key.did(),
                    started.elapsed().as_micros()
                ),
                Ok(None) => match DeviceKey::load_or_generate(&mut kv, rng, DEVICE_ID) {
                    Ok(key) => println!(
                        "KEY identity=minted did={} us={}",
                        key.did(),
                        started.elapsed().as_micros()
                    ),
                    Err(e) => println!("KEY identity_mint_error={e:?}"),
                },
                Err(e) => println!("KEY identity_error={e:?}"),
            }
        }

        // ---- the owner's `nvs` partition: what espino provisioned ---------
        let part = match find_partition(&mut storage, "nvs") {
            Ok(Some(p)) => p,
            Ok(None) => {
                println!("KEY nvs=no-partition");
                return;
            }
            Err(e) => {
                println!("KEY nvs_table_error={e:?}");
                return;
            }
        };
        println!(
            "KEY partition=nvs offset=0x{:x} len=0x{:x}",
            part.offset, part.len
        );
        {
            let kv = PartitionFlash::new(&mut storage, part.offset, part.len)
                .and_then(|f| NvsKv::open(f, NAMESPACE));
            let kv = match kv {
                Ok(kv) => kv,
                Err(e) => {
                    println!("KEY nvs_open_error={e:?}");
                    return;
                }
            };
            let mut buf = [0u8; 64];
            match kv.get("name", &mut buf) {
                Ok(Some(n)) => println!(
                    "KEY nvs.janus.name={}",
                    core::str::from_utf8(&buf[..n]).unwrap_or("?")
                ),
                Ok(None) => println!("KEY nvs.janus.name=absent"),
                Err(e) => println!("KEY nvs.janus.name_error={e:?}"),
            }
            for key in ["wifi.ssid", "wifi.psk", "maker"] {
                // presence only: one of these is a passphrase
                match kv.get(key, &mut buf) {
                    Ok(Some(_)) => println!("KEY nvs.janus.{key}=present"),
                    Ok(None) => println!("KEY nvs.janus.{key}=absent"),
                    Err(e) => println!("KEY nvs.janus.{key}_error={e:?}"),
                }
            }
        }

        // ---- the writer's proof: the kill test's build only -------------------
        // A firmware that writes the owner's partition on every boot is the
        // wrong shape to ship; the default build reads and stops here.
        #[cfg(feature = "nvs-proof")]
        writer_proof(&mut storage, part, rng);
    }

    /// Put, get, replace, remove in a namespace of this firmware's own.
    #[cfg(feature = "nvs-proof")]
    fn writer_proof(
        storage: &mut esp_storage::FlashStorage<'_>,
        part: rusty_esp_mid_esp::hal::Partition,
        rng: &mut impl Rng,
    ) {
        let kv = PartitionFlash::new(storage, part.offset, part.len)
            .and_then(|f| NvsKv::open(f, PROOF_NAMESPACE));
        let mut kv = match kv {
            Ok(kv) => kv,
            Err(e) => {
                println!("KEY x4_open_error={e:?}");
                return;
            }
        };
        let mut back = [0u8; 128];
        match kv.get("blob", &mut back) {
            Ok(Some(n)) => println!("KEY x4.blob=present len={n} (left by an earlier boot)"),
            Ok(None) => println!("KEY x4.blob=absent"),
            Err(e) => println!("KEY x4.blob_error={e:?}"),
        }
        let mut secret = [0u8; 32];
        let _ = rng.fill(&mut secret);
        let started = Instant::now();
        let put = kv.put("blob", &secret);
        let put_us = started.elapsed().as_micros();
        let started = Instant::now();
        let got = kv.get("blob", &mut back);
        let get_us = started.elapsed().as_micros();
        println!(
            "KEY x4 put32={put:?} put_us={put_us} get={got:?} get_us={get_us} same={}",
            back[..32] == secret
        );
        let big = [0xA5u8; 100];
        let put = kv.put("big", &big);
        let got = kv.get("big", &mut back);
        println!(
            "KEY x4 put100={put:?} get={got:?} same={}",
            back[..100] == big
        );
        let removed = kv.remove("big");
        let after = kv.get("big", &mut back);
        println!("KEY x4 remove={removed:?} after={after:?}");
    }
}

/// Minimum and median of a sample, in microseconds. Median rather than mean:
/// a chip's interrupts add time, they never remove it, so the middle and the
/// floor say more than the average.
fn min_and_median(samples: &mut [u64]) -> (u64, u64) {
    samples.sort_unstable();
    (samples[0], samples[samples.len() / 2])
}

fn report(name: &str, samples: &mut [u64], mhz: u64) {
    let (min, median) = min_and_median(samples);
    let worst = samples[samples.len() - 1];
    println!(
        "KEY op={name} n={} min_us={min} median_us={median} max_us={worst} min_cycles={} median_cycles={}",
        samples.len(),
        min * mhz,
        median * mhz
    );
}

#[esp_hal::main]
fn main() -> ! {
    // The default boots this part at 80 MHz; a device that signs an
    // assertion cares about the other 160. Both were measured (ledger).
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    esp_alloc::heap_allocator!(size: 64 * 1024);

    let mhz = esp_hal::clock::cpu_clock().as_hz() as u64 / 1_000_000;
    println!("== JANUS KEYS xiao-s3 ==");
    // Which kernel this binary is actually on. A capability you cannot
    // detect is one you must not claim, and a kernel swap that cannot be
    // read off the serial log is one no ledger row can rest on.
    #[cfg(feature = "kairos")]
    println!(
        "KEY kernel={}",
        rusty_esp_rtos::port_name().unwrap_or("none")
    );
    #[cfg(not(feature = "kairos"))]
    println!("KEY kernel=bare-metal");
    println!(
        "KEY cpu_mhz={mhz} iterations={ITERATIONS} rung={}",
        if cfg!(feature = "alloc-rung") {
            "alloc"
        } else {
            "core-only"
        }
    );

    let _source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = match esp_hal::rng::Trng::try_new() {
        Ok(t) => t,
        Err(e) => {
            println!("KEY rng_unavailable={e:?}");
            loop {
                esp_hal::delay::Delay::new().delay_millis(1000);
            }
        }
    };
    let mut rng = ChipRng(trng);

    // X4: the identity partition, then the writer's proof, before the bench.
    #[cfg(feature = "identity")]
    identity::run(peripherals.FLASH, &mut rng);

    // minting is its own cost, and it happens once per device
    let start = Instant::now();
    let key = match DeviceKey::generate(&mut rng, "bench") {
        Ok(k) => k,
        Err(e) => {
            println!("KEY generate_failed={e:?}");
            loop {
                esp_hal::delay::Delay::new().delay_millis(1000);
            }
        }
    };
    let mint_us = start.elapsed().as_micros();
    println!("KEY op=generate n=1 min_us={mint_us} median_us={mint_us} max_us={mint_us} min_cycles={} median_cycles={}", mint_us * mhz, mint_us * mhz);

    let pubkey = key.pubkey_sec1_uncompressed();
    // a fixed digest: the cost under measurement is the curve arithmetic, not
    // the hash, and a constant keeps both arms doing identical work
    let prehash = [0x5au8; 32];

    let mut sign_us = [0u64; ITERATIONS];
    let mut signature = [0u8; 64];
    for slot in sign_us.iter_mut() {
        let t = Instant::now();
        signature = key.sign_prehash(&prehash);
        *slot = t.elapsed().as_micros();
    }
    report("sign", &mut sign_us, mhz);

    let mut verify_us = [0u64; ITERATIONS];
    let mut ok = 0u32;
    for slot in verify_us.iter_mut() {
        let t = Instant::now();
        let r = verify_prehash(&pubkey, &prehash, &signature);
        *slot = t.elapsed().as_micros();
        if r.is_ok() {
            ok += 1;
        }
    }
    report("verify", &mut verify_us, mhz);
    println!("KEY verify_ok={ok}/{ITERATIONS}");

    // the work count beside the clock, as the discipline asks: every
    // iteration did one curve operation over the same 32 bytes
    println!("KEY work signs={ITERATIONS} verifies={ITERATIONS} prehash_bytes=32");

    // The rung is only worth measuring if it is used: with link-time
    // optimisation, a feature nothing calls is dropped and the two binaries
    // come out byte-identical (seen on 2026-09-06 before this block existed).
    // So the alloc build signs a compact JWS, which is the rung's own work:
    // JSON shapes, base64 and an owned DID string.
    #[cfg(feature = "alloc-rung")]
    {
        let t = Instant::now();
        let compact = rusty_esp_mid_core::jws::build_jws_compact(br#"{"sub":"bench"}"#, &key);
        let us = t.elapsed().as_micros();
        println!(
            "KEY op=jws n=1 min_us={us} median_us={us} max_us={us} min_cycles={} median_cycles={} len={}",
            us * mhz,
            us * mhz,
            compact.len()
        );
        println!("KEY did_owned_len={}", key.did().to_did_string().len());
    }
    println!(
        "MEM used={} free={}",
        esp_alloc::HEAP.used(),
        esp_alloc::HEAP.free()
    );
    println!("== DONE ==");
    loop {
        esp_hal::delay::Delay::new().delay_millis(1000);
    }
}
