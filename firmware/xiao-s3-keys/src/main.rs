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
