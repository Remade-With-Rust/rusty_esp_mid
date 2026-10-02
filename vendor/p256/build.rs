//! Janus vendored (round 3): the asm field multiply uses `saltu`, which the
//! ESP32-S2 and ESP32-S3 cores (Xtensa LX7) have and the ESP32's LX6 does
//! not -- there the same bytes decode as `lsi`, a float load. So the asm is
//! behind `janus_saltu`, set here for those two targets only; every other
//! target, the ESP32 included, takes the portable Rust.
fn main() {
    println!("cargo:rustc-check-cfg=cfg(janus_saltu)");
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.starts_with("xtensa-esp32s3") || target.starts_with("xtensa-esp32s2") {
        println!("cargo:rustc-cfg=janus_saltu");
    }
}
