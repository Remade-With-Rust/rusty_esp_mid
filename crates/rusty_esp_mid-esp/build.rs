//! Re-emit esp-idf-sys's environment (the `esp_idf_*` sdkconfig cfgs this crate
//! reads for `Protection`), the way esp-idf-svc and esp-idf-hal do. Without it a
//! library crate never sees `esp_idf_nvs_encryption` / `esp_idf_secure_flash_enc_enabled`
//! even when the firmware configured them. On the host there is no esp-idf-sys
//! and this is a no-op.
fn main() {
    embuild::espidf::sysenv::output();
}
