//! JWS compact form for ES256, as `mid-issuer` builds it.
//!
//! `base64url(header) "." base64url(payload) "." base64url(sig)` with the
//! fixed header `{"alg":"ES256","typ":"JWT"}` and the signature over
//! `SHA-256(base64url(header) "." base64url(payload))`.

use alloc::string::String;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::signer::DeviceSigner;

/// The exact header bytes. Changing them is a wire-format break.
pub const JWS_HEADER_JSON: &str = r#"{"alg":"ES256","typ":"JWT"}"#;

/// Build a compact ES256 JWS over `payload_json`.
#[must_use]
pub fn build_jws_compact(payload_json: &[u8], signer: &impl DeviceSigner) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(JWS_HEADER_JSON.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);

    let mut signing_input = String::with_capacity(header_b64.len() + 1 + payload_b64.len() + 88);
    signing_input.push_str(&header_b64);
    signing_input.push('.');
    signing_input.push_str(&payload_b64);

    let prehash = crate::sha256(signing_input.as_bytes());
    let signature = signer.sign_prehash(&prehash);

    signing_input.push('.');
    signing_input.push_str(&URL_SAFE_NO_PAD.encode(signature));
    signing_input
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;

    #[test]
    fn three_segments_with_expected_header_and_signature_size() {
        let k = DeviceKey::from_seed_for_tests("jws", "dev");
        let jws = build_jws_compact(br#"{"x":1}"#, &k);
        let parts: alloc::vec::Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(parts[0]).unwrap(),
            JWS_HEADER_JSON.as_bytes()
        );
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(), 64);
    }
}
