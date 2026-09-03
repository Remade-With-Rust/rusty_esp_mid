//! The robustness gate: every decoder of bytes or JSON that reaches this
//! crate from a peer returns an error on bad input; it never panics. Random
//! inputs from an LCG and mutations of valid encodings (bit flips,
//! truncation, extension), under `catch_unwind` so a failure names the
//! decoder and prints the input.

use std::panic::{AssertUnwindSafe, catch_unwind};

use rusty_esp_mid_core::DeviceKey;
use rusty_esp_mid_core::adoption::{Adoption, AdoptionFields, CapList, OwnerPin};
use rusty_esp_mid_core::cap::Cap;
use rusty_esp_mid_core::did::Did;
use rusty_esp_mid_core::kms::json::{NonceEnvelope, SignedAssertion};

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let n = self.below(max_len + 1);
        (0..n).map(|_| (self.next() >> 56) as u8).collect()
    }

    fn mutate(&mut self, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        match self.below(6) {
            0 if !v.is_empty() => {
                let i = self.below(v.len());
                v[i] ^= 1 << self.below(8);
            }
            1 if !v.is_empty() => {
                let i = self.below(v.len());
                v[i] = (self.next() >> 56) as u8;
            }
            2 => v.truncate(self.below(v.len() + 1)),
            3 => {
                let extra = self.bytes(16);
                v.extend_from_slice(&extra);
            }
            4 => {
                let i = self.below(v.len() + 1);
                v.insert(i, (self.next() >> 56) as u8);
            }
            _ if !v.is_empty() => {
                let i = self.below(v.len());
                v.remove(i);
            }
            _ => {}
        }
        v
    }
}

fn check<R>(name: &str, input: &[u8], f: impl FnOnce() -> R) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
        panic!("{name} panicked on {} bytes: {hex}", input.len());
    }
}

#[test]
fn adoption_decoders_never_panic() {
    let mut rng = Lcg(0x3D0B_0001);
    let owner = DeviceKey::from_seed_for_tests("no-panic", "owner");
    let owner_identity = owner.did();
    let owner_did = owner_identity.to_did_string();
    let device_did = DeviceKey::from_seed_for_tests("no-panic", "cam-1")
        .did()
        .to_did_string();
    let fields = AdoptionFields {
        device_did: &device_did,
        owner_did: &owner_did,
        owner_genesis_pubkey: owner_identity.pubkey(),
        hub_endpoint_id: &[7u8; 32],
        hub_relay: "https://relay.mata.network",
        hub_host: "10.0.0.10:4243",
        caps: CapList::Slice(&["camera:snapshot", "telemetry:read@home"]),
        roster_version: 3,
        issued_at: 1_700_000_000,
        expires_at: 0,
    };
    let mut buf = vec![0u8; 1024];
    let n = fields.sign_into(&owner, &mut buf).unwrap();
    let valid = buf[..n].to_vec();
    assert!(Adoption::decode(&valid).unwrap().verify_signature().is_ok());
    let pin = OwnerPin {
        genesis_pubkey: *owner_identity.pubkey(),
        roster_version: 3,
    };
    let mut pin_buf = [0u8; OwnerPin::LEN];
    pin.encode(&mut pin_buf).unwrap();

    for i in 0..20_000 {
        let input = if i % 3 == 0 {
            rng.bytes(700)
        } else {
            rng.mutate(&valid)
        };
        check("Adoption::decode", &input, || {
            if let Ok(a) = Adoption::decode(&input) {
                let _ = a.verify_signature();
                let _ = a.fields.caps.iter().count();
            }
        });
        let pin_input = if i % 2 == 0 {
            rng.bytes(64)
        } else {
            rng.mutate(&pin_buf)
        };
        check("OwnerPin::decode", &pin_input, || {
            OwnerPin::decode(&pin_input)
        });
    }
}

#[test]
fn did_and_cap_parsers_never_panic() {
    let mut rng = Lcg(0x3D0B_0002);
    let did = DeviceKey::from_seed_for_tests("no-panic", "dev")
        .did()
        .to_did_string();
    let mb = DeviceKey::from_seed_for_tests("no-panic", "dev")
        .did()
        .to_multibase_string();
    for i in 0..30_000 {
        let bytes = match i % 3 {
            0 => rng.bytes(80),
            1 => rng.mutate(did.as_bytes()),
            _ => rng.mutate(mb.as_bytes()),
        };
        let s = String::from_utf8_lossy(&bytes);
        check("Did::parse", &bytes, || {
            Did::parse(&s).map(|d| d.to_did_string())
        });
        check("Did::parse_multibase", &bytes, || {
            Did::parse_multibase(&s).map(|d| d.to_multibase_string())
        });
        check("Cap::parse", &bytes, || Cap::parse(&s).map(|_| ()));
    }
}

#[test]
fn kms_json_parsers_never_panic() {
    let mut rng = Lcg(0x3D0B_0003);
    let k = DeviceKey::from_seed_for_tests("no-panic", "cam");
    let env = NonceEnvelope {
        envelope_version: 1,
        envelope_type: "nonce".into(),
        nonce: vec![9u8; 32],
        did: k.did().to_did_string(),
        audience: "home-computer".into(),
        purpose: "janus.telemetry".into(),
        issued_at: 1_700_000_000,
        expires_at: 1_700_000_060,
        issuer: "home-computer-gateway".into(),
    };
    let env_json = env.to_json();
    assert!(NonceEnvelope::from_json(&env_json).is_ok());
    let signed_json = NonceEnvelope::from_json(&env_json)
        .unwrap()
        .sign(&k)
        .unwrap()
        .to_json();
    assert!(SignedAssertion::from_json(&signed_json).is_ok());

    for i in 0..20_000 {
        let bytes = match i % 3 {
            0 => rng.bytes(300),
            1 => rng.mutate(env_json.as_bytes()),
            _ => rng.mutate(signed_json.as_bytes()),
        };
        let s = String::from_utf8_lossy(&bytes);
        check("NonceEnvelope::from_json", &bytes, || {
            NonceEnvelope::from_json(&s).map(|e| e.to_json())
        });
        check("SignedAssertion::from_json", &bytes, || {
            SignedAssertion::from_json(&s).map(|a| a.to_json())
        });
    }
}
