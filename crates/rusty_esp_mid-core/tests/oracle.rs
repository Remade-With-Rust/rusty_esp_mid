//! The oracle gate: everything this crate emits must be accepted by the real
//! `mid` / `kms` crates, byte for byte where the format is deterministic.
//!
//! These tests run on the host only (the oracles are `std`).

use std::collections::BTreeMap;
use std::sync::Arc;

use kms_types::{DidDocumentV2, RosterEntry};
use kms_verifier::{InMemoryDidResolver, InMemoryNonceStore, Verifier};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rusty_esp_mid_core::kms::json::NonceEnvelope;
use rusty_esp_mid_core::roster::sign_genesis_roster;
use rusty_esp_mid_core::token::{SignInRequest, build_self_issued_token, self_attested};
use rusty_esp_mid_core::{DeviceKey, DeviceSigner, cap};

const AUDIENCE: &str = "https://home.local";
const NOW: u64 = 1_760_000_000;

fn device() -> DeviceKey {
    DeviceKey::from_seed_for_tests("oracle", "cam-1")
}

/// The same key wrapped in `mid`'s own software signer.
fn kms_signer(k: &DeviceKey) -> kms_client::InMemoryDeviceSigner {
    let sk = SigningKey::from_bytes(&k.secret_bytes().into()).unwrap();
    kms_client::InMemoryDeviceSigner::new(k.device_id().as_str(), sk)
}

#[test]
fn did_and_multibase_match_mid_verify() {
    let k = device();
    let vk = VerifyingKey::from_sec1_bytes(k.did().pubkey()).unwrap();
    assert_eq!(k.did().to_did_string(), mid_verify::did_from_pubkey(&vk));
    assert_eq!(
        k.did().to_multibase_string(),
        mid_verify::multibase_from_pubkey(&vk)
    );
    let recovered = mid_verify::pubkey_from_did(&k.did().to_did_string()).unwrap();
    assert_eq!(
        recovered.to_encoded_point(true).as_bytes(),
        k.did().pubkey()
    );
}

#[test]
fn device_signer_is_byte_identical_to_kms_client() {
    let k = device();
    let oracle = kms_signer(&k);
    for msg in [b"a".as_slice(), b"hello world", &[0u8; 100]] {
        let prehash = rusty_esp_mid_core::sha256(msg);
        // RFC 6979 deterministic signing: same key, same prehash, same bytes.
        assert_eq!(k.sign_prehash(&prehash), oracle.sign_prehash(&prehash));
    }
    assert_eq!(k.device_id().as_str(), oracle.device_id());
}

#[test]
fn genesis_roster_is_identical_to_mid_issuer() {
    let k = device();
    let ours = sign_genesis_roster(&k.did(), &k, 1_700_000_000);
    let theirs = mid_issuer::bootstrap::sign_genesis_roster(
        k.did().to_did_string(),
        "cam-1",
        k.did().to_multibase_string(),
        1_700_000_000,
        &kms_signer(&k),
    );
    assert_eq!(
        serde_json::to_value(&ours).unwrap(),
        serde_json::to_value(&theirs).unwrap()
    );
}

#[tokio::test]
async fn kms_assertion_verifies_with_kms_verifier_and_replay_is_refused() {
    let k = device();
    let did = k.did().to_did_string();

    let store = Arc::new(InMemoryNonceStore::new());
    let resolver = Arc::new(InMemoryDidResolver::new());
    resolver
        .upsert(DidDocumentV2 {
            did: did.clone(),
            roster_version: 1,
            roster: vec![RosterEntry {
                device_id: "cam-1".into(),
                pubkey: k.pubkey_sec1_uncompressed().to_vec(),
                added_at: NOW,
                label: "doorbell camera".into(),
            }],
            updated_at: NOW,
        })
        .await;
    let verifier = Verifier::new(
        "home-computer-gateway",
        "home-computer",
        ["janus.telemetry".to_string()],
        store,
        resolver,
    );

    // gateway -> device, as JSON
    let issued = verifier.issue_nonce(&did, "janus.telemetry").await.unwrap();
    let json = serde_json::to_string(&issued).unwrap();
    let env = NonceEnvelope::from_json(&json).unwrap();
    assert_eq!(
        env.to_json(),
        json,
        "our JSON of the envelope is byte-identical"
    );
    assert_eq!(env.as_ref().canonical_bytes(), issued.canonical_bytes());

    // device -> gateway, as JSON
    let wire = env.sign(&k).unwrap().to_json();
    let assertion: kms_types::SignedAssertion = serde_json::from_str(&wire).unwrap();
    let identity = verifier
        .verify(&assertion, "janus.telemetry")
        .await
        .unwrap();
    assert_eq!(identity.did, did);
    assert_eq!(identity.device_id, "cam-1");
    assert_eq!(identity.purpose, "janus.telemetry");

    // the nonce is single-use
    assert!(
        verifier
            .verify(&assertion, "janus.telemetry")
            .await
            .is_err()
    );

    // M4's last audit row: kms-verifier refuses the high-s twin of an
    // assertion, and a refused twin does not burn the nonce (the signature
    // check comes before the consume), so the honest original still lands.
    let issued = verifier.issue_nonce(&did, "janus.telemetry").await.unwrap();
    let env = NonceEnvelope::from_json(&serde_json::to_string(&issued).unwrap()).unwrap();
    let honest: kms_types::SignedAssertion =
        serde_json::from_str(&env.sign(&k).unwrap().to_json()).unwrap();
    let low = p256::ecdsa::Signature::from_slice(&honest.signature).unwrap();
    assert!(low.normalize_s().is_none());
    let (r, s) = low.split_scalars();
    let high = p256::ecdsa::Signature::from_scalars(r, -*s).unwrap();
    let mut twin = honest.clone();
    twin.signature = high.to_bytes().to_vec();
    assert!(
        verifier.verify(&twin, "janus.telemetry").await.is_err(),
        "kms-verifier rejects high-s"
    );
    verifier
        .verify(&honest, "janus.telemetry")
        .await
        .expect("the refused twin did not consume the nonce");
}

#[test]
fn self_issued_token_verifies_with_mid_verify() {
    let k = device();
    let did = k.did().to_did_string();
    let mut claims = BTreeMap::new();
    claims.insert("name".to_string(), self_attested("acme doorbell"));
    let jwt = build_self_issued_token(
        &k.did(),
        &k,
        &SignInRequest {
            audience: AUDIENCE,
            nonce: "nonce-1",
        },
        NOW,
        3600,
        claims,
    )
    .unwrap();

    let verified = mid_verify::verify_mid_response(
        &jwt,
        &mid_verify::VerifyConfig {
            expected_audience: AUDIENCE.into(),
            expected_nonce: "nonce-1".into(),
            max_iat_skew_secs: 120,
            now_unix_secs: NOW + 5,
        },
    )
    .unwrap();
    assert_eq!(verified.did, did);
    assert_eq!(verified.current_version, 1);
    verified.check_rollback(None).unwrap();

    let wrong_audience = mid_verify::verify_mid_response(
        &jwt,
        &mid_verify::VerifyConfig {
            expected_audience: "https://evil.example".into(),
            expected_nonce: "nonce-1".into(),
            max_iat_skew_secs: 120,
            now_unix_secs: NOW + 5,
        },
    );
    assert!(wrong_audience.is_err());

    let wrong_nonce = mid_verify::verify_mid_response(
        &jwt,
        &mid_verify::VerifyConfig {
            expected_audience: AUDIENCE.into(),
            expected_nonce: "nonce-2".into(),
            max_iat_skew_secs: 120,
            now_unix_secs: NOW + 5,
        },
    );
    assert!(wrong_nonce.is_err());
}

/// The size ledger the plan asked for: a device token (1 verification
/// method) and owner tokens whose roster chain lists 8 and 64 devices, all
/// verified before their sizes are reported. Run with `--nocapture` to see it.
#[test]
fn token_size_ledger() {
    let k = device();
    let did = k.did().to_did_string();
    let signer = kms_signer(&k);

    let ours = build_self_issued_token(
        &k.did(),
        &k,
        &SignInRequest {
            audience: AUDIENCE,
            nonce: "n",
        },
        NOW,
        3600,
        BTreeMap::new(),
    )
    .unwrap();
    let cfg = |nonce: &str| mid_verify::VerifyConfig {
        expected_audience: AUDIENCE.into(),
        expected_nonce: nonce.into(),
        max_iat_skew_secs: 120,
        now_unix_secs: NOW + 1,
    };
    mid_verify::verify_mid_response(&ours, &cfg("n")).unwrap();

    let genesis = mid_issuer::bootstrap::sign_genesis_roster(
        did.clone(),
        "cam-1",
        k.did().to_multibase_string(),
        NOW - 1,
        &signer,
    );
    let genesis_vm = genesis.verification_methods[0].clone();
    let mut sizes = vec![(1usize, ours.len())];
    for n in [8usize, 64] {
        let mut vms = vec![genesis_vm.clone()];
        for i in 1..n {
            let extra = DeviceKey::from_seed_for_tests(&format!("extra-{i}"), &format!("dev-{i}"));
            vms.push(mid_issuer::VerificationMethod {
                id: format!("{did}#dev-{i}"),
                vm_type: mid_issuer::bootstrap::VM_TYPE_ECDSA_P256.into(),
                controller: did.clone(),
                public_key_multibase: extra.did().to_multibase_string(),
            });
        }
        let entry = mid_issuer::bootstrap::sign_roster_chain_entry(
            did.clone(),
            2,
            vms,
            "cam-1".into(),
            NOW - 1,
            &signer,
        );
        let snapshot = mid_issuer::IdentitySnapshot {
            did: did.clone(),
            genesis_roster: genesis.clone(),
            roster_chain: vec![entry],
            current_verification_method: mid_issuer::EmbeddedVerificationMethod {
                id: genesis_vm.id.clone(),
                vm_type: genesis_vm.vm_type.clone(),
                controller: genesis_vm.controller.clone(),
                public_key_multibase: genesis_vm.public_key_multibase.clone(),
            },
            approved_claims: BTreeMap::new(),
        };
        let request = mid_issuer::RpRequest {
            rp_origin: AUDIENCE.into(),
            nonce: format!("n{n}"),
            claims: mid_issuer::ClaimRequest {
                required: vec![],
                optional: vec![],
                custom: BTreeMap::new(),
            },
        };
        let jwt = mid_issuer::build_mid_jwt(&request, &snapshot, &signer, NOW).unwrap();
        let verified = mid_verify::verify_mid_response(&jwt, &cfg(&format!("n{n}"))).unwrap();
        assert_eq!(verified.current_version, 2);
        sizes.push((n, jwt.len()));
    }

    println!("\nmID token size ledger (JWS compact form, no claims):");
    println!("{:>8}  {:>10}", "devices", "bytes");
    for (n, bytes) in &sizes {
        println!("{n:>8}  {bytes:>10}");
    }
    assert!(
        sizes.windows(2).all(|w| w[0].1 < w[1].1),
        "size grows with the roster"
    );
}

/// M4's audit row for the upstream verifier, as a test rather than a claim:
/// this core refuses the high-s twin of any signature (ECDSA malleability;
/// `verify_prehash` in `signer.rs`), and the same twin of a self-issued
/// token, re-encoded into the JWS, is what `mid-verify` on the host makes
/// of it. The assertion pins today's upstream behaviour so a change either
/// way is noticed here, and the plan's audit table cites this test.
#[test]
fn high_s_twin_refused_here_and_its_fate_upstream_is_pinned() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::Signature;
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use sha2::{Digest, Sha256};

    let k = device();
    let jwt = build_self_issued_token(
        &k.did(),
        &k,
        &SignInRequest {
            audience: AUDIENCE,
            nonce: "nonce-hs",
        },
        NOW,
        3600,
        BTreeMap::new(),
    )
    .unwrap();
    let mut parts = jwt.splitn(3, '.');
    let (h, p, s) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let sig_bytes = URL_SAFE_NO_PAD.decode(s).unwrap();
    let low = Signature::from_slice(&sig_bytes).unwrap();
    assert!(low.normalize_s().is_none(), "the device emits low-s");
    let (r, s_scalar) = low.split_scalars();
    let high = Signature::from_scalars(r, -*s_scalar).unwrap();
    assert!(high.normalize_s().is_some(), "the twin is high-s");

    // The raw ECDSA layer: the twin is a valid signature over the same
    // prehash (that is what malleability means) ...
    let signing_input = format!("{h}.{p}");
    let prehash: [u8; 32] = Sha256::digest(signing_input.as_bytes()).into();
    let key = VerifyingKey::from_sec1_bytes(k.did().pubkey()).unwrap();
    key.verify_prehash(&prehash, &high).unwrap();
    // ... and this core's verifier still refuses it.
    let mut high_raw = [0u8; 64];
    high_raw.copy_from_slice(&high.to_bytes());
    assert_eq!(
        rusty_esp_mid_core::verify_prehash(k.did().pubkey(), &prehash, &high_raw),
        Err(rusty_esp_core::Error::Crypto)
    );

    // Upstream, today: `mid-verify` verifies the scalars as given, so the
    // high-s twin of a device token is accepted there. When upstream adds
    // the reject, this assertion flips and the audit table gets its tick.
    let twin = format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(high.to_bytes()));
    let cfg = mid_verify::VerifyConfig {
        expected_audience: AUDIENCE.into(),
        expected_nonce: "nonce-hs".into(),
        max_iat_skew_secs: 120,
        now_unix_secs: NOW + 5,
    };
    assert!(
        mid_verify::verify_mid_response(&jwt, &cfg).is_ok(),
        "the low-s original verifies"
    );
    assert!(
        mid_verify::verify_mid_response(&twin, &cfg).is_ok(),
        "UPSTREAM CHANGED: mid-verify now refuses the high-s twin — update the M4 audit table"
    );
}

#[test]
fn capability_matching_agrees_with_mata_cap() {
    let components = ["ledger", "camera"];
    let actions = ["read", "admin"];
    let scopes: [Option<&str>; 3] = [None, Some("us"), Some("eu")];
    let mut cases = 0;
    for &gc in &components {
        for &ga in &actions {
            for gs in scopes {
                for &nc in &components {
                    for &na in &actions {
                        for ns in scopes {
                            let grant = mata_cap::Capability {
                                component: gc.into(),
                                action: ga.into(),
                                scope: gs.map(Into::into),
                            };
                            let needed = mata_cap::Capability {
                                component: nc.into(),
                                action: na.into(),
                                scope: ns.map(Into::into),
                            };
                            assert_eq!(
                                grant.satisfies(&needed),
                                cap::grant_satisfies(&grant.as_str(), &needed.as_str()),
                                "grant {} vs needed {}",
                                grant.as_str(),
                                needed.as_str()
                            );
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 144);
}
