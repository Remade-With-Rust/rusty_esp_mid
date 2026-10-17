//! **An adoption delivered with the settings** — the owner's grant written
//! on the cable alongside the network, taken into the device's identity at
//! boot, before any network starts.
//!
//! A deployer writes `adopt` (opaque bytes, at most [`ADOPT_MAX`]) into the
//! settings namespace. At boot [`apply`] reads it and, whatever happens to
//! it, removes it from the settings, so a later reflash of the settings slot
//! can neither replay it nor leave it to be read twice:
//!
//! - **Accepted**: the container is stored verbatim in the identity store
//!   (`mid.adopt`, its kind in `mid.adopt.kind`), the owner pinned
//!   (`mid.owner`, an [`OwnerPin`]), and the pin marked **provisional**
//!   (`mid.owner.prov`) when the check was structural only.
//! - **Rehomed**: a pin already exists and the adoption is from the same
//!   owner with a roster version at least the pinned one — the grant is
//!   replaced, as `Adoption::accept`'s trust on first use allows.
//! - **Refused**: malformed, for another device, or from a different owner
//!   than the one pinned. Never silently rebound; the caller logs the reason.
//!
//! The one kind accepted here is [`KIND_MATA_STATEMENT`]: a wallet's signed
//! statement, as the UTF-8 JSON container `{"content": <text>, "jws":
//! <compact JWS>}`. Its check here is **structural**: the JWS header is
//! `{"alg":"ES256","typ":"JWT"}`, its payload's `context` is
//! [`STATEMENT_CONTEXT`] and its `content_hash` is base64url(sha256(content));
//! the content is `{"v":1, "device_did", "owner_did", "roster_version",
//! "caps", "iat", "exp", "name"?}` with `device_did` this device and
//! `owner_did` equal to the payload's `iss` (the owner's genesis DID); the
//! pin is the key that DID names. The signature and roster chain are not
//! verified here — that is the statement verifier's, once a `no_std`
//! mid-verify exists; until then the pin is provisional, and the first boot
//! with the verifier re-checks the stored container and drops the pin if it
//! fails. The settings arrive only over the cable, and the hub verifies the
//! signature in full before it treats anyone as the owner.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::Kv;
use serde_json::Value;

use crate::adoption::{KV_ADOPTION, KV_OWNER_PIN, OwnerPin};
use crate::did::Did;
use crate::status::KIND_MATA_STATEMENT;

/// The settings key the adoption is delivered in.
pub const SETTINGS_ADOPT: &str = "adopt";

/// The largest adoption accepted from the settings, in bytes (espino's
/// `ADOPT_MAX`).
pub const ADOPT_MAX: usize = 8 * 1024;

/// The identity key holding the stored adoption's kind.
pub const KV_ADOPTION_KIND: &str = "mid.adopt.kind";

/// The identity key marking the owner pin provisional (one byte, 1): taken
/// on a structural check, to be re-verified once the signature can be.
pub const KV_PIN_PROVISIONAL: &str = "mid.owner.prov";

/// The statement context an adoption is signed under.
pub const STATEMENT_CONTEXT: &str = "janus-adoption-v1";

/// What a boot did with the settings' adoption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No adoption in the settings.
    Nothing,
    /// The device took its first owner.
    Adopted {
        /// The owner's genesis DID.
        owner_did: String,
        /// The roster version pinned.
        roster_version: u32,
        /// Taken on a structural check only.
        provisional: bool,
    },
    /// The pinned owner's newer grant replaced the stored one.
    Rehomed {
        /// The owner's genesis DID.
        owner_did: String,
        /// The roster version now pinned.
        roster_version: u32,
        /// Taken on a structural check only.
        provisional: bool,
    },
    /// Not taken, and removed from the settings; why, for the log.
    Refused(&'static str),
}

/// A statement container that passed the structural check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// The owner's genesis DID (`content.owner_did` = the payload's `iss`).
    pub owner_did: String,
    /// The pin to store.
    pub pin: OwnerPin,
}

fn field<'v>(v: &'v Value, key: &str) -> Option<&'v Value> {
    v.as_object()?.get(key)
}

fn text<'v>(v: &'v Value, key: &str) -> Option<&'v str> {
    field(v, key)?.as_str()
}

fn b64(part: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| Error::InvalidFormat)
}

/// The structural check of a `mata-statement-v1` container for `my_did`.
pub fn check_statement(
    container: &[u8],
    my_did: &str,
) -> core::result::Result<Checked, &'static str> {
    let outer: Value =
        serde_json::from_slice(container).map_err(|_| "the container is not JSON")?;
    let content = text(&outer, "content").ok_or("the container has no content text")?;
    let jws = text(&outer, "jws").ok_or("the container has no jws text")?;

    let mut parts = jws.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("the jws is not three parts");
    };
    let header: Value =
        serde_json::from_slice(&b64(h).map_err(|_| "the jws header is not base64url")?)
            .map_err(|_| "the jws header is not JSON")?;
    if text(&header, "alg") != Some("ES256") || text(&header, "typ") != Some("JWT") {
        return Err("the jws header is not ES256/JWT");
    }
    if b64(s).map(|sig| sig.len()) != Ok(64) {
        return Err("the jws signature is not 64 bytes");
    }
    let payload: Value =
        serde_json::from_slice(&b64(p).map_err(|_| "the jws payload is not base64url")?)
            .map_err(|_| "the jws payload is not JSON")?;
    if text(&payload, "context") != Some(STATEMENT_CONTEXT) {
        return Err("the statement's context is not janus-adoption-v1");
    }
    let iss = text(&payload, "iss").ok_or("the statement has no iss")?;
    let declared = text(&payload, "content_hash").ok_or("the statement has no content_hash")?;
    if declared != URL_SAFE_NO_PAD.encode(crate::sha256(content.as_bytes())) {
        return Err("the content_hash does not match the content");
    }

    let body: Value = serde_json::from_str(content).map_err(|_| "the content is not JSON")?;
    if field(&body, "v").and_then(Value::as_u64) != Some(1) {
        return Err("the content is not version 1");
    }
    if text(&body, "device_did") != Some(my_did) {
        return Err("the adoption is for another device");
    }
    let owner_did = text(&body, "owner_did").ok_or("the content has no owner_did")?;
    if owner_did != iss {
        return Err("the content's owner is not the statement's issuer");
    }
    let roster_version = field(&body, "roster_version")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("the content has no roster_version")?;
    let owner = Did::parse(owner_did).map_err(|_| "the owner is not a key did:mata")?;
    Ok(Checked {
        owner_did: owner_did.into(),
        pin: OwnerPin {
            genesis_pubkey: *owner.pubkey(),
            roster_version,
        },
    })
}

fn stored_pin<I: Kv + ?Sized>(identity: &I) -> Result<Option<OwnerPin>> {
    let mut buf = [0u8; OwnerPin::LEN];
    match identity.get(KV_OWNER_PIN, &mut buf)? {
        Some(n) if n == OwnerPin::LEN => Ok(Some(OwnerPin::decode(&buf)?)),
        Some(_) => Err(Error::Corrupt),
        None => Ok(None),
    }
}

/// Take the settings' adoption into the identity store (see the module
/// docs). `my_did` is this device's `did:mata`.
pub fn apply<S: Kv + ?Sized, I: Kv + ?Sized>(
    settings: &mut S,
    identity: &mut I,
    my_did: &str,
) -> Result<Outcome> {
    let mut container = vec![0u8; ADOPT_MAX];
    let n = match settings.get(SETTINGS_ADOPT, &mut container) {
        Ok(Some(n)) => n,
        Ok(None) => return Ok(Outcome::Nothing),
        // longer than any adoption may be: refused, and cleared
        Err(Error::BufferTooSmall { .. }) => {
            settings.remove(SETTINGS_ADOPT)?;
            return Ok(Outcome::Refused("the adoption is longer than 8 KiB"));
        }
        Err(e) => return Err(e),
    };
    container.truncate(n);

    let checked = match check_statement(&container, my_did) {
        Ok(c) => c,
        Err(why) => {
            settings.remove(SETTINGS_ADOPT)?;
            return Ok(Outcome::Refused(why));
        }
    };
    let pinned = stored_pin(identity)?;
    if let Some(pin) = &pinned {
        if pin.genesis_pubkey != checked.pin.genesis_pubkey {
            settings.remove(SETTINGS_ADOPT)?;
            return Ok(Outcome::Refused("the device is pinned to another owner"));
        }
        if checked.pin.roster_version < pin.roster_version {
            settings.remove(SETTINGS_ADOPT)?;
            return Ok(Outcome::Refused(
                "the adoption's roster is older than the pinned one",
            ));
        }
    }

    // the grant, then the pin, then the mark, then the settings cleared: a
    // power cut between any two leaves a state the next boot redoes
    // harmlessly (the same owner, the same roster version)
    identity.put(KV_ADOPTION, &container)?;
    identity.put(KV_ADOPTION_KIND, KIND_MATA_STATEMENT.as_bytes())?;
    let mut pin = [0u8; OwnerPin::LEN];
    checked.pin.encode(&mut pin)?;
    identity.put(KV_OWNER_PIN, &pin)?;
    identity.put(KV_PIN_PROVISIONAL, &[1])?;
    settings.remove(SETTINGS_ADOPT)?;

    let (owner_did, roster_version) = (checked.owner_did, checked.pin.roster_version);
    Ok(if pinned.is_some() {
        Outcome::Rehomed {
            owner_did,
            roster_version,
            provisional: true,
        }
    } else {
        Outcome::Adopted {
            owner_did,
            roster_version,
            provisional: true,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;
    use alloc::format;
    use alloc::string::ToString;
    use rusty_esp_core::hal::host::MemoryKv;

    fn did_of(key: &DeviceKey) -> String {
        let mut buf = [0u8; 64];
        key.did().write(&mut buf).unwrap().to_string()
    }

    /// A container shaped as the wallet makes it (the signature bytes are a
    /// stand-in: the check here is structural).
    fn container(device: &str, owner: &str, iss: &str, roster: u32, context: &str) -> Vec<u8> {
        let content = format!(
            r#"{{"caps":[],"device_did":"{device}","exp":0,"iat":1760000000,"name":"porch","owner_did":"{owner}","roster_version":{roster},"v":1}}"#
        );
        let hash = URL_SAFE_NO_PAD.encode(crate::sha256(content.as_bytes()));
        let payload = format!(
            r#"{{"iss":"{iss}","iat":1760000000,"exp":null,"nonce":null,"context":"{context}","content_type":"application/json","content_hash":"{hash}","content_preview":null}}"#
        );
        let jws = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload.as_bytes()),
            URL_SAFE_NO_PAD.encode([7u8; 64])
        );
        serde_json::to_vec(&serde_json::json!({ "content": content, "jws": jws })).unwrap()
    }

    fn setup() -> (String, String, String) {
        let device = did_of(&DeviceKey::from_seed_for_tests(
            "settings-adopt-device",
            "d",
        ));
        let owner = did_of(&DeviceKey::from_seed_for_tests("settings-adopt-owner", "o"));
        let other = did_of(&DeviceKey::from_seed_for_tests("settings-adopt-other", "x"));
        (device, owner, other)
    }

    #[test]
    fn nothing_in_the_settings_is_nothing() {
        let (device, ..) = setup();
        let (mut s, mut id) = (MemoryKv::new(), MemoryKv::new());
        assert_eq!(apply(&mut s, &mut id, &device), Ok(Outcome::Nothing));
    }

    #[test]
    fn a_first_adoption_is_pinned_provisionally_stored_verbatim_and_cleared() {
        let (device, owner, _) = setup();
        let c = container(&device, &owner, &owner, 1, STATEMENT_CONTEXT);
        let (mut s, mut id) = (MemoryKv::new(), MemoryKv::new());
        s.put(SETTINGS_ADOPT, &c).unwrap();
        assert_eq!(
            apply(&mut s, &mut id, &device),
            Ok(Outcome::Adopted {
                owner_did: owner.clone(),
                roster_version: 1,
                provisional: true
            })
        );
        let mut buf = vec![0u8; ADOPT_MAX];
        let n = id.get(KV_ADOPTION, &mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], &c[..], "the container is stored byte for byte");
        let n = id.get(KV_ADOPTION_KIND, &mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], KIND_MATA_STATEMENT.as_bytes());
        let pin = stored_pin(&id).unwrap().unwrap();
        assert_eq!(pin.genesis_pubkey, *Did::parse(&owner).unwrap().pubkey());
        assert_eq!(id.get(KV_PIN_PROVISIONAL, &mut buf).unwrap(), Some(1));
        assert_eq!(s.get(SETTINGS_ADOPT, &mut buf).unwrap(), None, "cleared");
    }

    #[test]
    fn the_same_owner_rehomes_another_is_refused_and_both_are_cleared() {
        let (device, owner, other) = setup();
        let (mut s, mut id) = (MemoryKv::new(), MemoryKv::new());
        s.put(
            SETTINGS_ADOPT,
            &container(&device, &owner, &owner, 2, STATEMENT_CONTEXT),
        )
        .unwrap();
        apply(&mut s, &mut id, &device).unwrap();

        s.put(
            SETTINGS_ADOPT,
            &container(&device, &owner, &owner, 3, STATEMENT_CONTEXT),
        )
        .unwrap();
        assert!(matches!(
            apply(&mut s, &mut id, &device),
            Ok(Outcome::Rehomed {
                roster_version: 3,
                ..
            })
        ));

        s.put(
            SETTINGS_ADOPT,
            &container(&device, &owner, &owner, 2, STATEMENT_CONTEXT),
        )
        .unwrap();
        assert_eq!(
            apply(&mut s, &mut id, &device),
            Ok(Outcome::Refused(
                "the adoption's roster is older than the pinned one"
            ))
        );

        s.put(
            SETTINGS_ADOPT,
            &container(&device, &other, &other, 9, STATEMENT_CONTEXT),
        )
        .unwrap();
        assert_eq!(
            apply(&mut s, &mut id, &device),
            Ok(Outcome::Refused("the device is pinned to another owner"))
        );
        let mut buf = [0u8; 8];
        assert_eq!(
            s.get(SETTINGS_ADOPT, &mut buf).unwrap(),
            None,
            "cleared even when refused"
        );
        assert_eq!(
            stored_pin(&id).unwrap().unwrap().roster_version,
            3,
            "the owner kept"
        );
    }

    #[test]
    fn the_structural_checks_each_refuse() {
        let (device, owner, other) = setup();
        let refuse = |c: Vec<u8>| check_statement(&c, &device).unwrap_err();
        assert_eq!(
            refuse(container(&other, &owner, &owner, 1, STATEMENT_CONTEXT)),
            "the adoption is for another device"
        );
        assert_eq!(
            refuse(container(&device, &owner, &other, 1, STATEMENT_CONTEXT)),
            "the content's owner is not the statement's issuer"
        );
        assert_eq!(
            refuse(container(&device, &owner, &owner, 1, "some-other-context")),
            "the statement's context is not janus-adoption-v1"
        );
        assert_eq!(refuse(b"not json".to_vec()), "the container is not JSON");
        assert_eq!(
            refuse(container(
                &device,
                "did:mata:nope",
                "did:mata:nope",
                1,
                STATEMENT_CONTEXT
            )),
            "the owner is not a key did:mata"
        );
        // content edited after signing: its hash no longer matches
        let mut v: Value =
            serde_json::from_slice(&container(&device, &owner, &owner, 1, STATEMENT_CONTEXT))
                .unwrap();
        let edited = v["content"]
            .as_str()
            .unwrap()
            .replace("\"porch\"", "\"attic\"");
        v["content"] = Value::String(edited);
        assert_eq!(
            refuse(serde_json::to_vec(&v).unwrap()),
            "the content_hash does not match the content"
        );
    }

    #[test]
    fn an_oversize_adoption_is_refused_and_cleared() {
        let (device, ..) = setup();
        let (mut s, mut id) = (MemoryKv::new(), MemoryKv::new());
        s.put(SETTINGS_ADOPT, &vec![b'x'; ADOPT_MAX + 1]).unwrap();
        assert_eq!(
            apply(&mut s, &mut id, &device),
            Ok(Outcome::Refused("the adoption is longer than 8 KiB"))
        );
        let mut buf = [0u8; 8];
        assert_eq!(s.get(SETTINGS_ADOPT, &mut buf).unwrap(), None);
    }
}

#[cfg(test)]
mod dyn_tests {
    use super::*;
    use rusty_esp_core::hal::host::MemoryKv;

    /// The stores a firmware holds are boxed `dyn Kv`s: `apply` takes them.
    #[test]
    fn apply_takes_unsized_stores() {
        let mut s: alloc::boxed::Box<dyn Kv> = alloc::boxed::Box::new(MemoryKv::new());
        let mut id: alloc::boxed::Box<dyn Kv> = alloc::boxed::Box::new(MemoryKv::new());
        assert_eq!(apply(&mut *s, &mut *id, "did:mata:x"), Ok(Outcome::Nothing));
    }
}
