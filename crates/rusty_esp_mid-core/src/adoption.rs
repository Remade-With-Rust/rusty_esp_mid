//! **Adoption** — the owner-signed grant that tells a device who it belongs
//! to and who it may talk to. It is the Pi-mission bind record, signed.
//!
//! Wire form (all integers big-endian, `len16` = 2-byte length prefix):
//!
//! ```text
//! "janus-adoption-v1\n"
//! version (1)                       = 1
//! len16(device_did) device_did
//! len16(owner_did)  owner_did
//! owner_genesis_pubkey (33)         SEC1 compressed
//! hub_endpoint_id (32)              iroh endpoint id, all-zero when none
//! len16(hub_relay) hub_relay        may be empty
//! len16(hub_host)  hub_host         may be empty ("ip:port")
//! cap_count (1) then cap_count × ( len16(cap) cap )
//! roster_version (4)
//! issued_at (8)                     Unix seconds
//! expires_at (8)                    Unix seconds, 0 = never
//! signature (64)                    low-s ECDSA P-256 by the owner's genesis key
//!                                   over sha256(everything above)
//! ```
//!
//! Decoding borrows every string from the input buffer: no allocation.
//! **TOFU:** the device pins `owner_genesis_pubkey` on first adoption and
//! afterwards accepts only adoptions signed by that key with a roster version
//! at least as new. Rehome is a new adoption from the pinned owner; a factory
//! reset clears the pin and nothing else.

use rusty_esp_core::error::{Error, Result};

use crate::signer::{DeviceSigner, verify_prehash};

/// Domain separator.
pub const ADOPTION_DOMAIN: &[u8] = b"janus-adoption-v1\n";

/// Current wire version.
pub const ADOPTION_VERSION: u8 = 1;

/// Most capability strings one adoption may carry.
pub const MAX_CAPS: usize = 32;

/// Longest single string field.
pub const MAX_FIELD_LEN: usize = 255;

/// Signature length.
pub const SIG_LEN: usize = 64;

/// The `Kv` key holding the encoded adoption.
pub const KV_ADOPTION: &str = "mid.adopt";

/// The `Kv` key holding the owner pin.
pub const KV_OWNER_PIN: &str = "mid.owner";

/// The fields of an adoption, over borrowed strings. Used both to encode
/// (the owner's tooling) and as the decoded view (the device).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdoptionFields<'a> {
    /// The adopted device.
    pub device_did: &'a str,
    /// The owner.
    pub owner_did: &'a str,
    /// The owner's genesis public key, 33 bytes compressed; what the device pins.
    pub owner_genesis_pubkey: &'a [u8; 33],
    /// The hub's iroh endpoint id, or all zeros.
    pub hub_endpoint_id: &'a [u8; 32],
    /// The hub's relay URL, or empty.
    pub hub_relay: &'a str,
    /// The hub's direct address `ip:port`, or empty.
    pub hub_host: &'a str,
    /// Capability strings granted to the hub over this device, in wire order.
    pub caps: CapList<'a>,
    /// The owner's roster version at signing time; monotonic.
    pub roster_version: u32,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds; 0 means never.
    pub expires_at: u64,
}

/// The capability strings of an adoption: either a slice of `&str` (when
/// encoding) or the raw wire bytes (when decoded), iterated the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapList<'a> {
    /// Strings supplied by the encoder.
    Slice(&'a [&'a str]),
    /// `count` length-prefixed strings in `bytes`, already validated.
    Wire {
        /// Number of strings.
        count: u8,
        /// The `len16 str` sequence.
        bytes: &'a [u8],
    },
}

impl<'a> CapList<'a> {
    /// Number of capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            CapList::Slice(s) => s.len(),
            CapList::Wire { count, .. } => *count as usize,
        }
    }

    /// True when no capability is granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate the capability strings.
    pub fn iter(&self) -> CapIter<'a> {
        match *self {
            CapList::Slice(s) => CapIter::Slice(s.iter()),
            CapList::Wire { count, bytes } => CapIter::Wire {
                remaining: count,
                bytes,
            },
        }
    }
}

/// Iterator over capability strings.
#[derive(Debug, Clone)]
pub enum CapIter<'a> {
    /// Over a slice.
    Slice(core::slice::Iter<'a, &'a str>),
    /// Over wire bytes.
    Wire {
        /// Strings left.
        remaining: u8,
        /// Bytes left.
        bytes: &'a [u8],
    },
}

impl<'a> Iterator for CapIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        match self {
            CapIter::Slice(it) => it.next().copied(),
            CapIter::Wire { remaining, bytes } => {
                if *remaining == 0 {
                    return None;
                }
                *remaining -= 1;
                let (s, rest) = read_str(bytes).ok()?;
                *bytes = rest;
                Some(s)
            }
        }
    }
}

/// A decoded, signature-carrying adoption.
#[derive(Debug, Clone, Copy)]
pub struct Adoption<'a> {
    /// The fields.
    pub fields: AdoptionFields<'a>,
    /// The signature over the canonical bytes.
    pub signature: &'a [u8; SIG_LEN],
    /// The canonical bytes (everything before the signature).
    canonical: &'a [u8],
}

/// The owner pin a device stores after its first adoption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerPin {
    /// The owner's genesis public key.
    pub genesis_pubkey: [u8; 33],
    /// The highest roster version accepted so far.
    pub roster_version: u32,
}

impl OwnerPin {
    /// Encoded size.
    pub const LEN: usize = 33 + 4;

    /// Encode into `out`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall { needed: Self::LEN });
        }
        out[..33].copy_from_slice(&self.genesis_pubkey);
        out[33..37].copy_from_slice(&self.roster_version.to_be_bytes());
        Ok(Self::LEN)
    }

    /// Decode from `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::LEN {
            return Err(Error::Corrupt);
        }
        let mut genesis_pubkey = [0u8; 33];
        genesis_pubkey.copy_from_slice(&bytes[..33]);
        let roster_version = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
        Ok(OwnerPin {
            genesis_pubkey,
            roster_version,
        })
    }
}

impl<'a> AdoptionFields<'a> {
    /// Validate field lengths and the capability strings.
    pub fn validate(&self) -> Result<()> {
        for s in [
            self.device_did,
            self.owner_did,
            self.hub_relay,
            self.hub_host,
        ] {
            if s.len() > MAX_FIELD_LEN {
                return Err(Error::InvalidFormat);
            }
        }
        if self.device_did.is_empty() || self.owner_did.is_empty() {
            return Err(Error::InvalidFormat);
        }
        if self.caps.len() > MAX_CAPS {
            return Err(Error::InvalidFormat);
        }
        for cap in self.caps.iter() {
            if cap.len() > MAX_FIELD_LEN || crate::cap::Cap::parse(cap).is_none() {
                return Err(Error::InvalidFormat);
            }
        }
        if self.expires_at != 0 && self.expires_at <= self.issued_at {
            return Err(Error::InvalidFormat);
        }
        Ok(())
    }

    /// Bytes needed by [`Self::encode`], excluding the signature.
    #[must_use]
    pub fn canonical_len(&self) -> usize {
        let mut n = ADOPTION_DOMAIN.len() + 1;
        n += 2 + self.device_did.len() + 2 + self.owner_did.len();
        n += 33 + 32;
        n += 2 + self.hub_relay.len() + 2 + self.hub_host.len();
        n += 1;
        for cap in self.caps.iter() {
            n += 2 + cap.len();
        }
        n + 4 + 8 + 8
    }

    /// Write the canonical (unsigned) bytes into `out`; returns the length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        self.validate()?;
        let needed = self.canonical_len();
        if out.len() < needed {
            return Err(Error::BufferTooSmall { needed });
        }
        let mut w = Writer { out, pos: 0 };
        w.bytes(ADOPTION_DOMAIN);
        w.bytes(&[ADOPTION_VERSION]);
        w.str16(self.device_did);
        w.str16(self.owner_did);
        w.bytes(self.owner_genesis_pubkey);
        w.bytes(self.hub_endpoint_id);
        w.str16(self.hub_relay);
        w.str16(self.hub_host);
        w.bytes(&[self.caps.len() as u8]);
        for cap in self.caps.iter() {
            w.str16(cap);
        }
        w.bytes(&self.roster_version.to_be_bytes());
        w.bytes(&self.issued_at.to_be_bytes());
        w.bytes(&self.expires_at.to_be_bytes());
        debug_assert_eq!(w.pos, needed);
        Ok(w.pos)
    }

    /// Encode and sign into `out` (canonical bytes followed by the 64-byte
    /// signature); returns the total length. The signer is the owner's key.
    pub fn sign_into(&self, signer: &impl DeviceSigner, out: &mut [u8]) -> Result<usize> {
        let n = self.encode(out)?;
        let total = n + SIG_LEN;
        if out.len() < total {
            return Err(Error::BufferTooSmall { needed: total });
        }
        let prehash = crate::sha256(&out[..n]);
        let sig = signer.sign_prehash(&prehash);
        out[n..total].copy_from_slice(&sig);
        Ok(total)
    }
}

impl<'a> Adoption<'a> {
    /// Decode a signed adoption from `bytes` without verifying it.
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < ADOPTION_DOMAIN.len() + 1 + SIG_LEN {
            return Err(Error::InvalidFormat);
        }
        let (canonical, sig_bytes) = bytes.split_at(bytes.len() - SIG_LEN);
        let signature: &[u8; SIG_LEN] = sig_bytes.try_into().map_err(|_| Error::InvalidFormat)?;

        let mut r = canonical;
        r = expect(r, ADOPTION_DOMAIN)?;
        let (version, rest) = read_u8(r)?;
        if version != ADOPTION_VERSION {
            return Err(Error::Unsupported);
        }
        r = rest;
        let (device_did, rest) = read_str(r)?;
        r = rest;
        let (owner_did, rest) = read_str(r)?;
        r = rest;
        let (owner_genesis_pubkey, rest) = read_array::<33>(r)?;
        r = rest;
        let (hub_endpoint_id, rest) = read_array::<32>(r)?;
        r = rest;
        let (hub_relay, rest) = read_str(r)?;
        r = rest;
        let (hub_host, rest) = read_str(r)?;
        r = rest;
        let (count, rest) = read_u8(r)?;
        r = rest;
        let caps_start = r;
        for _ in 0..count {
            let (_, rest) = read_str(r)?;
            r = rest;
        }
        let caps_bytes = &caps_start[..caps_start.len() - r.len()];
        let (rv, rest) = read_array::<4>(r)?;
        r = rest;
        let (ia, rest) = read_array::<8>(r)?;
        r = rest;
        let (ea, rest) = read_array::<8>(r)?;
        if !rest.is_empty() {
            return Err(Error::InvalidFormat);
        }
        let fields = AdoptionFields {
            device_did,
            owner_did,
            owner_genesis_pubkey,
            hub_endpoint_id,
            hub_relay,
            hub_host,
            caps: CapList::Wire {
                count,
                bytes: caps_bytes,
            },
            roster_version: u32::from_be_bytes(*rv),
            issued_at: u64::from_be_bytes(*ia),
            expires_at: u64::from_be_bytes(*ea),
        };
        fields.validate()?;
        Ok(Adoption {
            fields,
            signature,
            canonical,
        })
    }

    /// Verify the signature under the embedded owner genesis key. This alone
    /// does **not** make the adoption acceptable; see [`Self::accept`].
    pub fn verify_signature(&self) -> Result<()> {
        let prehash = crate::sha256(self.canonical);
        verify_prehash(self.fields.owner_genesis_pubkey, &prehash, self.signature)
    }

    /// The full acceptance check a device runs:
    ///
    /// 1. the adoption names *this* device;
    /// 2. the signature verifies under the embedded owner key;
    /// 3. if a pin exists, the owner key equals the pinned key and the roster
    ///    version is not older than the pinned one;
    /// 4. not expired at `now` (Unix seconds; pass `None` when the device has
    ///    no wall clock yet — expiry is then re-checked when it gets one).
    ///
    /// Returns the pin to store.
    pub fn accept(
        &self,
        my_did: &str,
        pin: Option<&OwnerPin>,
        now: Option<u64>,
    ) -> Result<OwnerPin> {
        if self.fields.device_did != my_did {
            return Err(Error::Denied);
        }
        self.verify_signature()?;
        if let Some(pin) = pin {
            if pin.genesis_pubkey != *self.fields.owner_genesis_pubkey {
                return Err(Error::Denied);
            }
            if self.fields.roster_version < pin.roster_version {
                return Err(Error::Denied);
            }
        }
        if let Some(now) = now {
            if self.fields.expires_at != 0 && now >= self.fields.expires_at {
                return Err(Error::Denied);
            }
        }
        Ok(OwnerPin {
            genesis_pubkey: *self.fields.owner_genesis_pubkey,
            roster_version: self.fields.roster_version,
        })
    }

    /// Does this adoption grant `needed` to the hub?
    #[must_use]
    pub fn grants(&self, needed: &str) -> bool {
        crate::cap::any_satisfies(self.fields.caps.iter(), needed)
    }
}

struct Writer<'o> {
    out: &'o mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, b: &[u8]) {
        self.out[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }

    fn str16(&mut self, s: &str) {
        self.bytes(&(s.len() as u16).to_be_bytes());
        self.bytes(s.as_bytes());
    }
}

fn expect<'a>(r: &'a [u8], lit: &[u8]) -> Result<&'a [u8]> {
    if r.len() < lit.len() || &r[..lit.len()] != lit {
        return Err(Error::InvalidFormat);
    }
    Ok(&r[lit.len()..])
}

fn read_u8(r: &[u8]) -> Result<(u8, &[u8])> {
    let (&b, rest) = r.split_first().ok_or(Error::InvalidFormat)?;
    Ok((b, rest))
}

fn read_array<const N: usize>(r: &[u8]) -> Result<(&[u8; N], &[u8])> {
    if r.len() < N {
        return Err(Error::InvalidFormat);
    }
    let (head, rest) = r.split_at(N);
    Ok((head.try_into().map_err(|_| Error::InvalidFormat)?, rest))
}

fn read_str(r: &[u8]) -> Result<(&str, &[u8])> {
    let (len, rest) = read_array::<2>(r)?;
    let len = u16::from_be_bytes(*len) as usize;
    if rest.len() < len {
        return Err(Error::InvalidFormat);
    }
    let (s, rest) = rest.split_at(len);
    Ok((
        core::str::from_utf8(s).map_err(|_| Error::InvalidFormat)?,
        rest,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;

    fn owner() -> DeviceKey {
        DeviceKey::from_seed_for_tests("owner", "phone")
    }

    fn device() -> DeviceKey {
        DeviceKey::from_seed_for_tests("device", "cam-1")
    }

    fn signed(
        owner: &DeviceKey,
        device_did: &str,
        caps: &[&str],
        rv: u32,
        exp: u64,
    ) -> alloc::vec::Vec<u8> {
        let owner_identity = owner.did();
        let owner_did = owner_identity.to_did_string();
        let fields = AdoptionFields {
            device_did,
            owner_did: &owner_did,
            owner_genesis_pubkey: owner_identity.pubkey(),
            hub_endpoint_id: &[7u8; 32],
            hub_relay: "https://relay.mata.network",
            hub_host: "10.0.0.10:4243",
            caps: CapList::Slice(caps),
            roster_version: rv,
            issued_at: 1_700_000_000,
            expires_at: exp,
        };
        let mut buf = alloc::vec![0u8; fields.canonical_len() + SIG_LEN];
        let n = fields.sign_into(owner, &mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn round_trip_and_accept() {
        let (o, d) = (owner(), device());
        let ddid = d.did().to_did_string();
        let bytes = signed(&o, &ddid, &["camera:snapshot", "telemetry:read@home"], 3, 0);
        let a = Adoption::decode(&bytes).unwrap();
        assert_eq!(a.fields.device_did, ddid);
        assert_eq!(a.fields.hub_host, "10.0.0.10:4243");
        assert_eq!(a.fields.caps.len(), 2);
        let caps: alloc::vec::Vec<&str> = a.fields.caps.iter().collect();
        assert_eq!(caps, ["camera:snapshot", "telemetry:read@home"]);
        assert!(a.grants("camera:snapshot@front"));
        assert!(!a.grants("gpio:set"));
        let pin = a.accept(&ddid, None, Some(1_700_000_100)).unwrap();
        assert_eq!(pin.roster_version, 3);
        assert_eq!(&pin.genesis_pubkey, o.did().pubkey());
    }

    #[test]
    fn tofu_pin_rejects_a_second_owner_and_rollback() {
        let (o, d) = (owner(), device());
        let ddid = d.did().to_did_string();
        let first = signed(&o, &ddid, &[], 5, 0);
        let pin = Adoption::decode(&first)
            .unwrap()
            .accept(&ddid, None, None)
            .unwrap();

        let thief = DeviceKey::from_seed_for_tests("thief", "laptop");
        let stolen = signed(&thief, &ddid, &[], 9, 0);
        let a = Adoption::decode(&stolen).unwrap();
        assert!(
            a.verify_signature().is_ok(),
            "signature is valid for the thief's key"
        );
        assert_eq!(a.accept(&ddid, Some(&pin), None), Err(Error::Denied));

        let rollback = signed(&o, &ddid, &[], 4, 0);
        assert_eq!(
            Adoption::decode(&rollback)
                .unwrap()
                .accept(&ddid, Some(&pin), None),
            Err(Error::Denied)
        );
        let rehome = signed(&o, &ddid, &[], 6, 0);
        assert_eq!(
            Adoption::decode(&rehome)
                .unwrap()
                .accept(&ddid, Some(&pin), None)
                .unwrap()
                .roster_version,
            6
        );
    }

    #[test]
    fn wrong_device_expiry_and_tamper() {
        let (o, d) = (owner(), device());
        let ddid = d.did().to_did_string();
        let bytes = signed(&o, &ddid, &["gpio:set"], 1, 1_700_000_500);
        let a = Adoption::decode(&bytes).unwrap();
        assert_eq!(
            a.accept("did:mata:someoneelse", None, None),
            Err(Error::Denied)
        );
        assert!(a.accept(&ddid, None, Some(1_700_000_499)).is_ok());
        assert_eq!(
            a.accept(&ddid, None, Some(1_700_000_500)),
            Err(Error::Denied)
        );

        let mut tampered = bytes.clone();
        let idx = ADOPTION_DOMAIN.len() + 1 + 2 + 1;
        tampered[idx] ^= 0x01;
        match Adoption::decode(&tampered) {
            Ok(t) => assert_eq!(t.verify_signature(), Err(Error::Crypto)),
            Err(e) => assert!(matches!(e, Error::InvalidFormat | Error::Crypto)),
        }
        let mut short = bytes.clone();
        short.pop();
        assert!(Adoption::decode(&short).is_err());
    }

    #[test]
    fn pin_round_trip() {
        let pin = OwnerPin {
            genesis_pubkey: *owner().did().pubkey(),
            roster_version: 42,
        };
        let mut buf = [0u8; OwnerPin::LEN];
        pin.encode(&mut buf).unwrap();
        assert_eq!(OwnerPin::decode(&buf).unwrap(), pin);
        assert_eq!(OwnerPin::decode(&buf[..10]), Err(Error::Corrupt));
    }

    #[test]
    fn validation_rejects_bad_caps_and_lengths() {
        let o = owner();
        let owner_identity = o.did();
        let owner_did = owner_identity.to_did_string();
        let bad_caps = ["not-a-cap"];
        let fields = AdoptionFields {
            device_did: "did:mata:x",
            owner_did: &owner_did,
            owner_genesis_pubkey: owner_identity.pubkey(),
            hub_endpoint_id: &[0u8; 32],
            hub_relay: "",
            hub_host: "",
            caps: CapList::Slice(&bad_caps),
            roster_version: 1,
            issued_at: 10,
            expires_at: 0,
        };
        assert_eq!(fields.validate(), Err(Error::InvalidFormat));
        let mut small = [0u8; 8];
        let ok_caps: [&str; 0] = [];
        let fields = AdoptionFields {
            caps: CapList::Slice(&ok_caps),
            ..fields
        };
        assert!(matches!(
            fields.encode(&mut small),
            Err(Error::BufferTooSmall { .. })
        ));
    }
}
