//! `did:mata` — the self-certifying identifier.
//!
//! `did:mata:<base58btc of the 33-byte SEC1-compressed P-256 public key>`,
//! exactly as `mid-verify::keys` defines it (v0: no multicodec prefix). The
//! multibase form used in verification methods is `z<same base58>`.
//!
//! Everything here works without `alloc`: encoding writes into a caller
//! buffer, parsing decodes into a fixed array.

use core::fmt;

use p256::ecdsa::VerifyingKey;
use rusty_esp_core::error::{Error, Result};

/// The DID method prefix.
pub const DID_PREFIX: &str = "did:mata:";

/// Length of a SEC1-compressed P-256 public key.
pub const PUBKEY_LEN: usize = 33;

/// Base58 of 33 bytes is at most 46 characters (ceil(33 · log(256) / log(58))).
pub const MAX_BASE58_LEN: usize = 46;

/// Longest `did:mata:…` string this crate produces.
pub const MAX_DID_LEN: usize = DID_PREFIX.len() + MAX_BASE58_LEN;

/// Longest multibase `z…` string this crate produces.
pub const MAX_MULTIBASE_LEN: usize = 1 + MAX_BASE58_LEN;

/// A `did:mata` identity: the compressed public key, validated on the curve.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Did {
    pubkey: [u8; PUBKEY_LEN],
}

impl Did {
    /// From a 33-byte SEC1-compressed public key. Rejects anything that is
    /// not a valid, non-identity point.
    pub fn from_pubkey(sec1_compressed: &[u8]) -> Result<Self> {
        let pubkey: [u8; PUBKEY_LEN] = sec1_compressed
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;
        if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
            return Err(Error::InvalidFormat);
        }
        VerifyingKey::from_sec1_bytes(&pubkey).map_err(|_| Error::Crypto)?;
        Ok(Did { pubkey })
    }

    /// From a verifying key.
    #[must_use]
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        let point = key.to_encoded_point(true);
        let mut pubkey = [0u8; PUBKEY_LEN];
        pubkey.copy_from_slice(point.as_bytes());
        Did { pubkey }
    }

    /// The 33-byte SEC1-compressed public key.
    #[must_use]
    pub fn pubkey(&self) -> &[u8; PUBKEY_LEN] {
        &self.pubkey
    }

    /// Write `did:mata:<base58>` into `out`; returns the string written.
    pub fn write<'o>(&self, out: &'o mut [u8]) -> Result<&'o str> {
        write_with_prefix(DID_PREFIX.as_bytes(), &self.pubkey, out)
    }

    /// Write the multibase form `z<base58>` into `out`; returns the string written.
    pub fn write_multibase<'o>(&self, out: &'o mut [u8]) -> Result<&'o str> {
        write_with_prefix(b"z", &self.pubkey, out)
    }

    /// Parse `did:mata:<base58>`. Legacy UUID-shaped DIDs are rejected: a
    /// device only ever talks to key-derived identities.
    pub fn parse(did: &str) -> Result<Self> {
        let suffix = did.strip_prefix(DID_PREFIX).ok_or(Error::InvalidFormat)?;
        Self::from_base58(suffix)
    }

    /// Parse the multibase form `z<base58>`.
    pub fn parse_multibase(mb: &str) -> Result<Self> {
        let suffix = mb.strip_prefix('z').ok_or(Error::InvalidFormat)?;
        Self::from_base58(suffix)
    }

    fn from_base58(suffix: &str) -> Result<Self> {
        if suffix.is_empty() || suffix.len() > MAX_BASE58_LEN {
            return Err(Error::InvalidFormat);
        }
        let mut buf = [0u8; PUBKEY_LEN + 1];
        let n = bs58::decode(suffix)
            .onto(&mut buf[..])
            .map_err(|_| Error::InvalidFormat)?;
        if n != PUBKEY_LEN {
            return Err(Error::InvalidFormat);
        }
        Self::from_pubkey(&buf[..PUBKEY_LEN])
    }

    /// `did:mata:<base58>` as an owned string.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn to_did_string(&self) -> alloc::string::String {
        let mut buf = [0u8; MAX_DID_LEN];
        let s = self
            .write(&mut buf)
            .expect("buffer sized for the longest DID");
        alloc::string::String::from(s)
    }

    /// `z<base58>` as an owned string.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn to_multibase_string(&self) -> alloc::string::String {
        let mut buf = [0u8; MAX_MULTIBASE_LEN];
        let s = self
            .write_multibase(&mut buf)
            .expect("buffer sized for the longest multibase key");
        alloc::string::String::from(s)
    }
}

fn write_with_prefix<'o>(prefix: &[u8], bytes: &[u8], out: &'o mut [u8]) -> Result<&'o str> {
    let needed_min = prefix.len() + 1;
    if out.len() < needed_min {
        return Err(Error::BufferTooSmall { needed: needed_min });
    }
    out[..prefix.len()].copy_from_slice(prefix);
    let n = bs58::encode(bytes)
        .onto(&mut out[prefix.len()..])
        .map_err(|_| Error::BufferTooSmall {
            needed: prefix.len() + MAX_BASE58_LEN,
        })?;
    let end = prefix.len() + n;
    core::str::from_utf8(&out[..end]).map_err(|_| Error::Corrupt)
}

impl fmt::Debug for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; MAX_DID_LEN];
        match self.write(&mut buf) {
            Ok(s) => f.write_str(s),
            Err(_) => f.write_str("did:mata:<invalid>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::DeviceKey;

    fn did() -> Did {
        DeviceKey::from_seed_for_tests("did-tests", "dev").did()
    }

    #[test]
    fn write_and_parse_round_trip() {
        let d = did();
        let mut buf = [0u8; MAX_DID_LEN];
        let s = d.write(&mut buf).unwrap();
        assert!(s.starts_with(DID_PREFIX));
        assert_eq!(Did::parse(s).unwrap(), d);
        let mut mb = [0u8; MAX_MULTIBASE_LEN];
        let m = d.write_multibase(&mut mb).unwrap();
        assert!(m.starts_with('z'));
        assert_eq!(Did::parse_multibase(m).unwrap(), d);
    }

    #[test]
    fn rejects_bad_inputs() {
        assert_eq!(Did::parse("did:key:zabc"), Err(Error::InvalidFormat));
        assert_eq!(
            Did::parse("did:mata:550e8400-e29b-41d4-a716-446655440000"),
            Err(Error::InvalidFormat)
        );
        assert_eq!(Did::parse("did:mata:abc"), Err(Error::InvalidFormat));
        assert_eq!(Did::from_pubkey(&[0x04; 33]), Err(Error::InvalidFormat));
        assert_eq!(Did::from_pubkey(&[0x02; 32]), Err(Error::InvalidFormat));
        // Right tag, wrong x: not on the curve for this x with overwhelming odds.
        let mut bad = [0xFFu8; 33];
        bad[0] = 0x02;
        assert!(matches!(
            Did::from_pubkey(&bad),
            Err(Error::Crypto) | Err(Error::InvalidFormat)
        ));
    }

    #[test]
    fn small_buffer_is_reported() {
        let d = did();
        let mut buf = [0u8; 12];
        assert!(matches!(
            d.write(&mut buf),
            Err(Error::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn display_matches_write() {
        let d = did();
        let mut buf = [0u8; MAX_DID_LEN];
        let s = d.write(&mut buf).unwrap();
        assert_eq!(std::format!("{d}"), s);
    }
}
