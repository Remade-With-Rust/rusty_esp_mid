//! The ESP-IDF partition table: 32-byte entries — a magic, a type and
//! subtype, an offset, a length, a 16-byte label, flags — ended by an MD5
//! entry or blank flash. Read through `esp-storage` in one piece to find a
//! label.
//!
//! **Where.** `0x8000` unless the build moves it with
//! `ESP_BOOTLOADER_ESP_IDF_CONFIG_PARTITION_TABLE_OFFSET`, the setting
//! `esp-bootloader-esp-idf` reads, so the two never disagree. A bootloader
//! with secure boot and flash encryption does not fit under `0x8000` on the
//! C6 (36,800 B), and its table moves to `0x10000`.
//!
//! **Encrypted.** Under flash encryption the table is ciphertext on the
//! flash; it is read through the cache, which decrypts it.

use esp_storage::FlashStorage;
use rusty_esp_mid_core::esp_core::error::{Error, Result};

/// Where the bootloader keeps the table.
pub const TABLE_OFFSET: u32 =
    match option_env!("ESP_BOOTLOADER_ESP_IDF_CONFIG_PARTITION_TABLE_OFFSET") {
        Some(v) => parse_u32(v),
        None => 0x8000,
    };

/// A decimal or `0x` hexadecimal `u32`, at compile time: a bad setting is a
/// build error, never a table looked for in the wrong place.
const fn parse_u32(s: &str) -> u32 {
    let b = s.as_bytes();
    let (mut i, radix) = if b.len() > 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') {
        (2, 16)
    } else {
        (0, 10)
    };
    assert!(i < b.len(), "an empty partition table offset");
    let mut v: u32 = 0;
    while i < b.len() {
        let d = match b[i] {
            c @ b'0'..=b'9' => (c - b'0') as u32,
            c @ b'a'..=b'f' if radix == 16 => (c - b'a' + 10) as u32,
            c @ b'A'..=b'F' if radix == 16 => (c - b'A' + 10) as u32,
            _ => panic!("the partition table offset is not a number"),
        };
        v = match v.checked_mul(radix) {
            Some(m) => match m.checked_add(d) {
                Some(n) => n,
                None => panic!("the partition table offset overflows"),
            },
            None => panic!("the partition table offset overflows"),
        };
        i += 1;
    }
    v
}
/// Entries the table can hold in its 3 KB (the last is the MD5).
pub const MAX_ENTRIES: u32 = 95;

const MAGIC: [u8; 2] = [0xAA, 0x50];
const MD5_MAGIC: [u8; 2] = [0xEB, 0xEB];

/// One partition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    /// `0` app, `1` data.
    pub kind: u8,
    /// The subtype byte (`0x02` NVS under data).
    pub subtype: u8,
    /// Where it starts, in flash.
    pub offset: u32,
    /// Its size in bytes.
    pub len: u32,
    label: [u8; 16],
}

impl Partition {
    /// The label, as far as its first NUL.
    #[must_use]
    pub fn label(&self) -> &str {
        let end = self
            .label
            .iter()
            .position(|&b| b == 0 || b == 0xFF)
            .unwrap_or(self.label.len());
        core::str::from_utf8(&self.label[..end]).unwrap_or("")
    }
}

impl core::fmt::Debug for Partition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Partition")
            .field("label", &self.label())
            .field("kind", &self.kind)
            .field("subtype", &self.subtype)
            .field("offset", &self.offset)
            .field("len", &self.len)
            .finish()
    }
}

/// The partition labelled `label`, or `Ok(None)`. `Corrupt` when an entry
/// carries neither the entry magic nor the end marks.
pub fn find_partition(storage: &mut FlashStorage<'_>, label: &str) -> Result<Option<Partition>> {
    let mut table = [0u8; MAX_ENTRIES as usize * 32];
    if esp_storage::flash_encryption() {
        storage.read_encrypted(TABLE_OFFSET, &mut table)
    } else {
        storage.read_nor(TABLE_OFFSET, &mut table)
    }
    .map_err(|_| Error::Hardware)?;
    for entry in table.chunks_exact(32) {
        if entry[..2] == MD5_MAGIC || entry[..2] == [0xFF, 0xFF] {
            return Ok(None);
        }
        if entry[..2] != MAGIC {
            return Err(Error::Corrupt);
        }
        let mut name = [0u8; 16];
        name.copy_from_slice(&entry[12..28]);
        let p = Partition {
            kind: entry[2],
            subtype: entry[3],
            offset: u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]),
            len: u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]),
            label: name,
        };
        if p.label() == label {
            return Ok(Some(p));
        }
    }
    Ok(None)
}
