//! The ESP-IDF partition table at `0x8000`: 32-byte entries — a magic,
//! a type and subtype, an offset, a length, a 16-byte label, flags — ended
//! by an MD5 entry or blank flash. Read through `esp-storage`, one entry
//! at a time, to find a label.

use esp_storage::FlashStorage;
use rusty_esp_mid_core::esp_core::error::{Error, Result};

/// Where the bootloader keeps the table.
pub const TABLE_OFFSET: u32 = 0x8000;
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
    let mut entry = [0u8; 32];
    for i in 0..MAX_ENTRIES {
        storage
            .read_nor(TABLE_OFFSET + i * 32, &mut entry)
            .map_err(|_| Error::Hardware)?;
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
