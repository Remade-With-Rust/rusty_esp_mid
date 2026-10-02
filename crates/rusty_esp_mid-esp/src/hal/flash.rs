//! One partition of the chip's SPI flash, through `esp-storage`, as the
//! seam crate's [`Flash`].
//!
//! `esp-storage` reads and programs four-byte words and erases 4 KB
//! sectors through the ROM's SPI flash routines, with the cache held off
//! meanwhile; the NVS module only ever asks for aligned words and whole
//! pages, so nothing here buffers. Offsets are partition-relative and
//! bounds-checked before they reach the flash.

use esp_storage::FlashStorage;
use rusty_esp_mid_core::esp_core::error::{Error, Result};
use rusty_esp_mid_core::esp_core::nvs::{Flash, PAGE_SIZE};

/// A partition: `base` and `len` from the partition table, both whole
/// pages. Borrows the flash, so a firmware opens its partitions one after
/// another on the one `FlashStorage`.
pub struct PartitionFlash<'a, 'd> {
    storage: &'a mut FlashStorage<'d>,
    base: u32,
    len: u32,
}

impl core::fmt::Debug for PartitionFlash<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PartitionFlash")
            .field("base", &self.base)
            .field("len", &self.len)
            .finish()
    }
}

impl<'a, 'd> PartitionFlash<'a, 'd> {
    /// The partition at `base` of `len` bytes. `InvalidGeometry` unless
    /// both are whole pages and `len` is not zero.
    pub fn new(storage: &'a mut FlashStorage<'d>, base: u32, len: u32) -> Result<Self> {
        if len == 0
            || base % PAGE_SIZE != 0
            || len % PAGE_SIZE != 0
            || base.checked_add(len).is_none()
        {
            return Err(Error::InvalidGeometry);
        }
        Ok(PartitionFlash { storage, base, len })
    }

    /// The absolute address of `offset`, when `count` bytes from it fit.
    fn at(&self, offset: u32, count: usize) -> Result<u32> {
        let count = u32::try_from(count).map_err(|_| Error::InvalidGeometry)?;
        match offset.checked_add(count) {
            Some(end) if end <= self.len => Ok(self.base + offset),
            _ => Err(Error::InvalidGeometry),
        }
    }
}

impl Flash for PartitionFlash<'_, '_> {
    fn len(&self) -> u32 {
        self.len
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<()> {
        let at = self.at(offset, buf.len())?;
        self.storage.read_nor(at, buf).map_err(|_| Error::Hardware)
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<()> {
        let at = self.at(offset, data.len())?;
        self.storage
            .write_nor(at, data)
            .map_err(|_| Error::Hardware)
    }

    fn erase_page(&mut self, offset: u32) -> Result<()> {
        let at = self.at(offset, PAGE_SIZE as usize)?;
        self.storage
            .erase(at, at + PAGE_SIZE)
            .map_err(|_| Error::Hardware)
    }
}
