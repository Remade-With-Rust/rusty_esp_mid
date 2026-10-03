//! Several partitions open at once on the one `FlashStorage`: the owner's
//! settings and the identity store, both kept open for the life of a
//! firmware (enc-ble: the setup session holds both).
//!
//! A [`PartitionFlash`] borrows the flash, so two of them cannot live side
//! by side. A [`SharedPartition`] holds the flash through a `RefCell` and
//! makes a `PartitionFlash` for each operation, so no partition holds it
//! between them. Two `NvsKv`s on the **same** partition would each keep
//! their own idea of where the free entries are and the second to write
//! would overwrite the first; [`Store`] is how one namespace is shared
//! instead (the settings and the identity, when a table has no `identity`
//! partition).

use core::cell::RefCell;

use esp_storage::FlashStorage;
use rusty_esp_mid_core::esp_core::error::Result;
use rusty_esp_mid_core::esp_core::hal::Kv;
use rusty_esp_mid_core::esp_core::nvs::{Flash, NvsKv};

use super::{PartitionFlash, find_partition};

/// The chip's flash, shared by every partition a firmware keeps open.
pub type SharedFlash<'d> = RefCell<FlashStorage<'d>>;

/// One namespace of one shared partition.
pub type SharedNvs<'a, 'd> = NvsKv<SharedPartition<'a, 'd>>;

/// One partition of the shared flash.
pub struct SharedPartition<'a, 'd> {
    storage: &'a SharedFlash<'d>,
    base: u32,
    len: u32,
}

impl core::fmt::Debug for SharedPartition<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedPartition")
            .field("base", &self.base)
            .field("len", &self.len)
            .finish()
    }
}

impl<'d> SharedPartition<'_, 'd> {
    fn with<R>(&self, f: impl FnOnce(PartitionFlash<'_, 'd>) -> Result<R>) -> Result<R> {
        let mut storage = self.storage.borrow_mut();
        f(PartitionFlash::new(&mut storage, self.base, self.len)?)
    }
}

impl Flash for SharedPartition<'_, '_> {
    fn len(&self) -> u32 {
        self.len
    }

    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<()> {
        self.with(|mut p| p.read(offset, buf))
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<()> {
        self.with(|mut p| p.write(offset, data))
    }

    fn erase_page(&mut self, offset: u32) -> Result<()> {
        self.with(|mut p| p.erase_page(offset))
    }
}

/// The namespace `namespace` of the partition labelled `label`; `Ok(None)`
/// when the table has no such partition.
pub fn open_shared<'a, 'd>(
    storage: &'a SharedFlash<'d>,
    label: &str,
    namespace: &str,
) -> Result<Option<SharedNvs<'a, 'd>>> {
    let Some(part) = find_partition(&mut storage.borrow_mut(), label)? else {
        return Ok(None);
    };
    let flash = SharedPartition {
        storage,
        base: part.offset,
        len: part.len,
    };
    NvsKv::open(flash, namespace).map(Some)
}

/// A namespace held in a `RefCell`, as a [`Kv`]: so one namespace can be
/// two of a session's stores at once.
pub struct Store<'r, K>(pub &'r RefCell<K>);

impl<K: Kv> Kv for Store<'_, K> {
    fn get(&self, key: &str, out: &mut [u8]) -> Result<Option<usize>> {
        self.0.borrow().get(key, out)
    }

    fn put(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.0.borrow_mut().put(key, value)
    }

    fn remove(&mut self, key: &str) -> Result<bool> {
        self.0.borrow_mut().remove(key)
    }
}
