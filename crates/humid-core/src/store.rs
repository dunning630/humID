//! Device storage the core owns (CORE.md §7): small named files plus monotonic counters.
//!
//! On iOS the files sit in the app container with `NSFileProtectionComplete`, excluded
//! from backup; on Android in the no-backup directory. The counters live somewhere a
//! file restore doesn't reach (iOS: a `ThisDeviceOnly` Keychain item; Android: a
//! Keystore-bound record), so restoring an old copy of the files can't roll them back.

use std::collections::BTreeMap;

/// Why storage failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The platform refused or the disk failed.
    Io,
    /// A counter would go backwards.
    CounterBackwards,
}

/// The counter that versions the record-revisions file (CORE.md §7).
pub const REVS_COUNTER: &str = "revs";

/// The core's storage. Writes are atomic (temp file, fsync, rename): after a crash a file
/// holds either its old or its new contents, never a mix. A write may report an error and
/// still have landed (the rename done, a later fsync failed); the core re-reads to find out.
///
/// File and counter names are core-chosen constants or `[a-z0-9-]` (CORE.md §7).
pub trait DeviceStore {
    /// Read a file, `None` if it doesn't exist.
    ///
    /// # Errors
    /// [`StoreError::Io`].
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError>;

    /// Replace a file atomically.
    ///
    /// # Errors
    /// [`StoreError::Io`].
    fn write(&mut self, name: &str, bytes: &[u8]) -> Result<(), StoreError>;

    /// Delete a file (no error if absent).
    ///
    /// # Errors
    /// [`StoreError::Io`].
    fn delete(&mut self, name: &str) -> Result<(), StoreError>;

    /// The rollback floor: the lowest wrap counter the core will still open.
    ///
    /// # Errors
    /// [`StoreError::Io`].
    fn floor(&self) -> Result<u64, StoreError>;

    /// Raise the floor. Never lowers it.
    ///
    /// # Errors
    /// [`StoreError::CounterBackwards`] if `n` is below the current floor.
    fn raise_floor(&mut self, n: u64) -> Result<(), StoreError>;

    /// Another named monotonic counter, kept with the floor (0 if never set).
    ///
    /// # Errors
    /// [`StoreError::Io`].
    fn counter(&self, name: &str) -> Result<u64, StoreError>;

    /// Raise a named counter. Never lowers it.
    ///
    /// # Errors
    /// [`StoreError::CounterBackwards`] if `n` is below its current value.
    fn raise_counter(&mut self, name: &str, n: u64) -> Result<(), StoreError>;
}

/// An in-memory store for tests and the simulator. `files` can be snapshotted and
/// restored to model a backup or forensic image; the floor and counters model separate
/// storage that a restore doesn't reach.
#[derive(Clone, Debug, Default)]
pub struct MemStore {
    /// The files.
    pub files: BTreeMap<String, Vec<u8>>,
    /// The wrap floor.
    pub floor: u64,
    /// Other counters.
    pub counters: BTreeMap<String, u64>,
    /// When set, the next write fails without landing.
    pub fail_next_write: bool,
    /// When set, the next write lands but reports an error (rename done, fsync failed).
    pub lie_next_write: bool,
    /// When set, the next floor raise fails (a crash between the wrap write and the floor).
    pub fail_next_floor: bool,
}

impl DeviceStore for MemStore {
    fn read(&self, name: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.files.get(name).cloned())
    }

    fn write(&mut self, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        if std::mem::take(&mut self.fail_next_write) {
            return Err(StoreError::Io);
        }
        self.files.insert(name.to_owned(), bytes.to_vec());
        if std::mem::take(&mut self.lie_next_write) {
            return Err(StoreError::Io);
        }
        Ok(())
    }

    fn delete(&mut self, name: &str) -> Result<(), StoreError> {
        self.files.remove(name);
        Ok(())
    }

    fn floor(&self) -> Result<u64, StoreError> {
        Ok(self.floor)
    }

    fn raise_floor(&mut self, n: u64) -> Result<(), StoreError> {
        if std::mem::take(&mut self.fail_next_floor) {
            return Err(StoreError::Io);
        }
        if n < self.floor {
            return Err(StoreError::CounterBackwards);
        }
        self.floor = n;
        Ok(())
    }

    fn counter(&self, name: &str) -> Result<u64, StoreError> {
        Ok(self.counters.get(name).copied().unwrap_or(0))
    }

    fn raise_counter(&mut self, name: &str, n: u64) -> Result<(), StoreError> {
        let c = self.counters.entry(name.to_owned()).or_insert(0);
        if n < *c {
            return Err(StoreError::CounterBackwards);
        }
        *c = n;
        Ok(())
    }
}
