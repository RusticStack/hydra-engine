//! Reader for Hydra sealed-generation program snapshots (format `HYSNAP01`, version 1).
//!
//! A snapshot holds the initialized memory of one program generation (one modification number). The
//! engine writes it once (`ghidra.app.decompiler.ProgramSnapshotFile`) and never changes it, so a
//! [`Snapshot`] is `Send + Sync` and any number of threads read it at once with no lock. The C++
//! decompiler reads the same file with its own mapping (`SnapshotImage`, loadimage_ghidra.cc); this
//! crate is the reader for Rust components and, through the C ABI in [`ffi`], for Java (FFM) and C.
//!
//! Layout, little-endian:
//!
//! | offset | field |
//! |---|---|
//! | 0 | magic `HYSNAP01` |
//! | 8 | u32 version (1) |
//! | 12 | u32 space count |
//! | 16 | u32 region count |
//! | 20 | u32 reserved (0) |
//! | 24 | u64 generation |
//! | 32 | region table: per region u32 space index, u32 reserved, u64 offset, u64 length, u64 data offset |
//! | ... | space table: per space u32 byte length, UTF-8 name |
//!
//! Regions are sorted by space index then offset and never overlap. A read is served only when the
//! whole range lies in one region, exactly like the decompiler's reader, so callers fall back to the
//! program database for anything else.

pub mod ffi;

use std::fmt;
use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

pub const MAGIC: &[u8; 8] = b"HYSNAP01";
pub const VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 32;
pub const REGION_ENTRY_SIZE: usize = 32;

/// Why a snapshot could not be opened.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Format(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "snapshot I/O error: {e}"),
            Error::Format(what) => write!(f, "bad snapshot: {what}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// One contiguous range of bytes in one address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub space: u32,
    pub offset: u64,
    pub length: u64,
    data_offset: u64,
}

/// One request of a bulk read: `length` bytes of `space` at `offset`, copied to `out_offset` in the
/// caller's buffer. `served` is set by [`Snapshot::read_bulk`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadRequest {
    pub space: u32,
    pub served: u32,
    pub offset: u64,
    pub length: u64,
    pub out_offset: u64,
}

enum Backing {
    Map(Mmap),
    Owned(Vec<u8>),
}

impl Backing {
    fn bytes(&self) -> &[u8] {
        match self {
            Backing::Map(m) => m,
            Backing::Owned(v) => v,
        }
    }
}

/// An open, validated snapshot. Immutable: every method takes `&self`.
pub struct Snapshot {
    backing: Backing,
    generation: u64,
    spaces: Vec<String>,
    regions: Vec<Region>,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

impl Snapshot {
    /// Map and validate the snapshot file at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Snapshot, Error> {
        let file = File::open(path)?;
        // SAFETY: snapshot files are written once and never modified while in use (sealed generation).
        let map = unsafe { Mmap::map(&file)? };
        Self::parse(Backing::Map(map))
    }

    /// Validate a snapshot held in memory (tests and in-process writers).
    pub fn from_vec(bytes: Vec<u8>) -> Result<Snapshot, Error> {
        Self::parse(Backing::Owned(bytes))
    }

    fn parse(backing: Backing) -> Result<Snapshot, Error> {
        let b = backing.bytes();
        let size = b.len() as u64;
        if b.len() < HEADER_SIZE || &b[0..8] != MAGIC {
            return Err(Error::Format("not a snapshot file"));
        }
        if u32_at(b, 8) != VERSION {
            return Err(Error::Format("unsupported version"));
        }
        let space_count = u32_at(b, 12) as u64;
        let region_count = u32_at(b, 16) as u64;
        let generation = u64_at(b, 24);
        if region_count > (size - HEADER_SIZE as u64) / REGION_ENTRY_SIZE as u64 {
            return Err(Error::Format("truncated region table"));
        }
        let mut pos = HEADER_SIZE as u64 + region_count * REGION_ENTRY_SIZE as u64;
        let mut spaces = Vec::with_capacity(space_count as usize);
        for _ in 0..space_count {
            if pos + 4 > size {
                return Err(Error::Format("truncated space table"));
            }
            let len = u32_at(b, pos as usize) as u64;
            pos += 4;
            if len > size - pos {
                return Err(Error::Format("truncated space table"));
            }
            let name = std::str::from_utf8(&b[pos as usize..(pos + len) as usize])
                .map_err(|_| Error::Format("space name is not UTF-8"))?;
            spaces.push(name.to_owned());
            pos += len;
        }
        let mut regions: Vec<Region> = Vec::with_capacity(region_count as usize);
        for i in 0..region_count as usize {
            let e = HEADER_SIZE + i * REGION_ENTRY_SIZE;
            let r = Region {
                space: u32_at(b, e),
                offset: u64_at(b, e + 8),
                length: u64_at(b, e + 16),
                data_offset: u64_at(b, e + 24),
            };
            if r.space as u64 >= space_count {
                return Err(Error::Format("bad space index"));
            }
            if r.length == 0 || r.data_offset > size || r.length > size - r.data_offset {
                return Err(Error::Format("bad region"));
            }
            if r.offset.checked_add(r.length - 1).is_none() {
                return Err(Error::Format("bad region"));
            }
            if let Some(prev) = regions.last()
                && (prev.space > r.space
                    || (prev.space == r.space && prev.offset + (prev.length - 1) >= r.offset))
            {
                return Err(Error::Format("regions out of order"));
            }
            regions.push(r);
        }
        Ok(Snapshot {
            backing,
            generation,
            spaces,
            regions,
        })
    }

    /// The program modification number the snapshot was written at.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Address space names, in index order.
    pub fn spaces(&self) -> &[String] {
        &self.spaces
    }

    /// The regions, sorted by space then offset.
    pub fn regions(&self) -> &[Region] {
        &self.regions
    }

    /// The index of the named address space, if the snapshot has bytes in it.
    pub fn space_index(&self, name: &str) -> Option<u32> {
        self.spaces.iter().position(|s| s == name).map(|i| i as u32)
    }

    /// The mapped bytes of `length` bytes at `offset` in `space`, if one region holds all of them.
    pub fn slice(&self, space: u32, offset: u64, length: u64) -> Option<&[u8]> {
        if length == 0 {
            return None;
        }
        let idx = self
            .regions
            .partition_point(|r| (r.space, r.offset) <= (space, offset));
        let r = self.regions.get(idx.checked_sub(1)?)?;
        if r.space != space {
            return None;
        }
        let rel = offset - r.offset;
        if rel >= r.length || length > r.length - rel {
            return None;
        }
        let start = (r.data_offset + rel) as usize;
        Some(&self.backing.bytes()[start..start + length as usize])
    }

    /// Copy `out.len()` bytes at `offset` in `space` into `out`. Returns false (and leaves `out`
    /// unchanged) unless one region holds the whole range.
    pub fn read(&self, space: u32, offset: u64, out: &mut [u8]) -> bool {
        match self.slice(space, offset, out.len() as u64) {
            Some(src) => {
                out.copy_from_slice(src);
                true
            }
            None => false,
        }
    }

    /// Serve many reads into one buffer. Each request's `served` is set to 1 or 0; a request whose
    /// output range does not fit in `out` is not served. Returns the number served.
    pub fn read_bulk(&self, requests: &mut [ReadRequest], out: &mut [u8]) -> usize {
        let mut served = 0;
        for req in requests.iter_mut() {
            req.served = 0;
            let Some(end) = req.out_offset.checked_add(req.length) else {
                continue;
            };
            if end > out.len() as u64 {
                continue;
            }
            let dst = &mut out[req.out_offset as usize..end as usize];
            if self.read(req.space, req.offset, dst) {
                req.served = 1;
                served += 1;
            }
        }
        served
    }
}

/// Build a snapshot file image from `(space, offset, bytes)` regions, in the writer's layout.
/// Regions must already be sorted and disjoint. Used by tests and by tools that write snapshots.
pub fn encode(generation: u64, spaces: &[&str], regions: &[(u32, u64, &[u8])]) -> Vec<u8> {
    let mut table_end = HEADER_SIZE + regions.len() * REGION_ENTRY_SIZE;
    for s in spaces {
        table_end += 4 + s.len();
    }
    let data_start = (table_end + 7) & !7;
    let mut out = Vec::with_capacity(data_start + regions.iter().map(|r| r.2.len()).sum::<usize>());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(spaces.len() as u32).to_le_bytes());
    out.extend_from_slice(&(regions.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&generation.to_le_bytes());
    let mut next = data_start as u64;
    for (space, offset, bytes) in regions {
        out.extend_from_slice(&space.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        out.extend_from_slice(&next.to_le_bytes());
        next += bytes.len() as u64;
    }
    for s in spaces {
        out.extend_from_slice(&(s.len() as u32).to_le_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    out.resize(data_start, 0);
    for (_, _, bytes) in regions {
        out.extend_from_slice(bytes);
    }
    out
}
