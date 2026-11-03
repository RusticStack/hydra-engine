//! Port of the read side of the memory map: `MemoryMapDBAdapterV3` (the "Memory Blocks" and
//! "Sub Memory Blocks" tables), `MemoryBlockDB` and `SubMemoryBlock`.

use ghidra_fmt_db::Database;
use ghidra_fmt_gbf::BufferStore;

use crate::{Address, AddressMap, AddressRange, ByteMappingScheme, Cols, ProgError, Result};

/// `MemoryBlock.EXECUTE`.
pub const EXECUTE: u8 = 0x1;
/// `MemoryBlock.WRITE`.
pub const WRITE: u8 = 0x2;
/// `MemoryBlock.READ`.
pub const READ: u8 = 0x4;
/// `MemoryBlock.VOLATILE`.
pub const VOLATILE: u8 = 0x8;
/// `MemoryBlock.ARTIFICIAL`.
pub const ARTIFICIAL: u8 = 0x10;

/// What backs a sub block (`MemoryMapDBAdapterV3.V3_SUB_TYPE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubBlockKind {
    /// Bit mapped onto another block (type 0).
    BitMapped,
    /// Byte mapped onto another block (type 1).
    ByteMapped,
    /// Bytes held in the database in a chained buffer (type 2).
    Buffer,
    /// Uninitialized (type 3).
    Uninitialized,
    /// Bytes from an imported file, referencing the "File Bytes" table (type 4).
    FileBytes,
}

impl SubBlockKind {
    fn from_code(code: i8) -> Result<Self> {
        Ok(match code {
            0 => Self::BitMapped,
            1 => Self::ByteMapped,
            2 => Self::Buffer,
            3 => Self::Uninitialized,
            4 => Self::FileBytes,
            n => return Err(ProgError::Corrupt(format!("unknown sub block type {n}"))),
        })
    }

    /// The word the oracle prints: `file_bytes`, `mapped`, `init` or `uninit`.
    pub fn oracle_name(self) -> &'static str {
        match self {
            Self::BitMapped | Self::ByteMapped => "mapped",
            Self::Buffer => "init",
            Self::Uninitialized => "uninit",
            Self::FileBytes => "file_bytes",
        }
    }
}

/// A row of "Sub Memory Blocks".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubBlock {
    /// Record key.
    pub id: i64,
    /// Key of the parent block.
    pub parent_id: i64,
    /// Kind.
    pub kind: SubBlockKind,
    /// Length in bytes.
    pub length: i64,
    /// Offset of this part within the block.
    pub start_offset: i64,
    /// "Source ID": file bytes id for file-backed parts, buffer id for buffers.
    pub source_id: i32,
    /// "Source Address/Offset": offset into the file bytes, or the encoded address key of the
    /// mapped start for mapped parts.
    pub source_offset: i64,
}

impl SubBlock {
    /// For a mapped part, the range of the mapped-to memory that backs it
    /// (`MemoryBlockSourceInfo.getMappedRange`): the byte mapped part covers
    /// `ByteMappingScheme.getMappedSourceAddress` of its last byte, a bit mapped part one source
    /// byte for every 8 bytes. `None` for a part that is not mapped.
    ///
    /// # Errors
    ///
    /// The errors of decoding the stored address; [`ProgError::Corrupt`] when the range leaves
    /// the address space.
    pub fn mapped_range(&self, map: &AddressMap) -> Result<Option<AddressRange>> {
        if self.length <= 0 {
            return Err(ProgError::Corrupt("mapped part without a length".into()));
        }
        let span = match self.kind {
            SubBlockKind::ByteMapped => {
                ByteMappingScheme::from_encoded(self.source_id)?.source_offset(self.length - 1)
            }
            SubBlockKind::BitMapped => (self.length - 1) / 8,
            _ => return Ok(None),
        };
        let Address::Space { space, offset } = map.decode(self.source_offset)? else {
            return Err(ProgError::Corrupt(
                "mapped part without a source address".into(),
            ));
        };
        let bits = map.spaces().find(&space).map_or(64, |s| s.bits);
        let max = u64::try_from(span)
            .ok()
            .and_then(|span| offset.checked_add(span))
            .filter(|m| bits >= 64 || *m < (1u64 << bits))
            .ok_or_else(|| ProgError::Corrupt("mapped range leaves its address space".into()))?;
        Ok(Some(AddressRange {
            space,
            min: offset,
            max,
        }))
    }
}

/// A memory block with its sub blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBlock {
    /// Record key.
    pub id: i64,
    /// Block name.
    pub name: String,
    /// Comment (`None` when the field is null).
    pub comment: Option<String>,
    /// Source name (`None` when the field is null).
    pub source_name: Option<String>,
    /// Raw flag byte (`MemoryBlock.READ` and friends).
    pub flags: u8,
    /// Decoded start address.
    pub start: Address,
    /// The space an overlay block overlays (`None` for a block in an ordinary space).
    pub overlay_base: Option<String>,
    /// Length in bytes.
    pub length: i64,
    /// Parts, sorted by start offset.
    pub sub_blocks: Vec<SubBlock>,
}

impl MemoryBlock {
    /// Read permission.
    pub fn is_read(&self) -> bool {
        self.flags & READ != 0
    }
    /// Write permission.
    pub fn is_write(&self) -> bool {
        self.flags & WRITE != 0
    }
    /// Execute permission.
    pub fn is_execute(&self) -> bool {
        self.flags & EXECUTE != 0
    }
    /// Volatile flag.
    pub fn is_volatile(&self) -> bool {
        self.flags & VOLATILE != 0
    }
    /// Artificial flag.
    pub fn is_artificial(&self) -> bool {
        self.flags & ARTIFICIAL != 0
    }
    /// True for a block in an overlay space (`MemoryBlockDB.isOverlay`).
    pub fn is_overlay(&self) -> bool {
        self.overlay_base.is_some()
    }
    /// True for blocks mapped onto other memory (`MemoryBlockDB.isMapped`).
    pub fn is_mapped(&self) -> bool {
        self.sub_blocks
            .first()
            .is_some_and(|s| matches!(s.kind, SubBlockKind::BitMapped | SubBlockKind::ByteMapped))
    }
    /// True when the first part holds bytes (`MemoryBlockDB.isInitialized`; a mapped block is
    /// never initialized, whatever it is mapped onto, checked against stock Ghidra 12.2).
    pub fn is_initialized(&self) -> bool {
        self.sub_blocks
            .first()
            .is_some_and(|s| matches!(s.kind, SubBlockKind::Buffer | SubBlockKind::FileBytes))
    }
}

pub(crate) fn read_blocks<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<MemoryBlock>> {
    let subs_table = db
        .table("Sub Memory Blocks")
        .map_err(|_| ProgError::MissingTable("Sub Memory Blocks".into()))?;
    let sc = Cols::new(subs_table.schema());
    let mut subs: Vec<SubBlock> = Vec::new();
    for rec in subs_table.records()? {
        let rec = rec?;
        let need = |v: Option<i64>, what: &str| {
            v.ok_or_else(|| ProgError::Corrupt(format!("sub block without {what}")))
        };
        subs.push(SubBlock {
            id: rec
                .key
                .long_value()
                .ok_or_else(|| ProgError::Corrupt("sub block key".into()))?,
            parent_id: need(sc.long(&rec, "Parent ID")?, "parent")?,
            kind: SubBlockKind::from_code(
                sc.byte(&rec, "Type")?
                    .ok_or_else(|| ProgError::Corrupt("sub block without type".into()))?,
            )?,
            length: need(sc.long(&rec, "Length")?, "length")?,
            start_offset: need(sc.long(&rec, "Starting Offset")?, "offset")?,
            source_id: sc.int(&rec, "Source ID")?.unwrap_or(0),
            source_offset: sc.long(&rec, "Source Address/Offset")?.unwrap_or(0),
        });
    }

    let table = db
        .table("Memory Blocks")
        .map_err(|_| ProgError::MissingTable("Memory Blocks".into()))?;
    let bc = Cols::new(table.schema());
    let mut blocks = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        let id = rec
            .key
            .long_value()
            .ok_or_else(|| ProgError::Corrupt("block key".into()))?;
        let start_key = bc
            .long(&rec, "Start Address")?
            .ok_or_else(|| ProgError::Corrupt("block without start address".into()))?;
        let mut sub_blocks: Vec<SubBlock> =
            subs.iter().filter(|s| s.parent_id == id).cloned().collect();
        sub_blocks.sort_by_key(|s| s.start_offset);
        let start = map.decode(start_key)?;
        blocks.push(MemoryBlock {
            id,
            name: bc.string(&rec, "Name")?.unwrap_or_default(),
            comment: bc.string(&rec, "Comments")?,
            source_name: bc.string(&rec, "Source Name")?,
            flags: bc.byte(&rec, "Flags")?.unwrap_or(0) as u8,
            overlay_base: match &start {
                Address::Space { space, .. } => map.spaces().overlay_base(space).map(str::to_owned),
                _ => None,
            },
            start,
            length: bc.long(&rec, "Length")?.unwrap_or(0),
            sub_blocks,
        });
    }
    blocks.sort_by_cached_key(|b| map.sort_key(&b.start));
    Ok(blocks)
}
