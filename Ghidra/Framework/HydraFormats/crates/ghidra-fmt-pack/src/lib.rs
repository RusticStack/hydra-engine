//! Reader for packed Ghidra items (`ghidra.framework.store.local.ItemSerializer` /
//! `ItemDeserializer`), e.g. a packed database `.pdb`.
//!
//! Layout: a Java `ObjectOutputStream` header holding, as block data, the magic number
//! `0x2e30212634e92c20`, the format version (1), the item name and content type (modified
//! UTF-8), the file type and the content length; followed by a ZIP stream with a single
//! `FOLDER_ITEM` entry. The ZIP is written by `ZipOutputStream` with a data descriptor, so
//! the entry sizes are only known after the compressed data; the deflate stream is decoded by
//! [`inflate::inflate`].

pub mod inflate;

use std::fmt;
use std::path::Path;

const MAGIC_NUMBER: i64 = 0x2e30_2126_34e9_2c20;
const FORMAT_VERSION: i32 = 1;
const ZIP_ENTRY_NAME: &str = "FOLDER_ITEM";
/// Maximum compression ratio `ItemDeserializer` accepts.
const MAX_EXPECTED_COMPRESSION_RATIO: i64 = 130;

const STREAM_MAGIC: [u8; 4] = [0xac, 0xed, 0x00, 0x05];
const TC_BLOCKDATA: u8 = 0x77;
const TC_BLOCKDATALONG: u8 = 0x7a;

/// Errors raised while reading a packed file.
#[derive(Debug)]
pub enum PackError {
    /// The input ended early.
    Truncated,
    /// Not a packed file or malformed header / zip structure.
    Invalid(&'static str),
    /// Invalid deflate data.
    Inflate(&'static str),
    /// The content is longer than the header length.
    TooLarge,
    /// The ZIP CRC-32 or size does not match the data.
    Checksum,
    /// File system error.
    Io(std::io::Error),
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "packed file is truncated"),
            Self::Invalid(m) => write!(f, "invalid packed file: {m}"),
            Self::Inflate(m) => write!(f, "invalid deflate data: {m}"),
            Self::TooLarge => write!(f, "packed content longer than its header length"),
            Self::Checksum => write!(f, "packed content CRC or size mismatch"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PackError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, PackError>;

/// Meta-data stored in front of the packed content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedHeader {
    /// Item name.
    pub item_name: String,
    /// Content type; `None` when stored blank.
    pub content_type: Option<String>,
    /// File type (`FolderItem.DATABASE_FILE_TYPE` for a database).
    pub file_type: i32,
    /// Unpacked content length.
    pub length: i64,
}

/// `ItemSerializer.isPackedFile`: the magic number sits at offset 6.
pub fn is_packed(bytes: &[u8]) -> bool {
    bytes
        .get(6..14)
        .is_some_and(|m| m == MAGIC_NUMBER.to_be_bytes())
}

/// Reads the bytes of Java block-data records as one contiguous stream.
struct BlockReader<'a> {
    data: &'a [u8],
    pos: usize,
    block_left: usize,
}

impl<'a> BlockReader<'a> {
    fn raw(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self
            .data
            .get(self.pos..self.pos + n)
            .ok_or(PackError::Truncated)?;
        self.pos += n;
        Ok(s)
    }

    fn next_block(&mut self) -> Result<()> {
        let tag = self.raw(1)?[0];
        self.block_left = match tag {
            TC_BLOCKDATA => usize::from(self.raw(1)?[0]),
            TC_BLOCKDATALONG => {
                let l = self.raw(4)?;
                let v = i32::from_be_bytes([l[0], l[1], l[2], l[3]]);
                usize::try_from(v).map_err(|_| PackError::Invalid("negative block length"))?
            }
            _ => return Err(PackError::Invalid("header is not block data")),
        };
        Ok(())
    }

    fn take(&mut self, mut n: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        while n > 0 {
            if self.block_left == 0 {
                self.next_block()?;
                continue;
            }
            let k = n.min(self.block_left);
            out.extend_from_slice(self.raw(k)?);
            self.block_left -= k;
            n -= k;
        }
        Ok(out)
    }

    fn i32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i64(&mut self) -> Result<i64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&b);
        Ok(i64::from_be_bytes(a))
    }

    fn utf(&mut self) -> Result<String> {
        let l = self.take(2)?;
        let n = usize::from(u16::from_be_bytes([l[0], l[1]]));
        decode_modified_utf8(&self.take(n)?)
    }
}

/// `DataInput.readUTF` decoding.
fn decode_modified_utf8(b: &[u8]) -> Result<String> {
    let bad = PackError::Invalid("malformed UTF in header");
    let mut units = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = u16::from(b[i]);
        match c >> 4 {
            0..=7 => {
                units.push(c);
                i += 1;
            }
            12 | 13 => {
                let c2 = *b
                    .get(i + 1)
                    .ok_or(PackError::Invalid("malformed UTF in header"))?;
                if c2 & 0xc0 != 0x80 {
                    return Err(bad);
                }
                units.push(((c & 0x1f) << 6) | u16::from(c2 & 0x3f));
                i += 2;
            }
            14 => {
                let (Some(&c2), Some(&c3)) = (b.get(i + 1), b.get(i + 2)) else {
                    return Err(bad);
                };
                if c2 & 0xc0 != 0x80 || c3 & 0xc0 != 0x80 {
                    return Err(bad);
                }
                units.push(((c & 0x0f) << 12) | (u16::from(c2 & 0x3f) << 6) | u16::from(c3 & 0x3f));
                i += 3;
            }
            _ => return Err(bad),
        }
    }
    Ok(String::from_utf16_lossy(&units))
}

fn le16(b: &[u8], at: usize) -> Result<u16> {
    let s = b.get(at..at + 2).ok_or(PackError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn le32(b: &[u8], at: usize) -> Result<u32> {
    let s = b.get(at..at + 4).ok_or(PackError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse only the header (`new ItemDeserializer(file)`); returns it and the offset of the ZIP
/// stream. `file_len` is the packed file length used for the compression-ratio check.
pub fn read_header(bytes: &[u8]) -> Result<(PackedHeader, usize)> {
    if bytes.get(..4) != Some(&STREAM_MAGIC[..]) {
        return Err(PackError::Invalid("no object stream header"));
    }
    let mut r = BlockReader {
        data: bytes,
        pos: 4,
        block_left: 0,
    };
    if r.i64()? != MAGIC_NUMBER {
        return Err(PackError::Invalid("Invalid data"));
    }
    if r.i32()? != FORMAT_VERSION {
        return Err(PackError::Invalid("Unsupported data format"));
    }
    let item_name = r.utf()?;
    let content = r.utf()?;
    let file_type = r.i32()?;
    let length = r.i64()?;
    if r.block_left != 0 {
        return Err(PackError::Invalid("unexpected data after header fields"));
    }
    if item_name.trim().is_empty() || length <= 0 {
        return Err(PackError::Invalid("Invalid packed data file"));
    }
    if length / (bytes.len() as i64) > MAX_EXPECTED_COMPRESSION_RATIO {
        return Err(PackError::Invalid("suspicious compression ratio"));
    }
    let content_type = (!content.trim().is_empty()).then_some(content);
    Ok((
        PackedHeader {
            item_name,
            content_type,
            file_type,
            length,
        },
        r.pos,
    ))
}

/// Unpack a packed file held in memory: header and the item content.
pub fn unpack(bytes: &[u8]) -> Result<(PackedHeader, Vec<u8>)> {
    let (header, zip) = read_header(bytes)?;
    if le32(bytes, zip)? != 0x0403_4b50 {
        return Err(PackError::Invalid("Data error: no zip entry"));
    }
    let flags = le16(bytes, zip + 6)?;
    let method = le16(bytes, zip + 8)?;
    let name_len = usize::from(le16(bytes, zip + 26)?);
    let extra_len = usize::from(le16(bytes, zip + 28)?);
    let name = bytes
        .get(zip + 30..zip + 30 + name_len)
        .ok_or(PackError::Truncated)?;
    if name != ZIP_ENTRY_NAME.as_bytes() {
        return Err(PackError::Invalid("Data error: wrong zip entry name"));
    }
    if method != 8 {
        return Err(PackError::Invalid("zip entry is not deflated"));
    }
    let start = zip + 30 + name_len + extra_len;
    let limit = usize::try_from(header.length).map_err(|_| PackError::TooLarge)?;
    let body = bytes.get(start..).ok_or(PackError::Truncated)?;
    let (content, used) = inflate::inflate(body, limit)?;
    if content.len() != limit {
        return Err(PackError::Invalid("content shorter than header length"));
    }
    let (crc, csize, usize_) = if flags & 8 != 0 {
        // data descriptor, with or without its signature
        let mut at = start + used;
        if le32(bytes, at)? == 0x0807_4b50 {
            at += 4;
        }
        (le32(bytes, at)?, le32(bytes, at + 4)?, le32(bytes, at + 8)?)
    } else {
        (
            le32(bytes, zip + 14)?,
            le32(bytes, zip + 18)?,
            le32(bytes, zip + 22)?,
        )
    };
    if crc != inflate::crc32(&content) || csize as usize != used || usize_ as usize != limit {
        return Err(PackError::Checksum);
    }
    Ok((header, content))
}

/// Unpack the packed file at `path`.
pub fn unpack_file(path: impl AsRef<Path>) -> Result<(PackedHeader, Vec<u8>)> {
    unpack(&std::fs::read(path)?)
}

#[cfg(test)]
mod tests;
