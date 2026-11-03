//! RFC 1951 raw deflate decoder and CRC-32, so the pack reader needs no dependency.

use crate::PackError;

/// CRC-32 (IEEE, as used by zip).
pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = !0u32;
    for &b in data {
        crc = table[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    !crc
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u32,
    nbits: u32,
}

impl<'a> Bits<'a> {
    fn need(&mut self, n: u32) -> Result<(), PackError> {
        while self.nbits < n {
            let b = *self.data.get(self.pos).ok_or(PackError::Truncated)?;
            self.pos += 1;
            self.bit |= u32::from(b) << self.nbits;
            self.nbits += 8;
        }
        Ok(())
    }

    fn bits(&mut self, n: u32) -> Result<u32, PackError> {
        if n == 0 {
            return Ok(0);
        }
        self.need(n)?;
        let v = self.bit & ((1u32 << n) - 1);
        self.bit >>= n;
        self.nbits -= n;
        Ok(v)
    }

    fn align(&mut self) {
        self.bit = 0;
        self.nbits = 0;
    }
}

/// Canonical Huffman decoding table (counts per length plus symbols in code order).
struct Huffman {
    count: [u16; 16],
    symbol: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Self, PackError> {
        let mut count = [0u16; 16];
        for &l in lengths {
            count[usize::from(l)] += 1;
        }
        count[0] = 0;
        let mut left: i32 = 1;
        for &c in &count[1..] {
            left = (left << 1) - i32::from(c);
            if left < 0 {
                return Err(PackError::Inflate("over-subscribed Huffman code"));
            }
        }
        let mut offs = [0u16; 16];
        for i in 1..15 {
            offs[i + 1] = offs[i] + count[i];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (s, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbol[usize::from(offs[usize::from(l)])] = s as u16;
                offs[usize::from(l)] += 1;
            }
        }
        Ok(Self { count, symbol })
    }

    fn decode(&self, b: &mut Bits<'_>) -> Result<u16, PackError> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..16 {
            code |= b.bits(1)? as i32;
            let count = i32::from(self.count[len]);
            if code - count < first {
                return Ok(self.symbol[(index + (code - first)) as usize]);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(PackError::Inflate("invalid Huffman code"))
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn codes(
    b: &mut Bits<'_>,
    out: &mut Vec<u8>,
    limit: usize,
    lit: &Huffman,
    dist: &Huffman,
) -> Result<(), PackError> {
    loop {
        let sym = lit.decode(b)?;
        match sym {
            0..=255 => {
                if out.len() >= limit {
                    return Err(PackError::TooLarge);
                }
                out.push(sym as u8);
            }
            256 => return Ok(()),
            257..=285 => {
                let i = usize::from(sym - 257);
                let len = usize::from(LEN_BASE[i]) + b.bits(u32::from(LEN_EXTRA[i]))? as usize;
                let ds = usize::from(dist.decode(b)?);
                if ds >= 30 {
                    return Err(PackError::Inflate("invalid distance symbol"));
                }
                let d = usize::from(DIST_BASE[ds]) + b.bits(u32::from(DIST_EXTRA[ds]))? as usize;
                if d > out.len() {
                    return Err(PackError::Inflate("distance too far back"));
                }
                if out.len() + len > limit {
                    return Err(PackError::TooLarge);
                }
                for _ in 0..len {
                    let c = out[out.len() - d];
                    out.push(c);
                }
            }
            _ => return Err(PackError::Inflate("invalid literal/length symbol")),
        }
    }
}

fn fixed_tables() -> Result<(Huffman, Huffman), PackError> {
    let mut l = [0u8; 288];
    for (i, v) in l.iter_mut().enumerate() {
        *v = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    Ok((Huffman::new(&l)?, Huffman::new(&[5u8; 30])?))
}

fn dynamic_tables(b: &mut Bits<'_>) -> Result<(Huffman, Huffman), PackError> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let nlen = b.bits(5)? as usize + 257;
    let ndist = b.bits(5)? as usize + 1;
    let ncode = b.bits(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err(PackError::Inflate("too many length or distance codes"));
    }
    let mut lengths = [0u8; 320];
    for &o in ORDER.iter().take(ncode) {
        lengths[o] = b.bits(3)? as u8;
    }
    let code_h = Huffman::new(&lengths[..19])?;
    let mut lengths = [0u8; 320];
    let mut i = 0;
    while i < nlen + ndist {
        let sym = code_h.decode(b)?;
        if sym < 16 {
            lengths[i] = sym as u8;
            i += 1;
        } else {
            let (prev, rep) = match sym {
                16 => {
                    if i == 0 {
                        return Err(PackError::Inflate("repeat with no previous length"));
                    }
                    (lengths[i - 1], 3 + b.bits(2)? as usize)
                }
                17 => (0, 3 + b.bits(3)? as usize),
                _ => (0, 11 + b.bits(7)? as usize),
            };
            if i + rep > nlen + ndist {
                return Err(PackError::Inflate("too many code lengths"));
            }
            for _ in 0..rep {
                lengths[i] = prev;
                i += 1;
            }
        }
    }
    if lengths[256] == 0 {
        return Err(PackError::Inflate("no end-of-block code"));
    }
    Ok((
        Huffman::new(&lengths[..nlen])?,
        Huffman::new(&lengths[nlen..nlen + ndist])?,
    ))
}

/// Inflate the raw deflate stream at the start of `data`. At most `limit` bytes are produced
/// (more is [`PackError::TooLarge`]). Returns the output and the number of input bytes consumed.
pub fn inflate(data: &[u8], limit: usize) -> Result<(Vec<u8>, usize), PackError> {
    let mut b = Bits {
        data,
        pos: 0,
        bit: 0,
        nbits: 0,
    };
    let mut out = Vec::new();
    loop {
        let last = b.bits(1)?;
        match b.bits(2)? {
            0 => {
                b.align();
                let p = b.pos;
                let hdr = data.get(p..p + 4).ok_or(PackError::Truncated)?;
                let len = usize::from(u16::from_le_bytes([hdr[0], hdr[1]]));
                let nlen = u16::from_le_bytes([hdr[2], hdr[3]]);
                if nlen != !(len as u16) {
                    return Err(PackError::Inflate("stored block length check"));
                }
                let body = data.get(p + 4..p + 4 + len).ok_or(PackError::Truncated)?;
                if out.len() + len > limit {
                    return Err(PackError::TooLarge);
                }
                out.extend_from_slice(body);
                b.pos = p + 4 + len;
            }
            1 => {
                let (l, d) = fixed_tables()?;
                codes(&mut b, &mut out, limit, &l, &d)?;
            }
            2 => {
                let (l, d) = dynamic_tables(&mut b)?;
                codes(&mut b, &mut out, limit, &l, &d)?;
            }
            _ => return Err(PackError::Inflate("invalid block type")),
        }
        if last == 1 {
            break;
        }
    }
    // bits left in the last byte are padding; whole unread bytes are not consumed
    Ok((out, b.pos))
}
