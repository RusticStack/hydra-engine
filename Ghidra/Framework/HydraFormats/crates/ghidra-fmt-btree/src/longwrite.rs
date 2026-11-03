//! Write path of the long-key B-tree: `db.LongKeyInteriorNode`, `db.LongKeyRecordNode`,
//! `db.VarRecNode` and `db.FixedRecNode` (insert, update, delete, leaf split, interior split
//! and balance). Java never merges leaves; an emptied leaf is removed and interior nodes are
//! rebalanced, and this port does the same operations in the same order so that, from the same
//! operation sequence, the buffers come out byte for byte identical (including stale bytes that
//! Java leaves behind in moved-from regions).
//!
//! Java keeps a `parent` pointer in each node it descended through. Here the same chain is an
//! explicit list of ancestor buffer ids (`path`, root first).

use ghidra_fmt_bytes as bytes;
use ghidra_fmt_chain::ChainedBuffer;
use ghidra_fmt_gbf::{BufferStore, BufferStoreMut, DataBuffer};

use crate::{BtreeError, NodeType, Result};

const KEY_COUNT_OFFSET: usize = 1;
const NODE_HEADER: usize = 5;
const LEAF_HEADER: usize = 13;
const PREV_LEAF: usize = 5;
const NEXT_LEAF: usize = 9;
const KEY_SIZE: usize = 8;
const VAR_ENTRY: usize = KEY_SIZE + 4 + 1;
const INTERIOR_ENTRY: usize = KEY_SIZE + 4;
const MAX_DEPTH: usize = 64;

/// A node buffer held in memory while it is being changed.
#[derive(Clone)]
struct Page {
    id: i32,
    d: Vec<u8>,
}

impl Page {
    fn load<S: BufferStore + ?Sized>(s: &S, id: i32) -> Result<Self> {
        let d = s
            .get_buffer(id)?
            .data
            .ok_or(BtreeError::CorruptNode("node buffer is empty"))?;
        Ok(Self { id, d })
    }

    fn save<S: BufferStoreMut + ?Sized>(&self, s: &mut S) -> Result<()> {
        s.put_buffer(&DataBuffer::new(self.id, self.d.clone()))?;
        Ok(())
    }

    fn len(&self) -> usize {
        self.d.len()
    }

    fn ty(&self) -> u8 {
        self.d.first().copied().unwrap_or(0xff)
    }

    fn i32(&self, off: usize) -> Result<i32> {
        Ok(bytes::get_i32(&self.d, off)?)
    }

    fn set_i32(&mut self, off: usize, v: i32) -> Result<()> {
        Ok(bytes::put_i32(&mut self.d, off, v)?)
    }

    fn i64(&self, off: usize) -> Result<i64> {
        Ok(bytes::get_i64(&self.d, off)?)
    }

    fn set_i64(&mut self, off: usize, v: i64) -> Result<()> {
        Ok(bytes::put_i64(&mut self.d, off, v)?)
    }

    fn count(&self) -> Result<usize> {
        usize::try_from(self.i32(KEY_COUNT_OFFSET)?)
            .map_err(|_| BtreeError::CorruptNode("negative key count"))
    }

    fn set_count(&mut self, n: usize) -> Result<()> {
        self.set_i32(KEY_COUNT_OFFSET, n as i32)
    }

    /// `DataBuffer.move` (memmove inside the buffer).
    fn mv(&mut self, src: i64, dst: i64, len: i64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let n = self.d.len() as i64;
        if src < 0 || dst < 0 || len < 0 || src + len > n || dst + len > n {
            return Err(BtreeError::CorruptNode("buffer move out of range"));
        }
        self.d
            .copy_within(src as usize..(src + len) as usize, dst as usize);
        Ok(())
    }

    /// `DataBuffer.copy(dstOffset, srcBuffer, srcOffset, len)`.
    fn copy_from(&mut self, dst: usize, other: &Page, src: usize, len: usize) -> Result<()> {
        let s = bytes::slice(&other.d, src, len)?;
        Ok(bytes::put_bytes(&mut self.d, dst, s)?)
    }

    fn put_data(&mut self, off: usize, data: &[u8]) -> Result<()> {
        Ok(bytes::put_bytes(&mut self.d, off, data)?)
    }
}

fn new_page<S: BufferStoreMut + ?Sized>(s: &mut S, ty: NodeType) -> Result<Page> {
    let id = s.create_buffer()?;
    let d = s
        .get_buffer(id)?
        .data
        .ok_or(BtreeError::CorruptNode("new buffer is empty"))?;
    let mut p = Page { id, d };
    p.d[0] = ty as u8;
    p.set_count(0)?;
    Ok(p)
}

fn is_leaf_type(t: u8) -> bool {
    t == NodeType::LongKeyVarRec as u8 || t == NodeType::LongKeyFixedRec as u8
}

// ---- interior node primitives ------------------------------------------------------------

fn max_interior_keys(p: &Page) -> usize {
    (p.len() - NODE_HEADER) / INTERIOR_ENTRY
}

fn ikey(p: &Page, i: usize) -> Result<i64> {
    p.i64(NODE_HEADER + i * INTERIOR_ENTRY)
}

fn ichild(p: &Page, i: usize) -> Result<i32> {
    p.i32(NODE_HEADER + i * INTERIOR_ENTRY + KEY_SIZE)
}

/// `getIdIndex`.
fn id_index(p: &Page, key: i64) -> Result<usize> {
    let kc = p.count()? as i64;
    if kc == 0 {
        return Err(BtreeError::CorruptNode("interior node without keys"));
    }
    let (mut min, mut max) = (1i64, kc - 1);
    while min <= max {
        let i = (min + max) / 2;
        let k = ikey(p, i as usize)?;
        match k.cmp(&key) {
            std::cmp::Ordering::Equal => return Ok(i as usize),
            std::cmp::Ordering::Less => min = i + 1,
            std::cmp::Ordering::Greater => max = i - 1,
        }
    }
    Ok(max as usize)
}

/// Interior `getKeyIndex`: `Ok(i)` when present, `Err(insertion point)` otherwise.
fn ikey_index(p: &Page, key: i64) -> Result<std::result::Result<usize, usize>> {
    let (mut min, mut max) = (0i64, p.count()? as i64 - 1);
    while min <= max {
        let i = (min + max) / 2;
        let k = ikey(p, i as usize)?;
        match k.cmp(&key) {
            std::cmp::Ordering::Equal => return Ok(Ok(i as usize)),
            std::cmp::Ordering::Less => min = i + 1,
            std::cmp::Ordering::Greater => max = i - 1,
        }
    }
    Ok(Err(min as usize))
}

fn put_entry(p: &mut Page, i: usize, key: i64, id: i32) -> Result<()> {
    let off = NODE_HEADER + i * INTERIOR_ENTRY;
    p.set_i64(off, key)?;
    p.set_i32(off + KEY_SIZE, id)
}

fn insert_entry(p: &mut Page, index: usize, key: i64, id: i32) -> Result<()> {
    let kc = p.count()?;
    let start = NODE_HEADER + index * INTERIOR_ENTRY;
    let end = NODE_HEADER + kc * INTERIOR_ENTRY;
    p.mv(
        start as i64,
        (start + INTERIOR_ENTRY) as i64,
        (end - start) as i64,
    )?;
    p.set_i64(start, key)?;
    p.set_i32(start + KEY_SIZE, id)?;
    p.set_count(kc + 1)
}

fn delete_entry(p: &mut Page, index: usize) -> Result<()> {
    let kc = p.count()?;
    if kc < 3 || index >= kc {
        return Err(BtreeError::Assertion("interior deleteEntry"));
    }
    let index = index + 1;
    if index < kc {
        let start = NODE_HEADER + index * INTERIOR_ENTRY;
        let end = NODE_HEADER + kc * INTERIOR_ENTRY;
        p.mv(
            start as i64,
            (start - INTERIOR_ENTRY) as i64,
            (end - start) as i64,
        )?;
    }
    p.set_count(kc - 1)
}

fn move_keys_right(left: &mut Page, right: &mut Page, count: usize) -> Result<()> {
    let lk = left.count()?;
    let rk = right.count()?;
    if count > lk {
        return Err(BtreeError::Assertion("moveKeysRight count"));
    }
    let left_offset = NODE_HEADER + (lk - count) * INTERIOR_ENTRY;
    let len = count * INTERIOR_ENTRY;
    right.mv(
        NODE_HEADER as i64,
        (NODE_HEADER + len) as i64,
        (rk * INTERIOR_ENTRY) as i64,
    )?;
    right.copy_from(NODE_HEADER, left, left_offset, len)?;
    left.set_count(lk - count)?;
    right.set_count(rk + count)
}

fn move_keys_left(left: &mut Page, right: &mut Page, count: usize) -> Result<()> {
    let lk = left.count()?;
    let mut rk = right.count()?;
    let left_offset = NODE_HEADER + lk * INTERIOR_ENTRY;
    let len = count * INTERIOR_ENTRY;
    left.copy_from(left_offset, right, NODE_HEADER, len)?;
    left.set_count(lk + count)?;
    if count < rk {
        rk -= count;
        right.mv(
            (NODE_HEADER + len) as i64,
            NODE_HEADER as i64,
            (rk * INTERIOR_ENTRY) as i64,
        )?;
        right.set_count(rk)?;
    }
    Ok(())
}

// ---- leaf primitives ---------------------------------------------------------------------

fn leaf_search(p: &Page, key: i64, entry: usize) -> Result<std::result::Result<usize, usize>> {
    let (mut min, mut max) = (0i64, p.count()? as i64 - 1);
    while min <= max {
        let i = (min + max) / 2;
        let k = p.i64(LEAF_HEADER + i as usize * entry)?;
        match k.cmp(&key) {
            std::cmp::Ordering::Equal => return Ok(Ok(i as usize)),
            std::cmp::Ordering::Less => min = i + 1,
            std::cmp::Ordering::Greater => max = i - 1,
        }
    }
    Ok(Err(min as usize))
}

fn var_key(p: &Page, i: usize) -> Result<i64> {
    p.i64(LEAF_HEADER + i * VAR_ENTRY)
}

fn var_off(p: &Page, i: usize) -> Result<i32> {
    p.i32(LEAF_HEADER + i * VAR_ENTRY + KEY_SIZE)
}

fn set_var_off(p: &mut Page, i: usize, off: i32) -> Result<()> {
    p.set_i32(LEAF_HEADER + i * VAR_ENTRY + KEY_SIZE, off)
}

fn var_indirect(p: &Page, i: usize) -> Result<bool> {
    Ok(bytes::get_u8(&p.d, LEAF_HEADER + i * VAR_ENTRY + KEY_SIZE + 4)? != 0)
}

fn set_var_indirect(p: &mut Page, i: usize, on: bool) -> Result<()> {
    Ok(bytes::put_u8(
        &mut p.d,
        LEAF_HEADER + i * VAR_ENTRY + KEY_SIZE + 4,
        u8::from(on),
    )?)
}

fn leaf_key(p: &Page, i: usize, fixed_len: Option<usize>) -> Result<i64> {
    match p.ty() {
        t if t == NodeType::LongKeyVarRec as u8 => var_key(p, i),
        t if t == NodeType::LongKeyFixedRec as u8 => {
            let n = fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            p.i64(LEAF_HEADER + i * (KEY_SIZE + n))
        }
        _ => Err(BtreeError::CorruptNode("not a leaf")),
    }
}

fn var_free_space(p: &Page) -> Result<i64> {
    let kc = p.count()?;
    let top = if kc == 0 {
        p.len() as i64
    } else {
        i64::from(var_off(p, kc - 1)?)
    };
    Ok(top - (kc * VAR_ENTRY) as i64 - LEAF_HEADER as i64)
}

fn var_record_len(p: &Page, i: usize) -> Result<i64> {
    if i == 0 {
        Ok(p.len() as i64 - i64::from(var_off(p, 0)?))
    } else {
        Ok(i64::from(var_off(p, i - 1)?) - i64::from(var_off(p, i)?))
    }
}

fn var_record_len_at(p: &Page, i: usize, off: i32) -> Result<i64> {
    if i == 0 {
        Ok(p.len() as i64 - i64::from(off))
    } else {
        Ok(i64::from(var_off(p, i - 1)?) - i64::from(off))
    }
}

/// `VarRecNode.moveRecords`.
fn var_move_records(p: &mut Page, index: usize, offset: i64) -> Result<i32> {
    let kc = p.count()?;
    if index == kc {
        if index == 0 {
            return Ok((p.len() as i64 + offset) as i32);
        }
        return Ok((i64::from(var_off(p, kc - 1)?) + offset) as i32);
    }
    let start = i64::from(var_off(p, kc - 1)?);
    let end = if index == 0 {
        p.len() as i64
    } else {
        i64::from(var_off(p, index - 1)?)
    };
    p.mv(start, start + offset, end - start)?;
    for i in index..kc {
        let o = i64::from(var_off(p, i)?) + offset;
        set_var_off(p, i, o as i32)?;
    }
    Ok((end + offset) as i32)
}

fn var_max_record_len(p: &Page) -> i64 {
    (((p.len() - LEAF_HEADER) >> 2) as i64) - VAR_ENTRY as i64
}

fn var_split_index(p: &Page) -> Result<usize> {
    let kc = p.count()?;
    let top = if kc == 0 {
        p.len() as i64
    } else {
        i64::from(var_off(p, kc - 1)?)
    };
    let halfway = (top + p.len() as i64) / 2;
    let (mut min, mut max) = (1i64, kc as i64 - 1);
    while min < max {
        let i = (min + max) / 2;
        let off = i64::from(var_off(p, i as usize)?);
        if off == halfway {
            return Ok(i as usize);
        } else if off < halfway {
            max = i - 1;
        } else {
            min = i + 1;
        }
    }
    Ok(min as usize)
}

fn var_split_data(left: &mut Page, right: &mut Page) -> Result<()> {
    let kc = left.count()?;
    let split_index = var_split_index(left)?;
    let count = kc - split_index;
    let start = var_off(left, kc - 1)? as usize;
    let end = var_off(left, split_index - 1)? as usize;
    let split_len = end - start;
    let right_offset = left.len() - split_len;
    right.copy_from(right_offset, left, start, split_len)?;
    right.copy_from(
        LEAF_HEADER,
        left,
        LEAF_HEADER + split_index * VAR_ENTRY,
        count * VAR_ENTRY,
    )?;
    let correction = (left.len() - end) as i64;
    for i in 0..count {
        let o = i64::from(var_off(right, i)?) + correction;
        set_var_off(right, i, o as i32)?;
    }
    left.set_count(kc - count)?;
    right.set_count(count)
}

fn fixed_entry(n: usize) -> usize {
    KEY_SIZE + n
}

fn fixed_shift(p: &mut Page, index: usize, right: bool, n: usize) -> Result<()> {
    let kc = p.count()?;
    if index == kc {
        return Ok(());
    }
    let es = fixed_entry(n);
    let start = LEAF_HEADER + index * es;
    let end = LEAF_HEADER + kc * es;
    let dst = if right { start + es } else { start - es };
    p.mv(start as i64, dst as i64, (end - start) as i64)
}

fn fixed_split_data(left: &mut Page, right: &mut Page, n: usize) -> Result<()> {
    let kc = left.count()?;
    let es = fixed_entry(n);
    let split_index = kc / 2;
    let count = kc - split_index;
    let start = LEAF_HEADER + split_index * es;
    let end = LEAF_HEADER + kc * es;
    right.copy_from(LEAF_HEADER, left, start, end - start)?;
    left.set_count(kc - count)?;
    right.set_count(count)
}

/// Writer for one long-key table tree. It holds the root buffer id (`-1` while the table has
/// no records) and the fixed record length (`None` for variable-length records).
#[derive(Debug, Clone)]
pub struct LongKeyWriter {
    root: i32,
    fixed_len: Option<usize>,
}

impl LongKeyWriter {
    /// Writer for the tree rooted at `root` (`-1` for an empty table).
    pub fn new(root: i32, fixed_len: Option<usize>) -> Self {
        Self { root, fixed_len }
    }

    /// Current root buffer id, `-1` when the table is empty.
    pub fn root(&self) -> i32 {
        self.root
    }

    fn entry(&self, p: &Page) -> Result<usize> {
        match p.ty() {
            t if t == NodeType::LongKeyVarRec as u8 => Ok(VAR_ENTRY),
            t if t == NodeType::LongKeyFixedRec as u8 => Ok(fixed_entry(
                self.fixed_len.ok_or(BtreeError::MissingFixedLength)?,
            )),
            _ => Err(BtreeError::CorruptNode("not a leaf")),
        }
    }

    /// Walk from the root to the leaf for `key`; returns the leaf id and its ancestors.
    fn descend<S: BufferStore + ?Sized>(
        &self,
        s: &S,
        root: i32,
        key: i64,
    ) -> Result<(i32, Vec<i32>)> {
        let mut path = Vec::new();
        let mut id = root;
        for _ in 0..MAX_DEPTH {
            let p = Page::load(s, id)?;
            if p.ty() == NodeType::LongKeyInterior as u8 {
                let child = ichild(&p, id_index(&p, key)?)?;
                path.push(id);
                id = child;
            } else if is_leaf_type(p.ty()) {
                return Ok((id, path));
            } else {
                return Err(BtreeError::UnexpectedNodeType {
                    found: p.ty(),
                    buffer_id: id,
                });
            }
        }
        Err(BtreeError::TooDeep)
    }

    fn new_leaf<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        prev: i32,
        next: i32,
    ) -> Result<Page> {
        let ty = if self.fixed_len.is_some() {
            NodeType::LongKeyFixedRec
        } else {
            NodeType::LongKeyVarRec
        };
        let mut p = new_page(s, ty)?;
        p.set_i32(PREV_LEAF, prev)?;
        p.set_i32(NEXT_LEAF, next)?;
        Ok(p)
    }

    /// Insert or replace the record for `key` (`Table.putRecord` on a long-key table).
    /// `data` is the serialized non-key part of the record. Returns true when a new record was
    /// added, false when an existing one was replaced.
    pub fn put<S: BufferStoreMut + ?Sized>(
        &mut self,
        s: &mut S,
        key: i64,
        data: &[u8],
    ) -> Result<bool> {
        if let Some(n) = self.fixed_len
            && data.len() != n
        {
            return Err(BtreeError::BadRecordLength {
                expected: n,
                actual: data.len(),
            });
        }
        if self.root < 0 {
            let leaf = self.new_leaf(s, -1, -1)?;
            leaf.save(s)?;
            self.root = leaf.id;
        }
        let (leaf_id, path) = self.descend(s, self.root, key)?;
        let leaf = Page::load(s, leaf_id)?;
        let existed = leaf_search(&leaf, key, self.entry(&leaf)?)?.is_ok();
        self.root = self.put_record(s, leaf_id, path, key, data)?;
        Ok(!existed)
    }

    /// Remove the record for `key` (`Table.deleteRecord`). Returns whether it existed.
    pub fn delete<S: BufferStoreMut + ?Sized>(&mut self, s: &mut S, key: i64) -> Result<bool> {
        if self.root < 0 {
            return Ok(false);
        }
        let (leaf_id, path) = self.descend(s, self.root, key)?;
        match self.delete_record(s, leaf_id, &path, key)? {
            Some(root) => {
                self.root = root.0;
                Ok(root.1)
            }
            None => {
                self.root = -1;
                Ok(true)
            }
        }
    }

    // ---- leaf level ----

    fn put_record<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        mut leaf_id: i32,
        mut path: Vec<i32>,
        key: i64,
        data: &[u8],
    ) -> Result<i32> {
        for _ in 0..MAX_DEPTH * 4 {
            let mut leaf = Page::load(s, leaf_id)?;
            let entry = self.entry(&leaf)?;
            match leaf_search(&leaf, key, entry)? {
                Ok(index) => return self.update_record(s, leaf, &path, index, key, data),
                Err(index) => {
                    if self.insert_record(s, &mut leaf, index, key, data)? {
                        leaf.save(s)?;
                        if index == 0 && !path.is_empty() {
                            let k1 = leaf_key(&leaf, 1, self.fixed_len)?;
                            self.key_changed(s, &path, k1, key)?;
                        }
                        return Ok(path.first().copied().unwrap_or(leaf_id));
                    }
                    if index == leaf.count()? {
                        return self.append_new_leaf(s, leaf, &path, key, data);
                    }
                    let root = self.split(s, leaf, &path)?;
                    let (l, p) = self.descend(s, root, key)?;
                    leaf_id = l;
                    path = p;
                }
            }
        }
        Err(BtreeError::TooDeep)
    }

    /// Returns `(root, existed)`, or `None` when the tree became empty.
    fn delete_record<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        leaf_id: i32,
        path: &[i32],
        key: i64,
    ) -> Result<Option<(i32, bool)>> {
        let mut leaf = Page::load(s, leaf_id)?;
        let entry = self.entry(&leaf)?;
        let Ok(index) = leaf_search(&leaf, key, entry)? else {
            return Ok(Some((path.first().copied().unwrap_or(leaf_id), false)));
        };
        if leaf.count()? == 1 {
            return Ok(self.remove_leaf(s, leaf, path)?.map(|r| (r, true)));
        }
        self.remove(s, &mut leaf, index)?;
        leaf.save(s)?;
        if index == 0 && !path.is_empty() {
            let k0 = leaf_key(&leaf, 0, self.fixed_len)?;
            self.key_changed(s, path, key, k0)?;
        }
        Ok(Some((path.first().copied().unwrap_or(leaf_id), true)))
    }

    fn remove<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        leaf: &mut Page,
        index: usize,
    ) -> Result<()> {
        let kc = leaf.count()?;
        if index >= kc {
            return Err(BtreeError::Assertion("remove index"));
        }
        if leaf.ty() == NodeType::LongKeyFixedRec as u8 {
            let n = self.fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            fixed_shift(leaf, index + 1, false, n)?;
            return leaf.set_count(kc - 1);
        }
        if var_indirect(leaf, index)? {
            let id = leaf.i32(var_off(leaf, index)? as usize)?;
            remove_chained(s, id)?;
            set_var_indirect(leaf, index, false)?;
        }
        let len = var_record_len(leaf, index)?;
        var_move_records(leaf, index + 1, len)?;
        let start = LEAF_HEADER + (index + 1) * VAR_ENTRY;
        let l = (kc - index - 1) * VAR_ENTRY;
        leaf.mv(start as i64, (start - VAR_ENTRY) as i64, l as i64)?;
        leaf.set_count(kc - 1)
    }

    fn insert_record<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        leaf: &mut Page,
        index: usize,
        key: i64,
        data: &[u8],
    ) -> Result<bool> {
        let kc = leaf.count()?;
        if leaf.ty() == NodeType::LongKeyFixedRec as u8 {
            let n = self.fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            if kc == (leaf.len() - LEAF_HEADER) / fixed_entry(n) {
                return Ok(false);
            }
            fixed_shift(leaf, index, true, n)?;
            let off = LEAF_HEADER + index * fixed_entry(n);
            leaf.set_i64(off, key)?;
            leaf.put_data(off + KEY_SIZE, data)?;
            leaf.set_count(kc + 1)?;
            return Ok(true);
        }
        let mut len = data.len() as i64;
        let use_indirect = len > var_max_record_len(leaf);
        if use_indirect {
            len = 4;
        }
        if len + VAR_ENTRY as i64 > var_free_space(leaf)? {
            return Ok(false);
        }
        let offset = var_move_records(leaf, index, -len)?;
        let start = LEAF_HEADER + index * VAR_ENTRY;
        leaf.mv(
            start as i64,
            (start + VAR_ENTRY) as i64,
            ((kc - index) * VAR_ENTRY) as i64,
        )?;
        leaf.set_i64(start, key)?;
        leaf.set_i32(start + KEY_SIZE, offset)?;
        leaf.set_count(kc + 1)?;
        if use_indirect {
            let mut cb = ChainedBuffer::create(s, data.len() as i32, false)?;
            leaf.set_i32(offset as usize, cb.id())?;
            cb.put(s, 0, data)?;
        } else {
            leaf.put_data(offset as usize, data)?;
        }
        set_var_indirect(leaf, index, use_indirect)?;
        Ok(true)
    }

    fn update_record<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        mut leaf: Page,
        path: &[i32],
        index: usize,
        key: i64,
        data: &[u8],
    ) -> Result<i32> {
        let leaf_id = leaf.id;
        let root = path.first().copied().unwrap_or(leaf_id);
        if leaf.ty() == NodeType::LongKeyFixedRec as u8 {
            let n = self.fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            let off = LEAF_HEADER + index * fixed_entry(n) + KEY_SIZE;
            leaf.put_data(off, data)?;
            leaf.save(s)?;
            return Ok(root);
        }
        let mut offset = var_off(&leaf, index)?;
        let old_len = var_record_len_at(&leaf, index, offset)?;
        let mut len = data.len() as i64;
        let was_indirect = var_indirect(&leaf, index)?;
        let use_indirect = len > var_max_record_len(&leaf);
        if use_indirect {
            len = 4;
            if was_indirect {
                let id = leaf.i32(offset as usize)?;
                let mut cb = ChainedBuffer::open(s, id)?;
                cb.set_size(s, data.len() as i32, false)?;
                cb.put(s, 0, data)?;
            } else {
                // Java assumes the old record is at least 4 bytes (a variable-length schema
                // always stores a 4 byte length prefix); a shorter one would be corrupted
                if old_len < 4 {
                    return Err(BtreeError::Assertion(
                        "record shorter than 4 bytes cannot become indirect",
                    ));
                }
                let mut cb = ChainedBuffer::create(s, data.len() as i32, false)?;
                leaf.set_i32((i64::from(offset) + old_len - 4) as usize, cb.id())?;
                set_var_indirect(&mut leaf, index, true)?;
                cb.put(s, 0, data)?;
            }
        } else if was_indirect {
            let id = leaf.i32(offset as usize)?;
            remove_chained(s, id)?;
            set_var_indirect(&mut leaf, index, false)?;
        }
        if use_indirect || len <= var_free_space(&leaf)? + old_len {
            let shift = old_len - len;
            if shift != 0 {
                offset = var_move_records(&mut leaf, index + 1, shift)?;
                set_var_off(&mut leaf, index, offset)?;
            }
            if !use_indirect {
                leaf.put_data(offset as usize, data)?;
            }
            leaf.save(s)?;
            return Ok(root);
        }
        // not enough room: remove and add again
        leaf.save(s)?;
        let Some((new_root, _)) = self.delete_record(s, leaf_id, path, key)? else {
            return Err(BtreeError::Assertion(
                "tree emptied while replacing a record",
            ));
        };
        let (l, p) = self.descend(s, new_root, key)?;
        self.put_record(s, l, p, key, data)
    }

    fn append_new_leaf<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        mut leaf: Page,
        path: &[i32],
        key: i64,
        data: &[u8],
    ) -> Result<i32> {
        let mut new_leaf = self.new_leaf(s, -1, -1)?;
        self.insert_record(s, &mut new_leaf, 0, key, data)?;
        // appendLeaf
        new_leaf.set_i32(PREV_LEAF, leaf.id)?;
        let right_id = leaf.i32(NEXT_LEAF)?;
        new_leaf.set_i32(NEXT_LEAF, right_id)?;
        leaf.set_i32(NEXT_LEAF, new_leaf.id)?;
        new_leaf.save(s)?;
        leaf.save(s)?;
        if right_id >= 0 {
            let mut right = Page::load(s, right_id)?;
            right.set_i32(PREV_LEAF, new_leaf.id)?;
            right.save(s)?;
        }
        let first_key = leaf_key(&new_leaf, 0, self.fixed_len)?;
        if let Some((&parent, anc)) = path.split_last() {
            return self.interior_insert(s, anc, parent, new_leaf.id, first_key);
        }
        let k0 = leaf_key(&leaf, 0, self.fixed_len)?;
        self.new_root(s, k0, leaf.id, first_key, new_leaf.id)
    }

    fn split<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        mut leaf: Page,
        path: &[i32],
    ) -> Result<i32> {
        let old_sibling = leaf.i32(NEXT_LEAF)?;
        let mut new_leaf = self.new_leaf(s, leaf.id, old_sibling)?;
        leaf.set_i32(NEXT_LEAF, new_leaf.id)?;
        if old_sibling >= 0 {
            let mut sib = Page::load(s, old_sibling)?;
            sib.set_i32(PREV_LEAF, new_leaf.id)?;
            sib.save(s)?;
        }
        if leaf.ty() == NodeType::LongKeyFixedRec as u8 {
            let n = self.fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            fixed_split_data(&mut leaf, &mut new_leaf, n)?;
        } else {
            var_split_data(&mut leaf, &mut new_leaf)?;
        }
        leaf.save(s)?;
        new_leaf.save(s)?;
        let right_key = leaf_key(&new_leaf, 0, self.fixed_len)?;
        if let Some((&parent, anc)) = path.split_last() {
            return self.interior_insert(s, anc, parent, new_leaf.id, right_key);
        }
        let k0 = leaf_key(&leaf, 0, self.fixed_len)?;
        self.new_root(s, k0, leaf.id, right_key, new_leaf.id)
    }

    /// `removeLeaf`; `None` when the whole tree became empty.
    fn remove_leaf<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        leaf: Page,
        path: &[i32],
    ) -> Result<Option<i32>> {
        if leaf.ty() == NodeType::LongKeyVarRec as u8 {
            for i in 0..leaf.count()? {
                if var_indirect(&leaf, i)? {
                    let id = leaf.i32(var_off(&leaf, i)? as usize)?;
                    remove_chained(s, id)?;
                }
            }
        }
        let key = leaf_key(&leaf, 0, self.fixed_len)?;
        let prev = leaf.i32(PREV_LEAF)?;
        let next = leaf.i32(NEXT_LEAF)?;
        if prev >= 0 {
            let mut p = Page::load(s, prev)?;
            p.set_i32(NEXT_LEAF, next)?;
            p.save(s)?;
        }
        if next >= 0 {
            let mut n = Page::load(s, next)?;
            n.set_i32(PREV_LEAF, prev)?;
            n.save(s)?;
        }
        s.delete_buffer(leaf.id)?;
        match path.split_last() {
            None => Ok(None),
            Some((&parent, anc)) => Ok(Some(self.delete_child(s, anc, parent, key)?)),
        }
    }

    // ---- interior level ----

    fn new_root<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        key1: i64,
        id1: i32,
        key2: i64,
        id2: i32,
    ) -> Result<i32> {
        let mut n = new_page(s, NodeType::LongKeyInterior)?;
        n.set_count(2)?;
        put_entry(&mut n, 0, key1, id1)?;
        put_entry(&mut n, 1, key2, id2)?;
        n.save(s)?;
        Ok(n.id)
    }

    /// `keyChanged` on the last node of `path` (the parent of the node whose first key changed).
    fn key_changed<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        path: &[i32],
        old: i64,
        new: i64,
    ) -> Result<()> {
        let Some((&pid, anc)) = path.split_last() else {
            return Ok(());
        };
        let mut p = Page::load(s, pid)?;
        let Ok(index) = ikey_index(&p, old)? else {
            return Err(BtreeError::Assertion("keyChanged: key not found"));
        };
        p.set_i64(NODE_HEADER + index * INTERIOR_ENTRY, new)?;
        p.save(s)?;
        if index == 0 && !anc.is_empty() {
            self.key_changed(s, anc, old, new)?;
        }
        Ok(())
    }

    /// `LongKeyInteriorNode.insert` on node `node_id` whose ancestors are `anc`.
    fn interior_insert<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        node_id: i32,
        id: i32,
        key: i64,
    ) -> Result<i32> {
        let mut n = Page::load(s, node_id)?;
        if n.count()? == max_interior_keys(&n) {
            return self.interior_split(s, anc, n, key, id);
        }
        let Err(index) = ikey_index(&n, key)? else {
            return Err(BtreeError::Assertion("interior insert: duplicate key"));
        };
        if id == 0 {
            return Err(BtreeError::Assertion("interior insert: id 0"));
        }
        insert_entry(&mut n, index, key, id)?;
        n.save(s)?;
        if index == 0 && !anc.is_empty() {
            let k1 = ikey(&n, 1)?;
            self.key_changed(s, anc, k1, key)?;
        }
        Ok(anc.first().copied().unwrap_or(node_id))
    }

    fn interior_split<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        mut left: Page,
        new_key: i64,
        new_id: i32,
    ) -> Result<i32> {
        let mut right = new_page(s, NodeType::LongKeyInterior)?;
        let half = left.count()? / 2;
        move_keys_right(&mut left, &mut right, half)?;
        left.save(s)?;
        right.save(s)?;
        let right_key = ikey(&right, 0)?;
        if new_key < right_key {
            self.interior_insert(s, anc, left.id, new_id, new_key)?;
        } else {
            // the new node has no parent link yet: it cannot be the target of keyChanged
            self.interior_insert(s, &[], right.id, new_id, new_key)?;
        }
        let left = Page::load(s, left.id)?;
        if let Some((&parent, anc2)) = anc.split_last() {
            return self.interior_insert(s, anc2, parent, right.id, right_key);
        }
        let k0 = ikey(&left, 0)?;
        self.new_root(s, k0, left.id, right_key, right.id)
    }

    /// `deleteChild` on node `node_id` (ancestors `anc`); returns the root id.
    fn delete_child<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        node_id: i32,
        key: i64,
    ) -> Result<i32> {
        let mut n = Page::load(s, node_id)?;
        let Ok(index) = ikey_index(&n, key)? else {
            return Err(BtreeError::Assertion("deleteChild: key not found"));
        };
        if n.count()? == 2 {
            if !anc.is_empty() {
                return Err(BtreeError::Assertion("deleteChild: non-root with 2 keys"));
            }
            let other = ichild(&n, 1 - index)?;
            s.delete_buffer(n.id)?;
            return Ok(other);
        }
        delete_entry(&mut n, index)?;
        n.save(s)?;
        if index == 0 && !anc.is_empty() {
            let k0 = ikey(&n, 0)?;
            self.key_changed(s, anc, key, k0)?;
        }
        match anc.split_last() {
            Some((&parent, anc2)) => self.balance_child(s, anc2, parent, node_id),
            None => Ok(node_id),
        }
    }

    /// `balanceChild(node)` on the parent `parent_id` (ancestors `anc`).
    fn balance_child<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        parent_id: i32,
        node_id: i32,
    ) -> Result<i32> {
        let parent = Page::load(s, parent_id)?;
        let node = Page::load(s, node_id)?;
        let root = anc.first().copied().unwrap_or(parent_id);
        if node.count()? > max_interior_keys(&parent) / 2 {
            return Ok(root);
        }
        let index = id_index(&parent, ikey(&node, 0)?)?;
        if index == parent.count()? - 1 {
            if index == 0 {
                return Err(BtreeError::Assertion("balanceChild: no sibling"));
            }
            let left = ichild(&parent, index - 1)?;
            self.balance_pair(s, anc, parent, left, node_id)
        } else {
            let right = ichild(&parent, index + 1)?;
            self.balance_pair(s, anc, parent, node_id, right)
        }
    }

    fn balance_pair<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        parent: Page,
        left_id: i32,
        right_id: i32,
    ) -> Result<i32> {
        let mut left = Page::load(s, left_id)?;
        let mut right = Page::load(s, right_id)?;
        let right_key = ikey(&right, 0)?;
        let lk = left.count()?;
        let rk = right.count()?;
        let mut new_left = lk + rk;
        if new_left <= max_interior_keys(&parent) {
            move_keys_left(&mut left, &mut right, rk)?;
            left.save(s)?;
            s.delete_buffer(right.id)?;
            return self.delete_child(s, anc, parent.id, right_key);
        }
        new_left /= 2;
        if new_left < lk {
            move_keys_right(&mut left, &mut right, lk - new_left)?;
        } else if new_left > lk {
            move_keys_left(&mut left, &mut right, new_left - lk)?;
        }
        left.save(s)?;
        right.save(s)?;
        let new_right_key = ikey(&right, 0)?;
        let mut chain = anc.to_vec();
        chain.push(parent.id);
        self.key_changed(s, &chain, right_key, new_right_key)?;
        Ok(anc.first().copied().unwrap_or(parent.id))
    }
}

fn remove_chained<S: BufferStoreMut + ?Sized>(s: &mut S, id: i32) -> Result<()> {
    let mut cb = ChainedBuffer::open(s, id)?;
    cb.delete(s)?;
    Ok(())
}

#[cfg(test)]
mod tests;
