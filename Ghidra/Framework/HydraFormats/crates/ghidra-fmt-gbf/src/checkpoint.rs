//! A buffer store with transaction checkpoints, undo and redo (`db.buffers.BufferMgr` and
//! `db.buffers.IndexProvider`).
//!
//! `BufferMgr` keeps, for every buffer id, a list of versions, one per checkpoint that changed
//! the buffer. A checkpoint is closed by [`CheckpointStore::checkpoint`] (the end of a
//! transaction). [`CheckpointStore::undo`] removes the newest checkpoint, [`CheckpointStore::redo`]
//! puts it back; both also move the free list and the index count the way Java does, because the
//! saved file shows them. This port keeps only the versions (the cache and the disk cache of
//! `BufferMgr` are not needed: the memory is the cache) and follows the order in which Java
//! visits the buffers of a checkpoint, which decides the order of the free index stack.
//!
//! What is modelled besides the visible bytes: a deleted buffer keeps its bytes and hands them
//! out again when the index is allocated again in the same version chain (a buffer still held by
//! the Java cache), but a version that Java has dropped from its cache (because a newer version
//! took its buffer) hands out a zero filled buffer. That matters for byte identical results
//! because node writers do not clear what they do not use. It is exact while the Java buffer
//! cache (4 MiB, so `4 MiB / buffer size` buffers) is not exhausted; beyond that Java recycles
//! the oldest cached buffers and the stale bytes of a new buffer differ.

use std::path::Path;

use crate::{BufferFile, BufferStore, BufferStoreMut, Checkpointed, DataBuffer, GbfError, Result};

/// `BufferMgr.DEFAULT_CHECKPOINT_COUNT`.
pub const DEFAULT_CHECKPOINT_COUNT: i32 = 10;

#[derive(Debug, Clone)]
struct Node {
    /// Number of the checkpoint that wrote this version (0 is the baseline).
    cp: i32,
    empty: bool,
    data: Vec<u8>,
    /// Java still holds the buffer of this version in its memory cache.
    has_buffer: bool,
}

#[derive(Debug, Clone)]
struct Checkpoint {
    number: i32,
    /// Buffer ids in the order their first change was released.
    ids: Vec<i32>,
    /// For a checkpoint on the redo stack, the nodes (parallel to `ids`).
    parked: Vec<Node>,
}

/// A buffer store with checkpoints (`BufferMgr` without the caches).
#[derive(Debug, Clone)]
pub struct CheckpointStore {
    buffer_size: usize,
    /// Versions per buffer id, oldest first; the last one is current.
    table: Vec<Vec<Node>>,
    /// `IndexProvider`: next never used index and the stack of freed ones.
    next_index: i32,
    free: Vec<i32>,
    /// Buffers handed out by `create_buffer` and not yet released.
    pending: Vec<(i32, Vec<u8>)>,
    heads: Vec<Checkpoint>,
    redo: Vec<Checkpoint>,
    current_cp: i32,
    head_active: bool,
    max_checkpoints: i32,
    has_non_undoable_changes: bool,
    mod_count: u64,
    /// Index count of the file this store was loaded from (0 for a new store).
    source_count: i32,
    /// Open table operations: the buffers they hold, in the order they were first held, with
    /// whether the buffer still has to be added to the checkpoint's list.
    groups: std::cell::RefCell<Vec<Group>>,
}

/// One open table operation: the nodes its `NodeMgr` holds and which of them were changed.
#[derive(Debug, Clone, Default)]
struct Group {
    table: NodeTable,
    /// Buffers changed by the operation (held), with whether they still have to be added to the
    /// checkpoint's list.
    held: Vec<(i32, bool)>,
}

impl CheckpointStore {
    /// An empty store (`new BufferMgr(size, cache, DEFAULT_CHECKPOINT_COUNT)`): `buffer_size` is
    /// the payload size after `LocalBufferFile.getRecommendedBufferSize`. The undo limit is
    /// `DEFAULT_CHECKPOINT_COUNT` (the constructor adds one for the baseline, so 10 undos).
    pub fn new(buffer_size: usize) -> Self {
        Self {
            buffer_size,
            table: Vec::new(),
            next_index: 0,
            free: Vec::new(),
            pending: Vec::new(),
            heads: vec![Checkpoint {
                number: 0,
                ids: Vec::new(),
                parked: Vec::new(),
            }],
            redo: Vec::new(),
            current_cp: 0,
            head_active: false,
            max_checkpoints: DEFAULT_CHECKPOINT_COUNT + 1,
            has_non_undoable_changes: false,
            mod_count: 0,
            source_count: 0,
            groups: std::cell::RefCell::new(Vec::new()),
        }
    }

    /// A store that starts from the buffers of `source` (`new BufferMgr(bufferFile)`): every
    /// buffer is the baseline version. `free` is the source's free list.
    pub fn from_store<S: BufferStore + ?Sized>(source: &S, free: &[i32]) -> Result<Self> {
        let mut s = Self::new(source.buffer_size());
        let count = source.index_count();
        for id in 0..count {
            let b = source.get_buffer(id)?;
            let node = match b.data {
                Some(data) if !b.empty => Node {
                    cp: 0,
                    empty: false,
                    data,
                    has_buffer: true,
                },
                _ => Node {
                    cp: 0,
                    empty: true,
                    data: vec![0; s.buffer_size],
                    has_buffer: false,
                },
            };
            s.table.push(vec![node]);
            s.heads[0].ids.push(id);
        }
        s.next_index = count;
        s.free = free.to_vec();
        s.source_count = count;
        Ok(s)
    }

    /// Payload size of every buffer.
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Ids on the free stack, in stack order (most recently freed last).
    pub fn free_ids(&self) -> &[i32] {
        &self.free
    }

    /// Number of buffers in use (not on the free stack).
    pub fn in_use_count(&self) -> usize {
        self.next_index as usize - self.free.len()
    }

    // ---- IndexProvider --------------------------------------------------------------------

    fn allocate_index(&mut self) -> i32 {
        if let Some(i) = self.free.pop() {
            return i;
        }
        let i = self.next_index;
        self.next_index += 1;
        i
    }

    /// `IndexProvider.allocateIndex(int)`.
    fn allocate_specific(&mut self, index: i32) -> bool {
        if index >= self.next_index {
            for i in self.next_index..index {
                self.free.push(i);
            }
            self.next_index = index + 1;
            return true;
        }
        match self.free.iter().position(|&f| f == index) {
            Some(p) => {
                self.free.remove(p);
                true
            }
            None => false,
        }
    }

    fn free_index(&mut self, index: i32) {
        self.free.push(index);
    }

    fn truncate(&mut self, new_count: i32) {
        if new_count >= self.next_index {
            return;
        }
        self.next_index = new_count;
        self.free.retain(|&f| f < new_count);
        self.table.truncate(new_count as usize);
        self.heads[0].ids.retain(|&i| i < new_count);
    }

    // ---- checkpoints ----------------------------------------------------------------------

    /// True when no buffer changed since the last checkpoint (`atCheckpoint`).
    pub fn at_checkpoint(&self) -> bool {
        !self.head_active
    }

    /// True when unsaved changes exist, or some were packed beyond undo (`isChanged`).
    pub fn is_changed(&self) -> bool {
        self.current_cp != 0 || self.head_active || self.has_non_undoable_changes
    }

    /// Number of buffer releases that changed something (`getModCount`).
    pub fn mod_count(&self) -> u64 {
        self.mod_count
    }

    /// Checkpoints that undo can go back through (`getAvailableUndoCount`; the open one counts).
    pub fn available_undo_count(&self) -> usize {
        self.heads.len() - 1
    }

    /// Checkpoints on the redo stack.
    pub fn available_redo_count(&self) -> usize {
        self.redo.len()
    }

    /// `hasUndoCheckpoints`.
    pub fn has_undo_checkpoints(&self) -> bool {
        self.heads.len() > 1
    }

    /// `hasRedoCheckpoints`.
    pub fn has_redo_checkpoints(&self) -> bool {
        !self.redo.is_empty()
    }

    /// `getMaxUndos` (Java returns the checkpoint limit, which is one more than the undo count).
    pub fn max_checkpoints(&self) -> i32 {
        self.max_checkpoints
    }

    fn start_checkpoint(&mut self) {
        self.redo.clear();
        self.current_cp += 1;
        self.heads.push(Checkpoint {
            number: self.current_cp,
            ids: Vec::new(),
            parked: Vec::new(),
        });
        self.head_active = true;
        self.pack_checkpoints();
    }

    /// `packCheckpoints`: the oldest checkpoint becomes the baseline.
    fn pack_checkpoints(&mut self) {
        if self.heads.len() as i32 <= self.max_checkpoints {
            return;
        }
        let cp = self.heads.remove(1);
        for &id in &cp.ids {
            let versions = &mut self.table[id as usize];
            if let Some(k) = versions.iter().position(|n| n.cp == cp.number) {
                // the version before it is the old baseline, which is discarded
                let at = if k > 0 {
                    versions.remove(k - 1);
                    k - 1
                } else {
                    0
                };
                versions[at].cp = 0;
            }
            self.heads[0].ids.push(id);
        }
        self.has_non_undoable_changes = true;
    }

    /// `checkpoint`: end the transaction. False when nothing changed since the last one.
    pub fn checkpoint(&mut self) -> bool {
        if !self.head_active {
            return false;
        }
        self.head_active = false;
        true
    }

    /// `setMaxUndos`: `max_undos < 0` restores the default. Packs the oldest checkpoints when the
    /// new limit is smaller and clears the redo stack.
    pub fn set_max_undos(&mut self, max_undos: i32) {
        self.max_checkpoints = if max_undos < 0 {
            DEFAULT_CHECKPOINT_COUNT
        } else {
            max_undos + 1
        };
        while self.heads.len() as i32 > self.max_checkpoints {
            self.pack_checkpoints();
        }
        self.redo.clear();
    }

    /// `clearCheckpoints`: close the open checkpoint and pack everything into the baseline.
    /// Java passes the checkpoint limit where an undo count is expected, so the limit grows by
    /// one every time this is called; that is kept.
    pub fn clear_checkpoints(&mut self) {
        let old = self.max_checkpoints;
        self.checkpoint();
        self.set_max_undos(0);
        self.set_max_undos(old);
    }

    /// `undo(redoable)`: remove the newest checkpoint (the open one first). False when only the
    /// baseline is left.
    ///
    /// # Errors
    /// [`GbfError::Invalid`] when the version lists are inconsistent.
    pub fn undo(&mut self, redoable: bool) -> Result<bool> {
        let ix = self.heads.len() - 1;
        if ix < 1 {
            return Ok(false);
        }
        let mut cp = self.heads.remove(ix);
        let mut revised = self.next_index;
        let mut parked: Vec<Node> = Vec::with_capacity(cp.ids.len());
        for &id in cp.ids.iter().rev() {
            let versions = self
                .table
                .get_mut(id as usize)
                .ok_or(GbfError::Invalid("undo: unknown buffer"))?;
            let node = versions
                .pop()
                .ok_or(GbfError::Invalid("undo: no version to remove"))?;
            if node.cp != cp.number {
                return Err(GbfError::Invalid("undo: version is not in the checkpoint"));
            }
            match versions.last().map(|o| o.empty) {
                None => {
                    // unknown before this checkpoint
                    if self.source_count == 0 || id >= self.source_count {
                        revised = revised.min(id);
                    } else if !node.empty {
                        self.free_index(id);
                    }
                }
                Some(old_empty) => {
                    if node.empty {
                        if !old_empty && !self.allocate_specific(id) {
                            return Err(GbfError::Invalid("undo: index not free"));
                        }
                    } else if old_empty {
                        self.free_index(id);
                    }
                }
            }
            parked.push(node);
        }
        self.truncate(revised);
        if redoable {
            parked.reverse();
            cp.parked = parked;
            self.redo.push(cp);
        } else {
            self.redo.clear();
        }
        self.current_cp = self.heads[ix - 1].number;
        self.head_active = false;
        Ok(true)
    }

    /// `redo`: put the newest undone checkpoint back. False when the redo stack is empty.
    ///
    /// # Errors
    /// [`GbfError::Invalid`] when the free list does not match.
    pub fn redo(&mut self) -> Result<bool> {
        let Some(mut cp) = self.redo.pop() else {
            return Ok(false);
        };
        let nodes = std::mem::take(&mut cp.parked);
        for (&id, node) in cp.ids.iter().zip(nodes).rev() {
            let known = self
                .table
                .get(id as usize)
                .and_then(|v| v.last())
                .map(|n| n.empty);
            match known {
                None => {
                    if !self.allocate_specific(id) {
                        return Err(GbfError::Invalid("redo: index not free"));
                    }
                    if node.empty {
                        self.free_index(id);
                    }
                }
                Some(cur_empty) => {
                    if node.empty {
                        if !cur_empty {
                            self.free_index(id);
                        }
                    } else if cur_empty && !self.allocate_specific(id) {
                        return Err(GbfError::Invalid("redo: index not free"));
                    }
                }
            }
            if self.table.len() <= id as usize {
                self.table.resize_with(id as usize + 1, Vec::new);
            }
            self.table[id as usize].push(node);
        }
        self.current_cp = cp.number;
        self.heads.push(cp);
        self.head_active = false;
        Ok(true)
    }

    // ---- buffer access --------------------------------------------------------------------

    fn current(&self, id: i32) -> Option<&Node> {
        usize::try_from(id)
            .ok()
            .and_then(|i| self.table.get(i))
            .and_then(|v| v.last())
    }

    /// Append `id` to the open checkpoint's list.
    fn push_id(&mut self, id: i32) {
        let cur = self.current_cp;
        if let Some(head) = self.heads.last_mut().filter(|h| h.number == cur) {
            head.ids.push(id);
        }
    }

    /// A buffer that was held by an open operation is released now (it is deleted or written
    /// directly): it takes its place in the checkpoint's list at this moment, and leaves the
    /// operation's node table.
    fn release_held_now(&mut self, id: i32) {
        let mut hit = None;
        for g in self.groups.get_mut().iter_mut() {
            if let Some(p) = g.held.iter().position(|&(h, _)| h == id) {
                hit = Some(g.held.remove(p).1);
                g.table.remove(id);
                break;
            }
        }
        if hit == Some(true) {
            self.push_id(id);
        }
    }

    /// `releaseDirtyBuffer`: store `data` as the current version of `id`.
    fn release_dirty(&mut self, id: i32, data: Vec<u8>, empty: bool, held: bool) {
        self.mod_count += 1;
        if !self.head_active {
            self.start_checkpoint();
        }
        let i = id as usize;
        if self.table.len() <= i {
            self.table.resize_with(i + 1, Vec::new);
        }
        let cur_cp = self.current_cp;
        let held_slot =
            (held && !self.groups.get_mut().is_empty()).then(|| self.groups.get_mut().len() - 1);
        let versions = &mut self.table[i];
        match versions.last_mut() {
            Some(node) if node.cp == cur_cp => {
                node.empty = empty;
                node.data = data;
                node.has_buffer = true;
                match held_slot {
                    Some(g) => {
                        let group = &mut self.groups.get_mut()[g];
                        if !group.held.iter().any(|&(h, _)| h == id) {
                            group.held.push((id, false));
                        }
                        group.table.note(id);
                    }
                    None => self.release_held_now(id),
                }
            }
            existing => {
                if let Some(old) = existing {
                    // a newer version takes the buffer of the old one
                    old.has_buffer = false;
                }
                versions.push(Node {
                    cp: cur_cp,
                    empty,
                    data,
                    has_buffer: true,
                });
                // with a limit of one checkpoint Java packs the new, empty checkpoint away at
                // once and writes into a detached list that undo can never reach
                match held_slot {
                    Some(g) => {
                        let group = &mut self.groups.get_mut()[g];
                        group.held.push((id, true));
                        group.table.note(id);
                    }
                    None => self.push_id(id),
                }
            }
        }
        if empty {
            self.free_index(id);
        }
    }

    /// `put_buffer` / `put_held`.
    fn put(&mut self, buf: &DataBuffer, held: bool) -> Result<()> {
        if let Some(p) = self.pending.iter().position(|(i, _)| *i == buf.id) {
            self.pending.remove(p);
        } else if buf.id < 0 || buf.id >= self.next_index {
            return Err(GbfError::IndexOutOfRange {
                index: buf.id,
                count: self.next_index,
            });
        }
        match &buf.data {
            Some(d) if d.len() != self.buffer_size => Err(GbfError::BadBufferSize {
                expected: self.buffer_size,
                actual: d.len(),
            }),
            Some(d) => {
                self.release_dirty(buf.id, d.clone(), buf.empty, held);
                Ok(())
            }
            None => {
                let stale = self
                    .current(buf.id)
                    .map_or_else(|| vec![0; self.buffer_size], |n| n.data.clone());
                self.release_dirty(buf.id, stale, true, held);
                Ok(())
            }
        }
    }

    /// Write the store as a new buffer file at `path` (what `BufferMgr.saveAs` produces: the
    /// non-empty buffers, the free stack as the file's free list).
    ///
    /// # Errors
    /// File errors.
    pub fn save_to_file(&self, path: impl AsRef<Path>, file_id: i64) -> Result<()> {
        let mut out = BufferFile::create(path, self.buffer_size, file_id)?;
        for id in 0..self.next_index {
            match self.current(id) {
                Some(n) if !n.empty => out.put(&DataBuffer::new(id, n.data.clone()), id)?,
                _ => out.put(&DataBuffer::empty(id), id)?,
            }
        }
        out.set_free_indexes(&self.free);
        out.flush()?;
        out.close()
    }
}

impl BufferStore for CheckpointStore {
    fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    fn index_count(&self) -> i32 {
        self.next_index
    }

    fn note_node(&self, id: i32) {
        if let Some(g) = self.groups.borrow_mut().last_mut() {
            g.table.note(id);
        }
    }

    fn get_buffer(&self, index: i32) -> Result<DataBuffer> {
        if let Some((_, d)) = self.pending.iter().find(|(i, _)| *i == index) {
            return Ok(DataBuffer::new(index, d.clone()));
        }
        match self.current(index) {
            Some(n) if n.empty => Ok(DataBuffer::empty(index)),
            Some(n) => Ok(DataBuffer::new(index, n.data.clone())),
            None => Err(GbfError::IndexOutOfRange {
                index,
                count: self.next_index,
            }),
        }
    }
}

impl BufferStoreMut for CheckpointStore {
    fn create_buffer(&mut self) -> Result<i32> {
        let id = self.allocate_index();
        let data = match self.current(id) {
            Some(n) if n.has_buffer => n.data.clone(),
            _ => vec![0; self.buffer_size],
        };
        self.pending.retain(|(i, _)| *i != id);
        self.pending.push((id, data));
        Ok(id)
    }

    fn put_buffer(&mut self, buf: &DataBuffer) -> Result<()> {
        self.put(buf, false)
    }

    fn delete_buffer(&mut self, id: i32) -> Result<()> {
        let node = self.current(id).ok_or(GbfError::IndexOutOfRange {
            index: id,
            count: self.next_index,
        })?;
        if node.empty {
            return Ok(());
        }
        let data = node.data.clone();
        if let Some(g) = self.groups.get_mut().last_mut() {
            g.table.remove(id);
        }
        self.release_dirty(id, data, true, false);
        Ok(())
    }

    fn clear_checkpoints(&mut self) {
        CheckpointStore::clear_checkpoints(self);
    }

    fn put_held(&mut self, buf: &DataBuffer) -> Result<()> {
        self.put(buf, true)
    }

    fn requires_transaction(&self) -> bool {
        true
    }

    fn begin_group(&mut self) {
        self.groups.get_mut().push(Group::default());
    }

    fn end_group(&mut self) {
        let Some(group) = self.groups.get_mut().pop() else {
            return;
        };
        for id in group.table.in_slot_order() {
            if group.held.iter().any(|&(h, pending)| h == id && pending) {
                self.push_id(id);
            }
        }
    }
}

impl Checkpointed for CheckpointStore {
    fn at_checkpoint(&self) -> bool {
        CheckpointStore::at_checkpoint(self)
    }
    fn checkpoint(&mut self) -> bool {
        CheckpointStore::checkpoint(self)
    }
    fn undo(&mut self, redoable: bool) -> Result<bool> {
        CheckpointStore::undo(self, redoable)
    }
    fn redo(&mut self) -> Result<bool> {
        CheckpointStore::redo(self)
    }
    fn has_undo_checkpoints(&self) -> bool {
        CheckpointStore::has_undo_checkpoints(self)
    }
    fn has_redo_checkpoints(&self) -> bool {
        CheckpointStore::has_redo_checkpoints(self)
    }
    fn available_undo_count(&self) -> usize {
        CheckpointStore::available_undo_count(self)
    }
    fn available_redo_count(&self) -> usize {
        CheckpointStore::available_redo_count(self)
    }
    fn set_max_undos(&mut self, max_undos: i32) {
        CheckpointStore::set_max_undos(self, max_undos);
    }
    fn is_changed(&self) -> bool {
        CheckpointStore::is_changed(self)
    }
    fn mod_count(&self) -> u64 {
        CheckpointStore::mod_count(self)
    }
}

/// `NodeMgr.NodeTable`: the nodes one table operation holds. An open addressing table of ids
/// that starts with 8 slots, doubles when one more entry would fill more than half of it, probes
/// linearly, removes with a backward shift, and is walked in slot order by `releaseNodes`.
#[derive(Debug, Clone, Default)]
struct NodeTable {
    slots: Vec<Option<i32>>,
    size: usize,
}

impl NodeTable {
    fn slot(id: i32, mask: usize) -> usize {
        let h = id.wrapping_mul(0x9E37_79B1_u32 as i32);
        ((h ^ (((h as u32) >> 15) as i32)) as usize) & mask
    }

    fn contains(&self, id: i32) -> bool {
        if self.size == 0 {
            return false;
        }
        let mask = self.slots.len() - 1;
        let mut i = Self::slot(id, mask);
        loop {
            match self.slots[i] {
                None => return false,
                Some(t) if t == id => return true,
                Some(_) => i = (i + 1) & mask,
            }
        }
    }

    /// Add `id` when the table does not hold it yet.
    fn note(&mut self, id: i32) {
        if self.contains(id) {
            return;
        }
        if self.slots.is_empty() {
            self.slots = vec![None; 8];
        } else if (self.size + 1) * 2 > self.slots.len() {
            let old = std::mem::take(&mut self.slots);
            self.slots = vec![None; old.len() * 2];
            self.size = 0;
            for t in old.into_iter().flatten() {
                self.insert(t);
            }
        }
        self.insert(id);
    }

    fn insert(&mut self, id: i32) {
        let mask = self.slots.len() - 1;
        let mut i = Self::slot(id, mask);
        while self.slots[i].is_some_and(|t| t != id) {
            i = (i + 1) & mask;
        }
        if self.slots[i].is_none() {
            self.size += 1;
        }
        self.slots[i] = Some(id);
    }

    fn remove(&mut self, id: i32) {
        if self.size == 0 {
            return;
        }
        let mask = self.slots.len() - 1;
        let mut i = Self::slot(id, mask);
        loop {
            match self.slots[i] {
                None => return,
                Some(t) if t == id => break,
                Some(_) => i = (i + 1) & mask,
            }
        }
        self.slots[i] = None;
        self.size -= 1;
        let mut j = i;
        loop {
            j = (j + 1) & mask;
            let Some(t) = self.slots[j] else {
                return;
            };
            let k = Self::slot(t, mask);
            if (j > i && (k <= i || k > j)) || (j < i && (k <= i && k > j)) {
                self.slots[i] = self.slots[j].take();
                i = j;
            }
        }
    }

    fn in_slot_order(&self) -> impl Iterator<Item = i32> + '_ {
        self.slots.iter().flatten().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(store: &CheckpointStore, fill: u8) -> DataBuffer {
        DataBuffer::new(0, vec![fill; store.buffer_size()])
    }

    /// Create a buffer holding `fill` and return its id.
    fn add(store: &mut CheckpointStore, fill: u8) -> i32 {
        let id = store.create_buffer().unwrap();
        let mut b = page(store, fill);
        b.id = id;
        store.put_buffer(&b).unwrap();
        id
    }

    #[test]
    fn undo_removes_created_buffers_and_redo_brings_them_back() {
        let mut s = CheckpointStore::new(64);
        let a = add(&mut s, 1);
        assert!(s.checkpoint());
        let b = add(&mut s, 2);
        let c = add(&mut s, 3);
        assert!(s.checkpoint());
        assert_eq!((a, b, c), (0, 1, 2));
        assert_eq!(s.index_count(), 3);

        assert!(s.undo(true).unwrap());
        assert_eq!(s.index_count(), 1);
        assert_eq!(s.available_redo_count(), 1);
        assert!(s.redo().unwrap());
        assert_eq!(s.index_count(), 3);
        assert_eq!(s.get_buffer(1).unwrap().data.unwrap()[0], 2);
        assert_eq!(s.get_buffer(2).unwrap().data.unwrap()[0], 3);
    }

    #[test]
    fn undo_of_a_delete_takes_the_index_off_the_free_stack() {
        let mut s = CheckpointStore::new(64);
        for f in 1..=3 {
            add(&mut s, f);
        }
        assert!(s.checkpoint());
        s.delete_buffer(1).unwrap();
        assert!(s.checkpoint());
        assert_eq!(s.free_ids(), &[1]);
        assert!(s.undo(true).unwrap());
        assert!(s.free_ids().is_empty());
        assert_eq!(s.get_buffer(1).unwrap().data.unwrap()[0], 2);
        assert!(s.redo().unwrap());
        assert_eq!(s.free_ids(), &[1]);
        assert!(s.get_buffer(1).unwrap().empty);
    }

    #[test]
    fn freed_indexes_are_handed_out_last_in_first_out() {
        let mut s = CheckpointStore::new(64);
        for f in 1..=4 {
            add(&mut s, f);
        }
        s.checkpoint();
        s.delete_buffer(1).unwrap();
        s.delete_buffer(3).unwrap();
        assert_eq!(s.create_buffer().unwrap(), 3);
        assert_eq!(s.create_buffer().unwrap(), 1);
        assert_eq!(s.create_buffer().unwrap(), 4);
    }

    #[test]
    fn rollback_discards_the_redo_stack_and_the_open_checkpoint() {
        let mut s = CheckpointStore::new(64);
        add(&mut s, 1);
        s.checkpoint();
        add(&mut s, 2);
        s.checkpoint();
        assert!(s.undo(true).unwrap());
        assert_eq!(s.available_redo_count(), 1);
        add(&mut s, 9); // opens a new checkpoint: the redo stack goes
        assert_eq!(s.available_redo_count(), 0);
        assert!(!s.at_checkpoint());
        assert!(s.undo(false).unwrap());
        assert!(s.at_checkpoint());
        assert_eq!(s.index_count(), 1);
        assert_eq!(s.available_redo_count(), 0);
    }

    #[test]
    fn the_oldest_checkpoint_is_packed_into_the_baseline() {
        let mut s = CheckpointStore::new(64);
        s.set_max_undos(2);
        let id = add(&mut s, 1);
        s.checkpoint();
        for fill in 2..=5 {
            let mut b = page(&s, fill);
            b.id = id;
            s.put_buffer(&b).unwrap();
            s.checkpoint();
        }
        // three checkpoints can still be undone, the older ones are the baseline now
        assert_eq!(s.available_undo_count(), 2);
        assert!(s.undo(true).unwrap());
        assert!(s.undo(true).unwrap());
        assert!(!s.undo(true).unwrap());
        assert_eq!(s.get_buffer(id).unwrap().data.unwrap()[0], 3);
        assert!(s.is_changed());
    }

    #[test]
    fn a_limit_of_one_checkpoint_keeps_no_undo_history() {
        let mut s = CheckpointStore::new(64);
        s.set_max_undos(0);
        add(&mut s, 1);
        assert!(s.checkpoint());
        assert!(!s.has_undo_checkpoints());
        assert!(!s.undo(true).unwrap());
    }

    #[test]
    fn clear_checkpoints_raises_the_limit_by_one() {
        let mut s = CheckpointStore::new(64);
        assert_eq!(s.max_checkpoints(), 11);
        s.clear_checkpoints();
        assert_eq!(s.max_checkpoints(), 12);
    }

    #[test]
    fn a_buffer_created_after_a_delete_still_holds_the_old_bytes() {
        // `NodeMgr` writers do not clear what they do not use, so Java's cached buffer shows
        let mut s = CheckpointStore::new(64);
        add(&mut s, 7);
        s.checkpoint();
        s.delete_buffer(0).unwrap();
        s.checkpoint();
        let id = s.create_buffer().unwrap();
        assert_eq!(id, 0);
        assert_eq!(s.get_buffer(0).unwrap().data.unwrap()[3], 7);
        // after an undo the older version has no cached buffer: zeros
        let mut t = CheckpointStore::new(64);
        add(&mut t, 7);
        t.checkpoint();
        t.delete_buffer(0).unwrap();
        t.checkpoint();
        add(&mut t, 8); // reuses 0 in a third checkpoint
        t.checkpoint();
        assert!(t.undo(true).unwrap());
        assert_eq!(t.create_buffer().unwrap(), 0);
        assert_eq!(t.get_buffer(0).unwrap().data.unwrap()[3], 0);
    }

    #[test]
    fn node_table_walks_in_slot_order_with_linear_probing() {
        // small ids all hash to the last of 8 slots, so later ones wrap around to the front
        let mut t = NodeTable::default();
        for id in [1, 6, 7] {
            t.note(id);
        }
        assert_eq!(t.in_slot_order().collect::<Vec<_>>(), [6, 7, 1]);
        // removing the first entry shifts the wrapped ones back
        t.remove(1);
        assert_eq!(t.in_slot_order().collect::<Vec<_>>(), [7, 6]);
        // the table doubles when one more entry would fill more than half of it
        let mut t = NodeTable::default();
        for id in 0..4 {
            t.note(id);
        }
        assert_eq!(t.slots.len(), 8);
        t.note(4);
        assert_eq!(t.slots.len(), 16);
        assert_eq!(t.size, 5);
    }
}
