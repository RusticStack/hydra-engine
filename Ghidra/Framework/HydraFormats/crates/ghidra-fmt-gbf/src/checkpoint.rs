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
//! What is modelled besides the visible bytes is the memory cache of `BufferMgr`, because node
//! writers do not clear what they do not use and so the bytes of a buffer that Java recycles
//! show up in the unused part of a new page. `BufferMgr` allocates new buffer objects until the
//! cache is full (`cacheSize < maxCacheSize`, zero filled); after that it reuses, in this order,
//! a buffer on the free stack (pushed when a checkpoint node is disposed: rollback, packing, redo
//! dropped), then the buffer of the least recently used cached node. A deleted node keeps its
//! buffer in the cache, so an index that is allocated again gets the old bytes back while that
//! buffer is still there. [`CacheModel`] keeps the LRU order, the free stack and the allocation
//! count; the order in which nodes enter the cache follows `NodeMgr` (nodes of a table operation
//! are held until the operation ends and are returned in the slot order of its node table).
//!
//! `SharedPages` (page interning by content, Hydra) can additionally hand a freed array with
//! the content of an interned page to the next new buffer. It depends on the pages other views
//! read and on garbage collection, so it is not modelled: byte identity is stated for
//! `-Dhydra.db.sharedPages=false`.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::{BufferFile, BufferStore, BufferStoreMut, Checkpointed, DataBuffer, GbfError, Result};

/// `BufferMgr.DEFAULT_CHECKPOINT_COUNT`.
pub const DEFAULT_CHECKPOINT_COUNT: i32 = 10;

#[derive(Debug, Clone)]
struct Node {
    /// Number of the checkpoint that wrote this version (0 is the baseline).
    cp: i32,
    /// Identity of the version (`BufferNode`), unique in the store.
    serial: u64,
    empty: bool,
    data: Vec<u8>,
}

/// Key of a version in the cache model: buffer id and the serial number of the version (a
/// version keeps it when packing renumbers its checkpoint).
type Key = (i32, u64);

/// `BufferMgr.DEFAULT_CACHE_SIZE`.
const DEFAULT_CACHE_BYTES: usize = 4 * 1024 * 1024;
/// `BufferMgr.MINIMUM_CACHE_SIZE`.
const MINIMUM_CACHE_BYTES: usize = 64 * 1024;

/// The memory cache of `BufferMgr`: which versions hold a buffer object, in least recently used
/// order, the stack of free buffer objects (their bytes) and how many were allocated.
#[derive(Debug, Clone, Default)]
struct CacheModel {
    /// `maxCacheSize`: number of buffer objects the cache may allocate.
    max: usize,
    /// `cacheSize`: buffer objects allocated so far.
    size: usize,
    /// `freeBuffers`: bytes of the buffer objects on the stack, newest last.
    free: Vec<Vec<u8>>,
    clock: u64,
    /// Versions in the cache by recency (the smallest stamp is the oldest).
    lru: BTreeMap<u64, Key>,
    stamp: HashMap<Key, u64>,
    /// `cacheHits` / `cacheMisses` of the buffer manager (loads of a stored node).
    hits: u64,
    misses: u64,
}

impl CacheModel {
    fn contains(&self, k: Key) -> bool {
        self.stamp.contains_key(&k)
    }

    /// `removeFromCache`.
    fn remove(&mut self, k: Key) -> bool {
        match self.stamp.remove(&k) {
            Some(t) => {
                self.lru.remove(&t);
                true
            }
            None => false,
        }
    }

    /// `returnToCache` / move to the top: `k` becomes the most recently used version.
    fn touch(&mut self, k: Key) {
        self.remove(k);
        self.clock += 1;
        self.lru.insert(self.clock, k);
        self.stamp.insert(k, self.clock);
    }

    fn pop_oldest(&mut self) -> Option<Key> {
        let (_, k) = self.lru.pop_first()?;
        self.stamp.remove(&k);
        Some(k)
    }
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
    next_serial: u64,
    head_active: bool,
    /// A table operation wrote a page but Java would only release it, and so start the
    /// checkpoint, when the operation ends (versions are written for checkpoint `current_cp + 1`).
    start_pending: bool,
    max_checkpoints: i32,
    has_non_undoable_changes: bool,
    mod_count: u64,
    /// Index count of the file this store was loaded from (0 for a new store).
    source_count: i32,
    /// Open table operations: the buffers they hold, in the order they were first held, with
    /// whether the buffer still has to be added to the checkpoint's list.
    groups: std::cell::RefCell<Vec<Group>>,
    /// The memory cache of the buffer manager (see the module notes).
    cache: std::cell::RefCell<CacheModel>,
}

/// One open table operation: the nodes its `NodeMgr` holds and which of them were changed.
#[derive(Debug, Clone, Default)]
struct Group {
    table: NodeTable,
    /// Buffers changed by the operation (held), with whether they still have to be added to the
    /// checkpoint's list.
    held: Vec<(i32, bool)>,
    /// Buffers of the operation that are out of the cache until it ends (`NodeMgr` keeps them
    /// locked), in the order they were taken.
    taken: Vec<i32>,
    taken_set: std::collections::HashSet<i32>,
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
            next_serial: 0,
            head_active: false,
            start_pending: false,
            max_checkpoints: DEFAULT_CHECKPOINT_COUNT + 1,
            has_non_undoable_changes: false,
            mod_count: 0,
            source_count: 0,
            groups: std::cell::RefCell::new(Vec::new()),
            cache: std::cell::RefCell::new(CacheModel {
                max: DEFAULT_CACHE_BYTES / buffer_size.max(1),
                ..CacheModel::default()
            }),
        }
    }

    fn serial(&mut self) -> u64 {
        self.next_serial += 1;
        self.next_serial
    }

    /// The size of the memory cache in bytes (`new BufferMgr(.., approxCacheSize, ..)`; Java
    /// raises anything below 64 KiB to 64 KiB). It decides when buffers start to be recycled.
    pub fn set_cache_bytes(&mut self, bytes: usize) {
        self.cache.get_mut().max = bytes.max(MINIMUM_CACHE_BYTES) / self.buffer_size.max(1);
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
                    serial: s.serial(),
                    empty: false,
                    data,
                },
                _ => Node {
                    cp: 0,
                    serial: s.serial(),
                    empty: true,
                    data: vec![0; s.buffer_size],
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

    /// The memory cache as `OracleTx` prints it (a debugging aid for the differential tests):
    /// the cached versions as `id@checkpoint`, most recently used first, the number of buffer
    /// objects allocated and the size of the free stack.
    pub fn cache_dump(&self) -> String {
        // `Arrays.hashCode(byte[])`
        fn hash(d: &[u8]) -> String {
            let h = d.iter().fold(1_i32, |h, &b| {
                h.wrapping_mul(31).wrapping_add(i32::from(b as i8))
            });
            format!("{h:x}")
        }
        let c = self.cache.borrow();
        let mut out = String::from("cache [");
        let mut first = true;
        for &(id, serial) in c.lru.values().rev() {
            if !first {
                out.push(' ');
            }
            first = false;
            let h = self.data_of((id, serial)).map_or_else(String::new, hash);
            let cp = self.cp_of((id, serial)).unwrap_or(-1);
            out.push_str(&format!("{id}@{cp}:{h}"));
        }
        let free: Vec<String> = c.free.iter().map(|d| hash(d)).collect();
        out.push_str(&format!(
            "] size={} free=[{}] misses={}",
            c.size,
            free.join(" "),
            c.misses
        ));
        out
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
        self.start_pending = false;
        self.dispose_redo();
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
        // Java walks the checkpoint list newest first
        for &id in cp.ids.iter().rev() {
            let versions = &mut self.table[id as usize];
            if let Some(k) = versions.iter().position(|n| n.cp == cp.number) {
                // the version before it is the old baseline, which is discarded
                let dropped = (k > 0).then(|| versions.remove(k - 1));
                let at = k.saturating_sub(1);
                versions[at].cp = 0;
                if let Some(old) = dropped {
                    self.dispose((id, old.serial), &old.data);
                }
            }
        }
        self.heads[0].ids.extend(cp.ids.iter().copied());
        self.has_non_undoable_changes = true;
    }

    /// `disposeNode`: a version leaves the checkpoint lists; the buffer it holds goes to the free
    /// stack.
    fn dispose(&mut self, key: Key, data: &[u8]) {
        let c = self.cache.get_mut();
        if c.remove(key) {
            c.free.push(data.to_vec());
        }
    }

    /// `disposeRedoCheckpoints`.
    fn dispose_redo(&mut self) {
        let redo = std::mem::take(&mut self.redo);
        for cp in &redo {
            for (&id, node) in cp.ids.iter().zip(&cp.parked).rev() {
                self.dispose((id, node.serial), &node.data);
            }
        }
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
        self.dispose_redo();
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
        parked.reverse();
        if redoable {
            cp.parked = parked;
            self.redo.push(cp);
        } else {
            // `disposeNodeList`, then `disposeRedoCheckpoints`
            for (&id, node) in cp.ids.iter().zip(&parked).rev() {
                self.dispose((id, node.serial), &node.data);
            }
            self.dispose_redo();
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

    /// The bytes of version `k`, wherever it is (version list or redo stack).
    fn data_of(&self, k: Key) -> Option<&[u8]> {
        let live = self
            .table
            .get(usize::try_from(k.0).ok()?)
            .and_then(|v| v.iter().find(|n| n.serial == k.1));
        live.or_else(|| {
            self.redo
                .iter()
                .flat_map(|c| c.ids.iter().zip(&c.parked))
                .find(|(id, n)| **id == k.0 && n.serial == k.1)
                .map(|(_, n)| n)
        })
        .map(|n| n.data.as_slice())
    }

    /// The checkpoint number of a version (debugging aid).
    fn cp_of(&self, k: Key) -> Option<i32> {
        self.table
            .get(usize::try_from(k.0).ok()?)
            .and_then(|v| v.iter().find(|n| n.serial == k.1))
            .map(|n| n.cp)
            .or_else(|| {
                self.redo
                    .iter()
                    .flat_map(|c| c.ids.iter().zip(&c.parked))
                    .find(|(id, n)| **id == k.0 && n.serial == k.1)
                    .map(|(_, n)| n.cp)
            })
    }

    /// `getCacheBuffer`: a new zero filled buffer while the cache is not full, then the top of
    /// the free stack, then the buffer of the least recently used cached version (its bytes stay).
    fn cache_buffer(&self, cache: &mut CacheModel) -> Result<Vec<u8>> {
        if cache.size < cache.max {
            cache.size += 1;
            return Ok(vec![0; self.buffer_size]);
        }
        if let Some(b) = cache.free.pop() {
            return Ok(b);
        }
        let k = cache
            .pop_oldest()
            .ok_or(GbfError::Invalid("Out of cache buffer space"))?;
        Ok(self
            .data_of(k)
            .map_or_else(|| vec![0; self.buffer_size], <[u8]>::to_vec))
    }

    /// `getBufferNode(id, true)` followed by returning the buffer: the version is loaded when it
    /// is not in the cache (which may recycle another one) and becomes the most recently used.
    fn access(&self, key: Key) -> Result<()> {
        let mut c = self.cache.borrow_mut();
        if c.contains(key) {
            c.hits += 1;
        } else {
            c.misses += 1;
            self.cache_buffer(&mut c)?;
        }
        c.touch(key);
        Ok(())
    }

    /// `getBuffer` and the release that follows it, for a page the caller reads once: inside a
    /// table operation a node the operation holds already is not asked for again (`NodeMgr`
    /// keeps its nodes), anything else (a chained buffer) goes through the cache.
    fn read(&self, id: i32, serial: u64) -> Result<()> {
        if self
            .groups
            .borrow()
            .last()
            .is_some_and(|g| g.taken_set.contains(&id))
        {
            return Ok(());
        }
        self.access((id, serial))
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
                if g.taken_set.remove(&id) {
                    g.taken.retain(|&t| t != id);
                }
                break;
            }
            if g.taken_set.remove(&id) {
                g.taken.retain(|&t| t != id);
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
        let held_slot =
            (held && !self.groups.get_mut().is_empty()).then(|| self.groups.get_mut().len() - 1);
        if !self.head_active {
            if held_slot.is_some() {
                // `releaseNodes` releases the page, and starts the checkpoint, at the end
                self.start_pending = true;
            } else {
                self.start_checkpoint();
            }
        }
        let i = id as usize;
        if self.table.len() <= i {
            self.table.resize_with(i + 1, Vec::new);
        }
        let cur_cp = self.current_cp + i32::from(self.start_pending);
        let fresh = self.next_serial + 1;
        let mut new_serial = fresh;
        let versions = &mut self.table[i];
        let mut superseded = None;
        match versions.last_mut() {
            Some(node) if node.cp == cur_cp => {
                new_serial = node.serial;
                node.empty = empty;
                node.data = data;
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
                // a newer version takes the buffer of the old one
                superseded = existing.map(|old| old.serial);
                versions.push(Node {
                    cp: cur_cp,
                    serial: fresh,
                    empty,
                    data,
                });
                self.next_serial = fresh;
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
        // `returnToCache`: at once, or when the table operation releases its nodes
        let key = (id, new_serial);
        let cache = self.cache.get_mut();
        if let Some(old) = superseded {
            cache.remove((id, old));
        }
        match held_slot {
            Some(g) => {
                cache.remove(key);
                let group = &mut self.groups.get_mut()[g];
                if group.taken_set.insert(id) {
                    group.taken.push(id);
                }
            }
            None => cache.touch(key),
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
        } else if let Some(n) = self.current(buf.id).filter(|n| !n.empty) {
            // Java can only change a buffer it has taken: one that was not read first (the
            // writers keep pages between operations) is loaded now
            let held = self
                .groups
                .borrow()
                .last()
                .is_some_and(|g| g.taken_set.contains(&buf.id));
            let key = (buf.id, n.serial);
            if !held && !self.cache.borrow().contains(key) {
                self.access(key)?;
            }
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
        self.for_each_saved(|id, data| match data {
            Some(d) => out.put(&DataBuffer::new(id, d.to_vec()), id),
            None => out.put(&DataBuffer::empty(id), id),
        })?;
        out.set_free_indexes(&self.free);
        // `close` flushes (header, free list, length, one `fsync`); flushing first as well made
        // two `fsync`s per save, where `BufferMgr.saveAs` does one
        out.close()
    }
}

impl CheckpointStore {
    /// Calls `f` for every index in order with the bytes `saveAs` stores (`None` for an empty
    /// buffer). Like `doSave` it loads each stored node into the memory cache.
    fn for_each_saved(&self, mut f: impl FnMut(i32, Option<&[u8]>) -> Result<()>) -> Result<()> {
        for id in 0..self.next_index {
            match self.current(id) {
                Some(n) if !n.empty => {
                    self.access((id, n.serial))?;
                    f(id, Some(&n.data))?;
                }
                _ => f(id, None)?,
            }
        }
        Ok(())
    }

    /// What [`CheckpointStore::save_to_file`] writes, kept in memory: the same buffers and free
    /// list without the file (the cost of a snapshot in a timing run).
    ///
    /// # Errors
    /// Bookkeeping errors of the cache model.
    pub fn save_to_memory(&self) -> Result<MemoryImage> {
        let mut buffers = Vec::with_capacity(usize::try_from(self.next_index).unwrap_or(0));
        self.for_each_saved(|_, d| {
            buffers.push(d.map(<[u8]>::to_vec));
            Ok(())
        })?;
        let mut free = self.free.clone();
        free.sort_unstable();
        Ok(MemoryImage {
            buffer_size: self.buffer_size,
            buffers,
            free,
        })
    }
}

/// A saved database image held in memory: a read-only [`BufferStore`] with the contents of the
/// buffer file [`CheckpointStore::save_to_file`] would have written (`None` is an empty buffer).
#[derive(Debug, Clone)]
pub struct MemoryImage {
    buffer_size: usize,
    buffers: Vec<Option<Vec<u8>>>,
    free: Vec<i32>,
}

impl MemoryImage {
    /// The free index list, ascending (what `BufferFile::free_indexes` returns).
    pub fn free_indexes(&self) -> &[i32] {
        &self.free
    }
}

impl BufferStore for MemoryImage {
    fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    fn index_count(&self) -> i32 {
        i32::try_from(self.buffers.len()).unwrap_or(i32::MAX)
    }

    fn get_buffer(&self, index: i32) -> Result<DataBuffer> {
        let slot = usize::try_from(index)
            .ok()
            .and_then(|i| self.buffers.get(i))
            .ok_or(GbfError::IndexOutOfRange {
                index,
                count: self.index_count(),
            })?;
        Ok(match slot {
            Some(d) => DataBuffer::new(index, d.clone()),
            None => DataBuffer::empty(-1),
        })
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
            // the operation now holds the node: its buffer stays out of the cache
            if g.taken_set.insert(id) {
                g.taken.push(id);
                let pending = self.pending.iter().any(|(i, _)| *i == id);
                if let Some(n) = self.current(id).filter(|n| !n.empty && !pending) {
                    // a page the writer holds was loaded: through the cache, if it was not yet
                    // (an error here would be "Out of cache buffer space", which `note_node`
                    // cannot report; the next read of the page does)
                    let _ = self.access((id, n.serial));
                    self.cache.borrow_mut().remove((id, n.serial));
                }
            }
        }
    }

    fn get_buffer(&self, index: i32) -> Result<DataBuffer> {
        if let Some((_, d)) = self.pending.iter().find(|(i, _)| *i == index) {
            return Ok(DataBuffer::new(index, d.clone()));
        }
        match self.current(index) {
            Some(n) if n.empty => Ok(DataBuffer::empty(index)),
            Some(n) => {
                self.read(index, n.serial)?;
                Ok(DataBuffer::new(index, n.data.clone()))
            }
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
        // `createBuffer`: the newest version of the index gives its buffer back when it still has
        // one (a deleted node keeps its bytes), otherwise a recycled or a new buffer is used
        let key = self.current(id).map(|n| (id, n.serial));
        let data = {
            let mut c = self.cache.borrow_mut();
            match key {
                Some(k) if c.remove(k) => self
                    .data_of(k)
                    .map_or_else(|| vec![0; self.buffer_size], <[u8]>::to_vec),
                _ => self.cache_buffer(&mut c)?,
            }
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
        let key = (id, node.serial);
        let mut was_held = false;
        if let Some(g) = self.groups.get_mut().last_mut() {
            g.table.remove(id);
            if g.taken_set.remove(&id) {
                g.taken.retain(|&t| t != id);
                was_held = true;
            }
        }
        // `NodeMgr.deleteNode` releases the node (back into the cache) and then `deleteBuffer`
        // takes it again
        if was_held {
            self.cache.get_mut().touch(key);
        }
        self.access(key)?;
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
        if self.start_pending {
            self.start_checkpoint();
        }
        for id in group.table.in_slot_order() {
            if group.held.iter().any(|&(h, pending)| h == id && pending) {
                self.push_id(id);
            }
        }
        // `releaseNodes`: the buffers go back to the cache in the slot order of the node table
        let mut back: Vec<i32> = group
            .table
            .in_slot_order()
            .filter(|id| group.taken_set.contains(id))
            .collect();
        let rest: Vec<i32> = group
            .taken
            .iter()
            .copied()
            .filter(|id| !back.contains(id))
            .collect();
        back.extend(rest);
        for id in back {
            if let Some(n) = self.current(id) {
                let key = (id, n.serial);
                self.cache.get_mut().touch(key);
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
