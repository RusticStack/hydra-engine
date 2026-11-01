//! Generation resolution (TRACE-1 section 7): processes, threads, module instances and object
//! lifetimes. A start observation opens a generation, an exit closes it, a reused PID or address
//! gets a new generation, and an entity whose start was never observed gets generation 0 with
//! `resolved = 0` ("lifetime-unresolved"). Identities never merge silently.

use crate::model::Event;
use crate::store::Result;
use rusqlite::{Transaction, params};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Default)]
struct ProcLife {
    cur: Option<u32>,
    max: u32,
    unres: bool,
}

#[derive(Clone, Debug, Default)]
struct ThreadLife {
    cur: Option<u32>,
    max: u32,
    unres: bool,
}

#[derive(Clone, Debug, Default)]
struct ObjLife {
    cur: Option<u32>,
    max: u32,
}

/// One module load instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModInst {
    pub inst: u32,
    pub pgen: u32,
    pub name: String,
    pub build: Option<String>,
    pub base: u64,
    pub size: u64,
    pub load_seq: i64,
    pub unload_seq: Option<i64>,
}

impl ModInst {
    /// True when this instance maps `va` at event ordinal `seq`.
    pub fn maps(&self, va: u64, seq: i64) -> bool {
        self.base <= va
            && va < self.base.saturating_add(self.size)
            && self.load_seq <= seq
            && self.unload_seq.is_none_or(|u| seq < u)
    }
}

/// An open coverage interval of one source.
#[derive(Clone, Debug)]
struct OpenCover {
    id: i64,
    t_end: i64,
    seq_end: i64,
    dirty: bool,
}

/// In-memory mirror of the lifetime tables; the tables are the truth and are reloaded after a
/// failed transaction.
#[derive(Debug, Default)]
pub struct Lifetimes {
    procs: HashMap<u32, ProcLife>,
    threads: HashMap<(u32, u32), ThreadLife>,
    pub(crate) modules: HashMap<u32, Vec<ModInst>>,
    next_inst: u32,
    objects: HashMap<(u32, u64), ObjLife>,
    clocks: HashSet<String>,
    cover: HashMap<String, OpenCover>,
}

fn u64_of(e: &Event, key: &str) -> Option<u64> {
    e.payload.get(key).and_then(|v| v.as_u64())
}

impl Lifetimes {
    /// Rebuild the mirror from the tables.
    pub fn load(conn: &rusqlite::Connection) -> Result<Self> {
        let mut life = Self::default();
        let mut stmt = conn.prepare("SELECT pid,gen,end_seq FROM processes ORDER BY pid,gen")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, u32>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, Option<i64>>(2)?,
            ))
        })?;
        for row in rows {
            let (pid, gen_, end) = row?;
            let p = life.procs.entry(pid).or_default();
            p.max = p.max.max(gen_);
            if gen_ > 0 && end.is_none() {
                p.cur = Some(gen_);
            }
        }
        let mut stmt = conn.prepare("SELECT pgen,tid,gen,end_seq FROM threads")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, u32>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, u32>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?;
        for row in rows {
            let (pgen, tid, gen_, end) = row?;
            let t = life.threads.entry((pgen, tid)).or_default();
            t.max = t.max.max(gen_);
            if gen_ > 0 && end.is_none() {
                t.cur = Some(gen_);
            }
        }
        let mut stmt = conn.prepare(
            "SELECT inst,pgen,name,build,base,size,load_seq,unload_seq FROM module_instances ORDER BY inst",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ModInst {
                inst: r.get(0)?,
                pgen: r.get(1)?,
                name: r.get(2)?,
                build: r.get(3)?,
                base: r.get::<_, i64>(4)? as u64,
                size: r.get::<_, i64>(5)? as u64,
                load_seq: r.get(6)?,
                unload_seq: r.get(7)?,
            })
        })?;
        for row in rows {
            let m = row?;
            life.next_inst = life.next_inst.max(m.inst);
            life.modules.entry(m.pgen).or_default().push(m);
        }
        let mut stmt = conn.prepare("SELECT pgen,addr,gen,destroy_seq FROM objects")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, u32>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, u32>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?;
        for row in rows {
            let (pgen, addr, gen_, destroy) = row?;
            let o = life.objects.entry((pgen, addr)).or_default();
            o.max = o.max.max(gen_);
            if gen_ > 0 && destroy.is_none() {
                o.cur = Some(gen_);
            }
        }
        let mut stmt = conn.prepare("SELECT name FROM clock_domains")?;
        for name in stmt.query_map([], |r| r.get::<_, String>(0))? {
            life.clocks.insert(name?);
        }
        // A source whose latest interval is still observing continues it, so a reopened index
        // extends the interval exactly as an uninterrupted run would.
        let mut stmt = conn.prepare(
            "SELECT source_id,id,state,t_end,seq_end FROM coverage_intervals c
             WHERE id=(SELECT MAX(id) FROM coverage_intervals WHERE source_id=c.source_id)",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        for row in rows {
            let (source, id, state, t_end, seq_end) = row?;
            if state == "observing" {
                life.cover.insert(
                    source,
                    OpenCover {
                        id,
                        t_end,
                        seq_end,
                        dirty: false,
                    },
                );
            }
        }
        Ok(life)
    }

    /// Resolve the generations of `e` (and record lifecycle events). Sets `process_gen`,
    /// `thread_gen` and `module_instance` on the stored copy of the event.
    pub(crate) fn observe(&mut self, tx: &Transaction<'_>, seq: i64, e: &mut Event) -> Result<()> {
        if let Some(pid) = e.process_id {
            let g = self.process(tx, seq, pid, &e.kind, e.process_gen)?;
            e.process_gen = Some(g);
            if let Some(tid) = e.thread_id {
                e.thread_gen = Some(self.thread(tx, seq, g, tid, &e.kind, e.thread_gen)?);
            }
        }
        let pgen = e.process_gen.unwrap_or(0);
        match e.kind.as_str() {
            "core.module.load" => self.module_load(tx, seq, pgen, e)?,
            "core.module.unload" => self.module_unload(tx, seq, pgen, e)?,
            "core.object.create" => self.object_create(tx, seq, pgen, e)?,
            "core.object.destroy" => self.object_destroy(tx, seq, pgen, e)?,
            _ => {
                if e.module_instance.is_none()
                    && let Some(name) = &e.module
                {
                    e.module_instance = self
                        .modules
                        .get(&pgen)
                        .and_then(|v| {
                            v.iter()
                                .rev()
                                .find(|m| m.unload_seq.is_none() && m.name == *name)
                        })
                        .map(|m| m.inst);
                }
            }
        }
        Ok(())
    }

    fn process(
        &mut self,
        tx: &Transaction<'_>,
        seq: i64,
        pid: u32,
        kind: &str,
        supplied: Option<u32>,
    ) -> Result<u32> {
        let life = self.procs.entry(pid).or_default();
        match kind {
            "core.process.start" => {
                if let Some(prev) = life.cur.take() {
                    tx.execute(
                        "UPDATE processes SET end_seq=?1, end_reason='reused-without-exit' WHERE pid=?2 AND gen=?3",
                        params![seq, pid, prev],
                    )?;
                }
                let g = match supplied {
                    Some(s) if s > life.max => s,
                    _ => life.max + 1,
                };
                life.max = g;
                life.cur = Some(g);
                tx.execute(
                    "INSERT INTO processes(pid,gen,start_seq,end_seq,end_reason,resolved) VALUES(?1,?2,?3,NULL,NULL,1)",
                    params![pid, g, seq],
                )?;
                Ok(g)
            }
            "core.process.exit" => {
                if let Some(g) = life.cur.take() {
                    tx.execute(
                        "UPDATE processes SET end_seq=?1, end_reason='exit' WHERE pid=?2 AND gen=?3",
                        params![seq, pid, g],
                    )?;
                    Ok(g)
                } else {
                    unresolved_process(tx, pid)?;
                    life.unres = true;
                    Ok(0)
                }
            }
            _ => match supplied {
                Some(s) if s > 0 && s <= life.max => Ok(s),
                _ => match life.cur {
                    Some(g) => Ok(g),
                    None => {
                        if !life.unres {
                            unresolved_process(tx, pid)?;
                            life.unres = true;
                        }
                        Ok(0)
                    }
                },
            },
        }
    }

    fn thread(
        &mut self,
        tx: &Transaction<'_>,
        seq: i64,
        pgen: u32,
        tid: u32,
        kind: &str,
        supplied: Option<u32>,
    ) -> Result<u32> {
        let life = self.threads.entry((pgen, tid)).or_default();
        match kind {
            "core.thread.start" => {
                if let Some(prev) = life.cur.take() {
                    tx.execute(
                        "UPDATE threads SET end_seq=?1 WHERE pgen=?2 AND tid=?3 AND gen=?4",
                        params![seq, pgen, tid, prev],
                    )?;
                }
                let g = match supplied {
                    Some(s) if s > life.max => s,
                    _ => life.max + 1,
                };
                life.max = g;
                life.cur = Some(g);
                tx.execute(
                    "INSERT INTO threads(pgen,tid,gen,start_seq,end_seq,resolved) VALUES(?1,?2,?3,?4,NULL,1)",
                    params![pgen, tid, g, seq],
                )?;
                Ok(g)
            }
            "core.thread.exit" => {
                if let Some(g) = life.cur.take() {
                    tx.execute(
                        "UPDATE threads SET end_seq=?1 WHERE pgen=?2 AND tid=?3 AND gen=?4",
                        params![seq, pgen, tid, g],
                    )?;
                    Ok(g)
                } else {
                    unresolved_thread(tx, pgen, tid)?;
                    life.unres = true;
                    Ok(0)
                }
            }
            _ => match supplied {
                Some(s) if s > 0 && s <= life.max => Ok(s),
                _ => match life.cur {
                    Some(g) => Ok(g),
                    None => {
                        if !life.unres {
                            unresolved_thread(tx, pgen, tid)?;
                            life.unres = true;
                        }
                        Ok(0)
                    }
                },
            },
        }
    }

    fn module_load(
        &mut self,
        tx: &Transaction<'_>,
        seq: i64,
        pgen: u32,
        e: &mut Event,
    ) -> Result<()> {
        let name = e
            .payload
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| e.module.clone())
            .unwrap_or_default();
        let base = u64_of(e, "base").unwrap_or(0);
        let size = u64_of(e, "size").unwrap_or(0);
        let build = e
            .payload
            .get("build")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let inst = match e.module_instance {
            Some(s) if s > self.next_inst => s,
            _ => self.next_inst + 1,
        };
        self.next_inst = inst;
        tx.execute(
            "INSERT INTO module_instances(inst,pgen,name,build,base,size,load_seq,unload_seq) VALUES(?1,?2,?3,?4,?5,?6,?7,NULL)",
            params![inst, pgen, name, build, base as i64, size as i64, seq],
        )?;
        self.modules.entry(pgen).or_default().push(ModInst {
            inst,
            pgen,
            name: name.clone(),
            build,
            base,
            size,
            load_seq: seq,
            unload_seq: None,
        });
        e.module_instance = Some(inst);
        if e.module.is_none() {
            e.module = Some(name);
        }
        Ok(())
    }

    fn module_unload(
        &mut self,
        tx: &Transaction<'_>,
        seq: i64,
        pgen: u32,
        e: &mut Event,
    ) -> Result<()> {
        let name = e
            .payload
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| e.module.clone())
            .unwrap_or_default();
        let base = u64_of(e, "base");
        if let Some(m) = self.modules.get_mut(&pgen).and_then(|v| {
            v.iter_mut().rev().find(|m| {
                m.unload_seq.is_none() && m.name == name && base.is_none_or(|b| b == m.base)
            })
        }) {
            m.unload_seq = Some(seq);
            e.module_instance = Some(m.inst);
            tx.execute(
                "UPDATE module_instances SET unload_seq=?1 WHERE inst=?2",
                params![seq, m.inst],
            )?;
        }
        if e.module.is_none() {
            e.module = Some(name);
        }
        Ok(())
    }

    fn object_create(
        &mut self,
        tx: &Transaction<'_>,
        seq: i64,
        pgen: u32,
        e: &Event,
    ) -> Result<()> {
        let Some(addr) = u64_of(e, "object") else {
            return Ok(());
        };
        let life = self.objects.entry((pgen, addr)).or_default();
        if let Some(prev) = life.cur.take() {
            tx.execute(
                "UPDATE objects SET destroy_seq=?1 WHERE pgen=?2 AND addr=?3 AND gen=?4",
                params![seq, pgen, addr as i64, prev],
            )?;
        }
        let g = match u64_of(e, "generation") {
            Some(s) if s as u32 > life.max => s as u32,
            _ => life.max + 1,
        };
        life.max = g;
        life.cur = Some(g);
        let ty = e.payload.get("type").and_then(|v| v.as_str());
        tx.execute(
            "INSERT INTO objects(pgen,addr,gen,type,create_seq,destroy_seq,resolved) VALUES(?1,?2,?3,?4,?5,NULL,1)",
            params![pgen, addr as i64, g, ty, seq],
        )?;
        Ok(())
    }

    fn object_destroy(
        &mut self,
        tx: &Transaction<'_>,
        seq: i64,
        pgen: u32,
        e: &Event,
    ) -> Result<()> {
        let Some(addr) = u64_of(e, "object") else {
            return Ok(());
        };
        let life = self.objects.entry((pgen, addr)).or_default();
        if let Some(g) = life.cur.take() {
            tx.execute(
                "UPDATE objects SET destroy_seq=?1 WHERE pgen=?2 AND addr=?3 AND gen=?4",
                params![seq, pgen, addr as i64, g],
            )?;
        } else {
            // A destroy with no observed create: the lifetime start is unresolved.
            tx.execute(
                "INSERT OR IGNORE INTO objects(pgen,addr,gen,type,create_seq,destroy_seq,resolved) VALUES(?1,?2,0,NULL,NULL,?3,0)",
                params![pgen, addr as i64, seq],
            )?;
        }
        Ok(())
    }

    /// The generation of the live object at `addr`, or `None` when no create was observed.
    pub fn object_gen(&self, pgen: u32, addr: u64) -> Option<u32> {
        self.objects.get(&(pgen, addr)).and_then(|o| o.cur)
    }

    /// Register a clock domain on first sight.
    pub(crate) fn clock(&mut self, tx: &Transaction<'_>, name: &str, source: &str) -> Result<()> {
        if self.clocks.insert(name.to_string()) {
            tx.execute(
                "INSERT OR IGNORE INTO clock_domains(name,source_id,unit,resolution_ns,calibrated,offset_ns,drift_ppm,uncertainty_ns,to_domain)
                 VALUES(?1,?2,'ns',1,0,NULL,NULL,NULL,NULL)",
                params![name, source],
            )?;
        }
        Ok(())
    }

    /// The module instance mapping `va` at `seq` for the process generation.
    pub fn find_module(&self, pgen: u32, va: u64, seq: i64) -> Option<&ModInst> {
        self.modules
            .get(&pgen)?
            .iter()
            .rev()
            .find(|m| m.maps(va, seq))
    }

    /// Extend (or open) the observing interval of `source` with an event at `(t, seq)`.
    pub(crate) fn cover_event(
        &mut self,
        tx: &Transaction<'_>,
        source: &str,
        t: i64,
        seq: i64,
    ) -> Result<()> {
        match self.cover.get_mut(source) {
            Some(c) => {
                c.t_end = t.max(c.t_end);
                c.seq_end = seq;
                c.dirty = true;
            }
            None => {
                tx.execute(
                    "INSERT INTO coverage_intervals(source_id,state,t_start,t_end,seq_start,seq_end,reason) VALUES(?1,'observing',?2,?2,?3,?3,NULL)",
                    params![source, t, seq],
                )?;
                self.cover.insert(
                    source.to_string(),
                    OpenCover {
                        id: tx.last_insert_rowid(),
                        t_end: t,
                        seq_end: seq,
                        dirty: false,
                    },
                );
            }
        }
        Ok(())
    }

    /// Close the observing interval of `source` and record a non-observing one.
    pub(crate) fn cover_break(
        &mut self,
        tx: &Transaction<'_>,
        source: &str,
        state: &str,
        reason: &str,
        t: i64,
        seq: i64,
    ) -> Result<()> {
        self.flush_cover(tx)?;
        self.cover.remove(source);
        tx.execute(
            "INSERT INTO coverage_intervals(source_id,state,t_start,t_end,seq_start,seq_end,reason) VALUES(?1,?2,?3,?3,?4,?4,?5)",
            params![source, state, t, seq, reason],
        )?;
        Ok(())
    }

    /// Write pending interval extensions. Called at the end of every batch.
    pub(crate) fn flush_cover(&mut self, tx: &Transaction<'_>) -> Result<()> {
        for c in self.cover.values_mut().filter(|c| c.dirty) {
            tx.execute(
                "UPDATE coverage_intervals SET t_end=?1, seq_end=?2 WHERE id=?3",
                params![c.t_end, c.seq_end, c.id],
            )?;
            c.dirty = false;
        }
        Ok(())
    }

    /// A new batch reopens intervals (the previous batch's rows stay as they were committed).
    pub(crate) fn end_batch(&mut self, tx: &Transaction<'_>) -> Result<()> {
        self.flush_cover(tx)
    }
}

fn unresolved_process(tx: &Transaction<'_>, pid: u32) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO processes(pid,gen,start_seq,end_seq,end_reason,resolved) VALUES(?1,0,NULL,NULL,NULL,0)",
        params![pid],
    )?;
    Ok(())
}

fn unresolved_thread(tx: &Transaction<'_>, pgen: u32, tid: u32) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO threads(pgen,tid,gen,start_seq,end_seq,resolved) VALUES(?1,?2,0,NULL,NULL,0)",
        params![pgen, tid],
    )?;
    Ok(())
}
