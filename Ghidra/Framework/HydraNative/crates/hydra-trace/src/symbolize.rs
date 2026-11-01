//! Symbolization (TRACE-1 section 10). A [`Symbolizer`] maps `(module, rva)` to a function at a
//! pinned program revision. Ingest symbolizes against the symbolizer set on the store; every
//! unresolved site keeps `function: null` and one reason: `no-stack`, `not-code`,
//! `module-unknown` or `no-symbol`. Results live in `event_symbols` under an interpretation
//! revision, so re-symbolization (a new revision) never rewrites an observation.

use crate::lifetime::{Lifetimes, ModInst};
use crate::store::{Result, Store};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A module as the symbolizer sees it.
#[derive(Clone, Debug)]
pub struct ModuleRef<'a> {
    pub name: &'a str,
    pub build: Option<&'a str>,
    pub instance: u32,
}

/// The answer for one `(module, rva)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Symbol {
        function: String,
        type_name: Option<String>,
    },
    /// The address is mapped but is not code (data, an import thunk table, ...).
    NotCode,
    /// Code, but no function covers it.
    NoSymbol,
}

/// The seam to the engine's read plane (or any table). Implementations are read-only and
/// thread-safe: the symbolizer never takes a program lock.
pub trait Symbolizer: Send + Sync {
    fn resolve(&self, module: &ModuleRef<'_>, rva: u64) -> Resolution;
}

/// Why a site has no function.
pub const REASONS: [&str; 4] = ["no-stack", "not-code", "module-unknown", "no-symbol"];

/// One function range of a [`TableSymbolizer`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionRange {
    pub start: u64,
    pub end: u64,
    pub name: String,
    #[serde(default)]
    pub type_name: Option<String>,
}

/// A module's functions plus its code ranges, from JSON (`trace_resymbolize`) or tests.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TableSymbolizer {
    /// module name -> ranges (rva, half open).
    pub modules: BTreeMap<String, ModuleTable>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModuleTable {
    /// Code ranges. Empty means "everything is code".
    #[serde(default)]
    pub code: Vec<(u64, u64)>,
    pub functions: Vec<FunctionRange>,
}

impl Symbolizer for TableSymbolizer {
    fn resolve(&self, module: &ModuleRef<'_>, rva: u64) -> Resolution {
        let Some(table) = self.modules.get(module.name) else {
            return Resolution::NoSymbol;
        };
        if !table.code.is_empty() && !table.code.iter().any(|&(s, e)| s <= rva && rva < e) {
            return Resolution::NotCode;
        }
        match table
            .functions
            .iter()
            .find(|f| f.start <= rva && rva < f.end)
        {
            Some(f) => Resolution::Symbol {
                function: f.name.clone(),
                type_name: f.type_name.clone(),
            },
            None => Resolution::NoSymbol,
        }
    }
}

/// The code address to symbolize for an event: the site, else the innermost return address.
pub fn site_of(va: Option<u64>, callstack: &[u64]) -> Option<u64> {
    va.or_else(|| callstack.first().copied())
}

/// Resolve one site against `module` (already looked up by the caller) at the symbolizer.
pub fn resolve_site(
    symbolizer: &dyn Symbolizer,
    modules: Option<&ModInst>,
    site: Option<u64>,
) -> (Option<String>, Option<&'static str>) {
    let Some(va) = site else {
        return (None, Some("no-stack"));
    };
    let Some(m) = modules else {
        return (None, Some("module-unknown"));
    };
    let module = ModuleRef {
        name: &m.name,
        build: m.build.as_deref(),
        instance: m.inst,
    };
    match symbolizer.resolve(&module, va - m.base) {
        Resolution::Symbol { function, .. } => (Some(function), None),
        Resolution::NotCode => (None, Some("not-code")),
        Resolution::NoSymbol => (None, Some("no-symbol")),
    }
}

/// Counts per outcome for one interpretation revision. `symbolized / (total - no_stack -
/// not_code)` is the M1 ratio over events that have a captured, mapped code address.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct SymbolCounts {
    pub interp: i64,
    pub symbol_revision: String,
    pub total: u64,
    pub symbolized: u64,
    pub no_stack: u64,
    pub not_code: u64,
    pub module_unknown: u64,
    pub no_symbol: u64,
}

/// Counts for `interp` (latest symbolization revision when `None`).
pub fn counts(store: &Store, interp: Option<i64>) -> Result<Option<SymbolCounts>> {
    let conn = store.conn();
    let interp = match interp {
        Some(i) => i,
        None => match latest_symbolization(store)? {
            Some(i) => i,
            None => return Ok(None),
        },
    };
    let symbol_revision: String = conn
        .query_row(
            "SELECT COALESCE(symbol_revision,'') FROM interpretations WHERE rev=?1",
            params![interp],
            |r| r.get(0),
        )
        .unwrap_or_default();
    let mut out = SymbolCounts {
        interp,
        symbol_revision,
        ..SymbolCounts::default()
    };
    let mut stmt = conn.prepare(
        "SELECT COALESCE(reason,''), COUNT(*) FROM event_symbols WHERE interp=?1 GROUP BY 1",
    )?;
    let rows = stmt.query_map(params![interp], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
    })?;
    for row in rows {
        let (reason, n) = row?;
        out.total += n;
        match reason.as_str() {
            "" => out.symbolized += n,
            "no-stack" => out.no_stack += n,
            "not-code" => out.not_code += n,
            "module-unknown" => out.module_unknown += n,
            _ => out.no_symbol += n,
        }
    }
    Ok(Some(out))
}

/// The newest symbolization interpretation revision.
pub fn latest_symbolization(store: &Store) -> Result<Option<i64>> {
    Ok(store.conn().query_row(
        "SELECT MAX(rev) FROM interpretations WHERE kind='symbolization'",
        [],
        |r| r.get::<_, Option<i64>>(0),
    )?)
}

/// Re-symbolize every event as a new interpretation revision against `symbolizer`. The original
/// observations are untouched. Returns the new revision.
pub fn resymbolize(
    store: &mut Store,
    symbolizer: &dyn Symbolizer,
    symbol_revision: &str,
) -> Result<i64> {
    let parent = latest_symbolization(store)?;
    let life = Lifetimes::load(store.conn())?;
    let tx = store.conn_mut().transaction()?;
    let rev: i64 = tx.query_row(
        "SELECT COALESCE(MAX(rev),0)+1 FROM interpretations",
        [],
        |r| r.get(0),
    )?;
    tx.execute(
        "INSERT INTO interpretations(rev,kind,parent,symbol_revision,codec_hash,schema_hash,context_from,context_to,note)
         VALUES(?1,'symbolization',?2,?3,NULL,NULL,NULL,NULL,'re-symbolization')",
        params![rev, parent, symbol_revision],
    )?;
    {
        let mut read = tx.prepare(
            "SELECT seq,process_gen,va,callstack FROM events ORDER BY seq",
        )?;
        let mut write = tx.prepare_cached(
            "INSERT INTO event_symbols(interp,seq,function,reason) VALUES(?1,?2,?3,?4)",
        )?;
        let mut rows = read.query([])?;
        while let Some(row) = rows.next()? {
            let seq: i64 = row.get(0)?;
            let pgen: Option<u32> = row.get(1)?;
            let va: Option<i64> = row.get(2)?;
            let stack: String = row.get(3)?;
            let stack: Vec<u64> = serde_json::from_str(&stack).unwrap_or_default();
            let site = site_of(va.map(|v| v as u64), &stack);
            let module = site.and_then(|a| life.find_module(pgen.unwrap_or(0), a, seq));
            let (function, reason) = resolve_site(symbolizer, module, site);
            write.execute(params![rev, seq, function, reason])?;
        }
    }
    bump_revision(&tx)?;
    tx.commit()?;
    Ok(rev)
}

fn bump_revision(tx: &rusqlite::Transaction<'_>) -> Result<()> {
    tx.execute(
        "UPDATE meta SET value=CAST(CAST(value AS INTEGER)+1 AS TEXT) WHERE key='revision'",
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> TableSymbolizer {
        let mut t = TableSymbolizer::default();
        t.modules.insert(
            "main.exe".into(),
            ModuleTable {
                code: vec![(0, 0x1000)],
                functions: vec![FunctionRange {
                    start: 0x100,
                    end: 0x200,
                    name: "Foo".into(),
                    type_name: None,
                }],
            },
        );
        t
    }

    #[test]
    fn reasons_are_distinct() {
        let m = ModInst {
            inst: 1,
            pgen: 1,
            name: "main.exe".into(),
            build: None,
            base: 0x40_0000,
            size: 0x2000,
            load_seq: 1,
            unload_seq: None,
        };
        let t = table();
        assert_eq!(resolve_site(&t, Some(&m), None).1, Some("no-stack"));
        assert_eq!(
            resolve_site(&t, None, Some(0x40_0150)).1,
            Some("module-unknown")
        );
        assert_eq!(
            resolve_site(&t, Some(&m), Some(0x40_1500)).1,
            Some("not-code")
        );
        assert_eq!(
            resolve_site(&t, Some(&m), Some(0x40_0800)).1,
            Some("no-symbol")
        );
        assert_eq!(
            resolve_site(&t, Some(&m), Some(0x40_0150)).0.as_deref(),
            Some("Foo")
        );
    }
}
