//! A small read-only query facade over a Program database, meant to be bound to other
//! languages. Everything here is owned data (no borrows of the open file), so a [`Program`] can be
//! shared behind a lock and its results can be handed across an FFI boundary.
//!
//! ```no_run
//! use ghidra_progdb::query::Program;
//! use ghidra_progdb::{AddressSpaces, SpaceDef};
//!
//! // The database stores space names only; describe the language's spaces.
//! let spaces = AddressSpaces::new(
//!     vec![SpaceDef { name: "ram".into(), id: 3, bits: 64 }],
//!     "ram",
//! );
//! let program = Program::open_file("db.1.gbf", spaces)?;
//! for f in program.functions() {
//!     println!("{} at {}", f.name.as_deref().unwrap_or("?"), f.entry);
//! }
//! let entry = program.parse_address("ram:140001030")?;
//! let callers = program.xrefs_to(&entry);
//! let first_bytes = program.read_bytes(&entry, 16)?;
//! # Ok::<(), ghidra_progdb::ProgError>(())
//! ```
//!
//! # Semantics
//!
//! Every answer is the answer Java's `ProgramDB` gives (checked by the differential tests against
//! the stock oracle), with the limits listed in `PORTING.md`: no dynamic symbols, no default local
//! variable names, no automatic parameters, no computed stack frame values, no instruction
//! decoding.
//!
//! # Ordering
//!
//! * [`Program::functions`]: function id ascending.
//! * [`Program::symbols_by_name`], [`Program::symbols_at`], [`Program::children`]: the order of
//!   `SymbolManager`, documented in the `symtab` module.
//! * [`Program::xrefs_from`], [`Program::xrefs_to`]: stored order (the order references were added).
//! * [`FunctionInfo::parameters`]: ordinal ascending; [`FunctionInfo::locals`]: symbol id.

use std::collections::HashMap;
use std::path::Path;

use ghidra_fmt_gbf::{BufferFile, BufferStore};

use crate::{
    Address, AddressRange, AddressSpaces, Function, ProgError, ProgramDb, Reference, Result,
    Symbol, SymbolTable, Variable,
};

/// A function with everything the stored tables say about it.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// The "Function Data" row joined with its symbol address and thunk link.
    pub function: Function,
    /// Name as Java shows it (`FUN_<addr>` for default names); `None` for default external
    /// functions.
    pub name: Option<String>,
    /// Entry point (`None` only if the function symbol is missing).
    pub entry: Address,
    /// Id of the namespace symbol the function lives in (0 is global).
    pub namespace_id: i64,
    /// Merged address ranges of the body.
    pub body: Vec<AddressRange>,
    /// Stored parameters, ordinal ascending. Automatic parameters are not included, and for
    /// functions without custom storage `storage` is whatever was stored, not what Java assigns.
    pub parameters: Vec<Variable>,
    /// Stored local variables, symbol id ascending.
    pub locals: Vec<Variable>,
}

impl std::ops::Deref for FunctionInfo {
    type Target = Function;

    fn deref(&self) -> &Function {
        &self.function
    }
}

/// An open Program database with all query indexes built.
pub struct Program<S: BufferStore> {
    db: ProgramDb<S>,
    symbols: SymbolTable,
    functions: Vec<FunctionInfo>,
    by_entry: HashMap<Address, usize>,
    /// (space, min, max, index into `functions`), sorted by space then min.
    ranges: Vec<(String, u64, u64, usize)>,
    refs_from: HashMap<Address, Vec<Reference>>,
    refs_to: HashMap<Address, Vec<Reference>>,
}

impl Program<BufferFile> {
    /// Open the `db.N.gbf` file at `path` read-only.
    ///
    /// # Errors
    ///
    /// The errors of [`Program::open`], or the file error when `path` cannot be read.
    pub fn open_file(path: impl AsRef<Path>, spaces: AddressSpaces) -> Result<Self> {
        let file = BufferFile::open(path, true)
            .map_err(|e| ProgError::Db(ghidra_fmt_db::DbError::from(e)))?;
        Self::open(file, spaces)
    }
}

impl<S: BufferStore> Program<S> {
    /// Open the Program database in `store` and build the indexes.
    ///
    /// `spaces` describes the language's address spaces (see [`AddressSpaces`]).
    ///
    /// # Errors
    ///
    /// See [`ProgramDb::open`]; also any error reading the tables the indexes are built from.
    pub fn open(store: S, spaces: AddressSpaces) -> Result<Self> {
        let db = ProgramDb::open(store, spaces)?;
        let symbols = db.symbol_table()?;
        let bodies = db.function_bodies()?;
        let variables = db.variables()?;
        let mut functions = Vec::new();
        for f in db.functions()? {
            let sym = symbols.get(f.id);
            let name = sym.and_then(|s| symbols.name(s));
            let namespace_id = sym.map_or(0, |s| symbols.parent_namespace_id(s));
            let entry = f.entry.clone().unwrap_or(Address::NoAddress);
            let mut parameters: Vec<Variable> = variables
                .iter()
                .filter(|v| v.function_id == f.id && v.is_parameter)
                .cloned()
                .collect();
            parameters.sort_by_key(|v| (v.ordinal, v.symbol_id));
            let locals = variables
                .iter()
                .filter(|v| v.function_id == f.id && !v.is_parameter)
                .cloned()
                .collect();
            functions.push(FunctionInfo {
                body: bodies.get(&f.id).cloned().unwrap_or_default(),
                function: f,
                name,
                entry,
                namespace_id,
                parameters,
                locals,
            });
        }
        functions.sort_by_key(|f| f.function.id);
        let mut by_entry = HashMap::new();
        let mut ranges = Vec::new();
        for (i, f) in functions.iter().enumerate() {
            by_entry.entry(f.entry.clone()).or_insert(i);
            for r in &f.body {
                ranges.push((r.space.clone(), r.min, r.max, i));
            }
        }
        ranges.sort();
        let mut refs_from: HashMap<Address, Vec<Reference>> = HashMap::new();
        for (owner, list) in db.references_from()? {
            refs_from.entry(owner).or_default().extend(list);
        }
        let mut refs_to: HashMap<Address, Vec<Reference>> = HashMap::new();
        for (owner, list) in db.references_to()? {
            refs_to.entry(owner).or_default().extend(list);
        }
        Ok(Self {
            db,
            symbols,
            functions,
            by_entry,
            ranges,
            refs_from,
            refs_to,
        })
    }

    /// The underlying reader, for anything the facade does not cover.
    pub fn db(&self) -> &ProgramDb<S> {
        &self.db
    }

    /// The symbol table with its `SymbolManager` queries.
    pub fn symbol_table(&self) -> &SymbolTable {
        &self.symbols
    }

    /// The "Language ID" of the program, when stored.
    pub fn language_id(&self) -> Option<&str> {
        self.db.language_id()
    }

    /// Parse `space:hex` (for example `ram:140001030`) or a bare hexadecimal offset in the default
    /// space (`140001030`, `0x140001030`).
    ///
    /// # Errors
    ///
    /// [`ProgError::UnknownSpace`] for a space that was not described, [`ProgError::Corrupt`]
    /// for text that is not an address (the variant is reused to avoid a second error type).
    pub fn parse_address(&self, text: &str) -> Result<Address> {
        let spaces = self.db.address_map().spaces();
        let (space, digits) = match text.rsplit_once(':') {
            Some((s, d)) => (s, d),
            None => (spaces.default_space.as_str(), text),
        };
        let def = spaces
            .find(space)
            .ok_or_else(|| ProgError::UnknownSpace(space.to_owned()))?;
        let digits = digits.strip_prefix("0x").unwrap_or(digits);
        let offset = u64::from_str_radix(digits, 16)
            .map_err(|_| ProgError::Corrupt(format!("not an address: {text:?}")))?;
        if def.bits < 64 && offset >> def.bits != 0 {
            return Err(ProgError::Corrupt(format!(
                "offset {offset:#x} is outside space {space}"
            )));
        }
        Ok(Address::Space {
            space: space.to_owned(),
            offset,
        })
    }

    /// Every function, id ascending (`FunctionManager.getFunctions` plus external functions).
    pub fn functions(&self) -> &[FunctionInfo] {
        &self.functions
    }

    /// The function whose entry point is `addr` (`FunctionManager.getFunctionAt`).
    pub fn function_at(&self, addr: &Address) -> Option<&FunctionInfo> {
        self.by_entry.get(addr).map(|&i| &self.functions[i])
    }

    /// The function whose body contains `addr` (`FunctionManager.getFunctionContaining`).
    pub fn function_containing(&self, addr: &Address) -> Option<&FunctionInfo> {
        let Address::Space { space, offset } = addr else {
            return None;
        };
        let at = self
            .ranges
            .partition_point(|(s, min, _, _)| (s.as_str(), *min) <= (space.as_str(), *offset));
        // bodies of different functions do not overlap, but nested ranges are possible in odd
        // databases, so look back over a few candidates
        self.ranges[..at]
            .iter()
            .rev()
            .take(8)
            .find(|(s, min, max, _)| s == space && *min <= *offset && *offset <= *max)
            .map(|&(_, _, _, i)| &self.functions[i])
    }

    /// The function with this id.
    pub fn function_by_id(&self, id: i64) -> Option<&FunctionInfo> {
        self.functions
            .binary_search_by_key(&id, |f| f.function.id)
            .ok()
            .map(|i| &self.functions[i])
    }

    /// Symbols with this name (`SymbolManager.getSymbols(String)`).
    pub fn symbols_by_name(&self, name: &str) -> Vec<&Symbol> {
        self.symbols.by_name(name)
    }

    /// Symbols at an address, primary first (`SymbolManager.getSymbols(Address)`).
    pub fn symbols_at(&self, addr: &Address) -> Vec<&Symbol> {
        self.symbols.at(addr)
    }

    /// The symbols directly inside a namespace (0 is the global namespace).
    pub fn children(&self, namespace_id: i64) -> Vec<&Symbol> {
        self.symbols.children(namespace_id)
    }

    /// References pointing at `addr` (`ReferenceManager.getReferencesTo`), stored order.
    pub fn xrefs_to(&self, addr: &Address) -> &[Reference] {
        self.refs_to.get(addr).map_or(&[], Vec::as_slice)
    }

    /// References made from `addr` (`ReferenceManager.getReferencesFrom`), stored order.
    pub fn xrefs_from(&self, addr: &Address) -> &[Reference] {
        self.refs_from.get(addr).map_or(&[], Vec::as_slice)
    }

    /// Up to `len` bytes at `addr` (`Memory.getBytes`): fewer where memory ends.
    ///
    /// # Errors
    ///
    /// [`ProgError::MemoryAccess`] when no byte can be read (unmapped or uninitialized memory).
    pub fn read_bytes(&self, addr: &Address, len: usize) -> Result<Vec<u8>> {
        self.db.memory()?.read(addr, len)
    }
}
