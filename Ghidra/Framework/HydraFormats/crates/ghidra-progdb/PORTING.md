# ghidra-progdb porting notes

Source: `ghidra.program.database.ProgramDB` (open, version policy, metadata map via
`DBStringMapAdapter`), `map.AddressMapDB` + `AddressMapDBAdapterV1`, `mem.MemoryMapDBAdapterV3`,
`MemoryBlockDB`, `SubMemoryBlock`, `symbol.SymbolDatabaseAdapter` (V4/V5 record layout).
Read-only. Upgrades stay in Java.

## Status

| Java | Rust | State |
| --- | --- | --- |
| `ProgramDB` open: stored version check (`DB_VERSION` 33, `UPGRADE_REQUIRED_BEFORE_VERSION` 19) | `ProgramDb::open`, `ProgError::{NewerVersion, UpgradeRequired, UnsupportedTableVersion}` | done; 19..=33 opens (Java opens 19..32 read-only through old adapters), anything else is refused |
| "Program" string map (`Language ID`, `Compiler Spec ID`, `Image Offset`, `DB Version`, ...) | `ProgramDb::metadata`, `language_id`, `compiler_spec_id`, `image_base_offset` | done |
| `AddressMapDBAdapterV1` + `AddressMapDB.decodeAddress` | `AddressMap::decode` | done for absolute, relocatable (image base, wrap), register, stack, external, variable, hash, `NO_ADDRESS`, `EXT_FROM`. NOT ported: old key type 0, namespace-qualified register/stack/external keys (`OldGenericNamespaceAddress`), segmented spaces, overlay spaces |
| `AddressMapDB.getKey` / encode | none | NOT ported (read-only) |
| `MemoryMapDBAdapterV3`, `MemoryBlockDB.refresh` | `ProgramDb::memory_blocks`, `MemoryBlock`, `SubBlock` | done (sorted by start address). Overlay detection, mapped-block targets and `isInitialized` of mapped blocks (Java asks the source) are NOT ported |
| Memory content: `MemoryMapDB.getBytes/getByte`, `MemoryBlockDB.getBytes`, `Buffer/FileBytes/Uninitialized/ByteMapped/BitMapped SubMemoryBlock`, `FileBytes.getModifiedBytes` (layered buffers over the originals), `ByteMappingScheme.getBytes`, `BinaryCodedField` int arrays | `ProgramDb::memory()` -> `Memory::{read, read_byte, block_at, blocks}` | done. `read(addr, len)` follows `Memory.getBytes`: reads on across adjacent blocks, returns fewer bytes where memory ends (no block, or a block whose FIRST part is uninitialized), errors (`ProgError::MemoryAccess`) when zero bytes could be read or when an uninitialized part sits inside an initialized block. Checked byte for byte (SHA-256) against Java for every block of both fixtures plus edge reads (block start, end, past the end, before the start). Mapped blocks are ported from the Java source and unit tested against real memory, but no fixture contains one, so they are NOT checked against Java. Not modelled: overlay spaces (address looked up by space name), the Hydra read snapshot, writes. Mapping cycles give an error (Java would overflow the stack) |
| `SymbolDatabaseAdapterV4/V5` record layout, `SourceType` flag decoding | `ProgramDb::symbols`, `Symbol` | done; `is_primary`/`is_pinned` follow the Java symbol classes. Names of default-named symbols are stored empty (Java computes `FUN_`/`LAB_` names; not ported) |
| `SymbolManager` queries: `getSymbols(String)`, `getSymbols(String, Namespace)`, `getSymbols(Namespace)` / `getChildren`, `getSymbols(Address)`, `getPrimarySymbol`, default function and parameter names, `parseDynamicName` | `ProgramDb::symbol_table()` -> `SymbolTable::{get, name, by_name, by_name_in_namespace, children, at, primary_at, address_string}` | done and equal to Java (ids and order) on both fixtures for: every stored name, every default function / parameter name, every (name, namespace) pair, the children of every namespace and the symbols plus primary symbol at every symbol address. Ordering rules are in the `symtab.rs` module docs: by name = id ascending; by name and namespace = stored locator hash then id (low 32 bits of the address key, then id); children = id ascending without default thunks; at address = id ascending with the last primary symbol swapped into slot 0; primary = first id with the Primary column set. NOT ported: dynamic symbols (`LAB_`/`DAT_` names Java invents for referenced addresses without a symbol), default local variable names, default external names (`name()` gives `None`), symbols by path / regex / prefix scans, `getSymbols(AddressSet)` iterators, word-addressable spaces and non-default RAM spaces in `address_string` |
| `FunctionAdapterV3` ("Function Data"), `ThunkFunctionAdapterV0`, calling convention ids | `ProgramDb::functions`, `Function` | done: id, entry (function symbol address), flags (vararg, inline, noreturn, custom storage, signature source), stack purge / return offset / local size, calling convention name, return storage, thunk link. NOT ported: tags, automatic parameters and the storage Java assigns to parameters of functions without custom storage (computed from the calling convention in the compiler spec), computed stack frame values (`getLocalSize`, `getParameterSize`, `getParameterOffset`; need the compiler spec). Thunks inherit most fields in Java; the oracle only compares the link for thunks |
| `AddressRangeMapDB` ("Range Map - SCOPE ADDRESSES"), `NamespaceManager.getAddressSet`, `VariableSymbolDB`, "Variable Storage" | `ProgramDb::function_bodies`, `ProgramDb::variables`, `AddressRange`, `Variable` | done and equal to Java on both fixtures: merged body ranges of every function (including wrapped records and nested namespaces), `StackReturnOffset`, and 1684 stored parameters / locals (symbol id, owner, kind, name, source, ordinal, first-use offset, data type id, stored storage string). Parameter storage is only compared for functions with custom storage. Ordering: bodies are sorted by (space id, offset); `variables()` is in symbol id order, Java orders by `VariableUtilities.compare` (not reproduced) |
| `FromAdapterV0` ("FROM REFS"), `ToAdapterV1` ("TO REFS"), `RefListV0` entry encoding, `RefListFlagsV0`, `RefTypeFactory` names | `ProgramDb::references_from`, `references_to`, `Reference`, `RefKind`, `ref_type_name` | done: from, to, type, operand index, source, primary, symbol id, offset / shift, the Java class (mem, offset, shifted, external, entry point, stack). NOT ported: TO REFS version 0 (refused), the `Ref Level` column (stored, unused), reference queries by variable |
| `Instructions` (`InstDBAdapterV1`), `Data` (`DataDBAdapterV0`), `Comments` (`CommentsDBAdapterV1`) | `ProgramDb::instructions`, `data`, `comments` | rows only: instruction address, prototype id, flags; data address and data type id; the five comment kinds per address. NOT ported: instruction decoding (mnemonic, operands, length needs the language), data type resolution, code unit properties, equates |
| data types, equates, bookmarks, properties | none | NOT ported |
| Query facade for bindings | `ghidra_progdb::query::Program` (`open_file`, `open`, `parse_address`, `functions`, `function_at`, `function_containing`, `function_by_id`, `symbols_by_name`, `symbols_at`, `children`, `xrefs_to`, `xrefs_from`, `read_bytes`) | done. Owned data only, builds every index once at open (memory use is proportional to the program), `Send + Sync` whenever the buffer store is. `tests/query.rs` checks it against the oracle output on both fixtures. Module docs state the ordering of every list |
| older table versions (symbol V0..V3, memory V0..V2, address map V0) | `UnsupportedTableVersion` | refused on purpose: Java upgrades these |

## Address spaces

The database stores space names only. The caller passes `AddressSpaces` (name, id, bits, default
space) taken from the language; the differential test reads them from the oracle output. The
static `EXTERNAL`, `VARIABLE` and `HASH` spaces are added when missing.

## Tests

* `tests/oracle_diff.rs`: for both checked-in v32 fixtures (`legacy-12.1.4`,
  `legacy-12.1.4-analysed`) compares stored version, language, compiler, image base, every memory
  block with its sub blocks (name, start, end, size, flags, comment, source, parts) and every row
  of the symbol table (385 and 2912 rows: id, name, decoded address, parent, type, source,
  primary, pinned), every function (id, entry, thunk link, flags, calling convention, purge, signature
  source), every reference from and to an address (not stack/register destinations: Java refuses
  them), the instruction addresses, defined data (address, type id) and all comments, sorted by
  address like the oracle, plus the SHA-256 of every memory block's bytes and edge reads, with `testdata/oracleprog-*.txt`. Those files come from
  `oracle/OracleProgram.java`, which opens the same files through the stock Ghidra 12.2
  `ProgramDB` (`OpenMode.IMMUTABLE`). See `oracle/README.md` for the command line.
* `tests/versions.rs`: a copy of the fixture with the stored version patched to 33, 19, 34, 18
  and 10 opens or is refused with the expected error.
* There is no v33 fixture in the repository; v33 is covered only by the patched-version test (the
  table layouts of 32 and 33 are the same in the files we have).
* Not covered: refusal of old table versions (no fixture has one), overlay and mapped blocks,
  segmented spaces.
