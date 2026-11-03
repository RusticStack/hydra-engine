/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! A program opened read-only from its database file, reduced to what the lite commands answer:
//! the fields of `info` and the function table of `functions`.
//!
//! Everything here is checked when the program is opened. A program this build cannot present
//! exactly (another format version, another language, a function in a namespace, memory that is
//! mapped or in an overlay) is refused at `open_program`, never half answered later.

use std::path::Path;

use ghidra_fmt_gbf::BufferFile;
use ghidra_progdb::query::Program;
use ghidra_progdb::{Address, AddressSpaces, MemoryBlock, ProgramOption, SpaceDef, SubBlockKind};

use crate::error::{Failure, Reason, refuse};
use crate::project::StoredFile;

/// The program database version of Ghidra 12.3 (`ProgramDB.DB_VERSION`).
pub const PROGRAM_DB_VERSION: i64 = 33;
/// The data type manager database version of Ghidra 12.3.
pub const DATA_TYPE_DB_VERSION: i64 = 3;
/// The one language this build presents.
pub const LANGUAGE_ID: &str = "x86:LE:64:default";
/// Its version in Ghidra 12.3 (`major.minor`).
pub const LANGUAGE_VERSION: &str = "4.9";

const OPTION_PREFIX: &str = "Program Information.";

/// One row of the `functions` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRow {
    /// `Function.getName(true)`.
    pub name: String,
    /// `hex(entry)`.
    pub address: String,
    /// `getBody().getNumAddresses()`.
    pub size: u64,
    /// `isThunk()`.
    pub thunk: bool,
}

/// An opened program.
#[derive(Debug, Clone)]
pub struct ProgramView {
    /// The domain file name (`Program.getName()`).
    pub name: String,
    /// `getLanguageID()`.
    pub language: String,
    /// `getCompilerSpec().getCompilerSpecID()`.
    pub compiler: String,
    /// `hex(getImageBase())`.
    pub image_base: String,
    /// `getExecutableFormat()`.
    pub format: Option<String>,
    /// `getExecutablePath()`.
    pub executable: Option<String>,
    /// `getExecutableSHA256()`.
    pub sha256: Option<String>,
    /// `getExecutableMD5()`.
    pub md5: Option<String>,
    /// `getFunctionManager().getFunctionCount()`.
    pub function_count: usize,
    /// `GhidraProgramUtilities.isAnalyzed`.
    pub analyzed: bool,
    /// The functions of the program's memory in address order.
    pub functions: Vec<FunctionRow>,
}

fn bad(msg: impl Into<String>) -> Failure {
    refuse(Reason::UnsupportedProgram, msg)
}

/// The address spaces of `x86:LE:64:default`.
#[must_use]
pub fn x86_64_spaces() -> AddressSpaces {
    let space = |name: &str, id: i32, bits: u32| SpaceDef {
        name: name.to_owned(),
        id,
        bits,
    };
    AddressSpaces::new(
        vec![
            space("EXTERNAL", 42, 32),
            space("const", 48, 64),
            space("stack", 53, 64),
            space("HASH", 126, 60),
            space("OTHER", 183, 64),
            space("unique", 291, 32),
            space("ram", 433, 64),
            space("register", 548, 32),
        ],
        "ram",
    )
}

/// Checks the stored versions and the language of a header (`ProjectFormat.need`): the program
/// must be exactly current, so that Java opens it as it is.
///
/// # Errors
///
/// A refusal naming what differs.
pub fn check_header(h: &ghidra_progdb::Header) -> Result<(), Failure> {
    let version = |map: &std::collections::BTreeMap<String, String>| -> i64 {
        map.get("DB Version")
            .and_then(|v| v.trim().parse::<i64>().ok())
            .unwrap_or(1)
    };
    let v = version(&h.program);
    if v != PROGRAM_DB_VERSION {
        return Err(bad(format!(
            "program database version {v}, this build presents {PROGRAM_DB_VERSION}"
        )));
    }
    if let Some(dt) = &h.data_type_manager {
        let d = version(dt);
        if d != DATA_TYPE_DB_VERSION {
            return Err(bad(format!(
                "data type database version {d}, this build presents {DATA_TYPE_DB_VERSION}"
            )));
        }
    }
    match h.program.get("Language ID").map(String::as_str) {
        Some(LANGUAGE_ID) => {}
        other => {
            return Err(bad(format!(
                "language {}, this build presents {LANGUAGE_ID}",
                other.unwrap_or("(none)")
            )));
        }
    }
    match h.program.get("Language Version").map(String::as_str) {
        Some(LANGUAGE_VERSION) => Ok(()),
        other => Err(bad(format!(
            "language version {}, this build presents {LANGUAGE_VERSION}",
            other.unwrap_or("(none)")
        ))),
    }
}

fn string_option(opts: &[ProgramOption], name: &str) -> Result<Option<String>, Failure> {
    let key = format!("{OPTION_PREFIX}{name}");
    match opts.iter().find(|o| o.key == key) {
        None => Ok(None),
        Some(o) if o.type_name() == Some("STRING_TYPE") => Ok(Some(o.value.clone())),
        Some(o) => Err(bad(format!(
            "option {key} is not a string ({:?})",
            o.type_name()
        ))),
    }
}

fn analyzed(opts: &[ProgramOption]) -> Result<bool, Failure> {
    let key = format!("{OPTION_PREFIX}Analyzed");
    match opts.iter().find(|o| o.key == key) {
        None => Ok(false),
        Some(o) if o.type_name() == Some("BOOLEAN_TYPE") => match o.value.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            other => Err(bad(format!("option {key} holds {other:?}"))),
        },
        Some(o) => Err(bad(format!(
            "option {key} is not a boolean ({:?})",
            o.type_name()
        ))),
    }
}

fn hex_ram(a: &Address) -> Option<String> {
    match a {
        Address::Space { space, offset } if space == "ram" => Some(format!("0x{offset:x}")),
        _ => None,
    }
}

/// The ranges of the memory blocks as `(min, max)` offsets of `ram`, sorted.
fn memory_ranges(blocks: &[MemoryBlock]) -> Result<Vec<(u64, u64)>, Failure> {
    let mut out = Vec::with_capacity(blocks.len());
    for b in blocks {
        if b.is_mapped()
            || b.sub_blocks.iter().any(|s| {
                !matches!(
                    s.kind,
                    SubBlockKind::Buffer | SubBlockKind::Uninitialized | SubBlockKind::FileBytes
                )
            })
        {
            return Err(bad(format!("memory block {} is mapped", b.name)));
        }
        let Address::Space { space, offset } = &b.start else {
            return Err(bad(format!("memory block {} has no address", b.name)));
        };
        if space != "ram" {
            return Err(bad(format!("memory block {} is in space {space}", b.name)));
        }
        let len = u64::try_from(b.length).map_err(|_| bad("a negative block length"))?;
        if len == 0 {
            return Err(bad(format!("memory block {} is empty", b.name)));
        }
        out.push((*offset, offset.saturating_add(len - 1)));
    }
    out.sort_unstable();
    Ok(out)
}

fn in_memory(ranges: &[(u64, u64)], offset: u64) -> bool {
    let i = ranges.partition_point(|&(min, _)| min <= offset);
    i > 0 && ranges[i - 1].1 >= offset
}

/// Opens the stored file read-only and reads what the lite commands need.
///
/// # Errors
///
/// A refusal when the program is not exactly presentable by this build.
pub fn open(stored: &StoredFile, name: &str) -> Result<ProgramView, Failure> {
    open_path(&stored.path, name)
}

/// [`open`] on a file path.
///
/// # Errors
///
/// As [`open`].
pub fn open_path(path: &Path, name: &str) -> Result<ProgramView, Failure> {
    let header = crate::project::read_header(path).map_err(|e| bad(format!("header: {e}")))?;
    check_header(&header)?;
    let file = BufferFile::open(path, true).map_err(|e| bad(format!("{}: {e}", path.display())))?;
    let program =
        Program::open_lazy(file, x86_64_spaces()).map_err(|e| bad(format!("open: {e}")))?;
    let db = program.db();
    let compiler = db
        .compiler_spec_id()
        .ok_or_else(|| bad("no compiler spec id"))?
        .to_owned();
    let language = db
        .language_id()
        .ok_or_else(|| bad("no language id"))?
        .to_owned();
    let base = u64::try_from(db.image_base_offset()).map_err(|_| bad("a negative image base"))?;
    let options = program
        .options()
        .map_err(|e| bad(format!("options: {e}")))?;
    let blocks = db
        .memory_blocks()
        .map_err(|e| bad(format!("memory: {e}")))?;
    let ranges = memory_ranges(&blocks)?;
    program
        .prepare()
        .map_err(|e| bad(format!("indexes: {e}")))?;
    let mut rows: Vec<(u64, FunctionRow)> = Vec::new();
    let all = program.functions();
    for f in all {
        let Address::Space { space, offset } = &f.entry else {
            continue;
        };
        if space != "ram" || !in_memory(&ranges, *offset) {
            continue;
        }
        if f.namespace_id != 0 {
            return Err(bad(format!("function at 0x{offset:x} is in a namespace")));
        }
        let Some(name) = f.name.clone() else {
            return Err(bad(format!("function at 0x{offset:x} has no name")));
        };
        let size = f
            .body
            .iter()
            .map(|r| r.max - r.min + 1)
            .try_fold(0u64, u64::checked_add)
            .ok_or_else(|| bad("a function body overflows"))?;
        let address = hex_ram(&f.entry).ok_or_else(|| bad("a function outside ram"))?;
        rows.push((
            *offset,
            FunctionRow {
                name,
                address,
                size,
                thunk: f.thunk_target.is_some(),
            },
        ));
    }
    if let Some(e) = program.deferred_error() {
        return Err(bad(format!("damaged table: {e}")));
    }
    rows.sort_by_key(|(o, _)| *o);
    Ok(ProgramView {
        name: name.to_owned(),
        language,
        compiler,
        image_base: format!("0x{base:x}"),
        format: string_option(options, "Executable Format")?,
        executable: string_option(options, "Executable Location")?,
        sha256: string_option(options, "Executable SHA256")?,
        md5: string_option(options, "Executable MD5")?,
        function_count: all.len(),
        analyzed: analyzed(options)?,
        functions: rows.into_iter().map(|(_, r)| r).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn header(version: &str, lang: &str, lv: &str) -> ghidra_progdb::Header {
        let program: BTreeMap<String, String> = [
            ("DB Version", version),
            ("Language ID", lang),
            ("Language Version", lv),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        ghidra_progdb::Header {
            program,
            data_type_manager: Some(
                [("DB Version".to_owned(), "3".to_owned())]
                    .into_iter()
                    .collect(),
            ),
            metadata: Vec::new(),
        }
    }

    #[test]
    fn only_the_current_x86_64_program_is_presented() {
        assert!(
            check_header(&header("33", LANGUAGE_ID, "4.9")).is_ok(),
            "current"
        );
        assert!(
            check_header(&header("32", LANGUAGE_ID, "4.9")).is_err(),
            "older database"
        );
        assert!(
            check_header(&header("33", "ARM:LE:32:v8", "1.0")).is_err(),
            "another language"
        );
        assert!(
            check_header(&header("33", LANGUAGE_ID, "4.8")).is_err(),
            "older language"
        );
        let mut h = header("33", LANGUAGE_ID, "4.9");
        h.data_type_manager = Some(
            [("DB Version".to_owned(), "2".to_owned())]
                .into_iter()
                .collect(),
        );
        assert!(check_header(&h).is_err(), "older data types");
    }

    #[test]
    fn memory_membership_uses_block_ranges() {
        let r = [(0x1000, 0x1fff), (0x3000, 0x3000)];
        assert!(in_memory(&r, 0x1000), "first byte");
        assert!(in_memory(&r, 0x1fff), "last byte");
        assert!(!in_memory(&r, 0x2000), "gap");
        assert!(in_memory(&r, 0x3000), "single byte block");
        assert!(!in_memory(&r, 0xfff), "before");
    }
}
