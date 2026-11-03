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
//! A Ghidra project on disk, read-only: resolving what a client typed to a `.gpr`
//! (`ProjectResolver`), the folder and file index of the repository (`IndexedV1LocalFileSystem`,
//! `idata/~index.dat` and the `.prp` files), the project revision (`Revision`), and the stored
//! versions of the programs (`UpgradeCache.readStored`).
//!
//! Only the layout the current Ghidra writes is read: a version 1 index, database items, no
//! versioned (shared) file system. Anything else is refused, not interpreted.

#![expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "Java's String.endsWith is case sensitive and ProjectResolver relies on it"
)]

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use sha2::{Digest, Sha256};

use crate::error::{Failure, Reason, SessionError, refuse};
use crate::javaish::{
    absolute_path, compare_files, compare_strings, file_name, hash_order, join, parent,
};

/// Files up to this size are hashed into the revision (`UpgradeCache.HASH_LIMIT`).
pub const HASH_LIMIT: u64 = 1 << 20;

/// The depth `ProjectResolver` searches below a folder.
const MAX_DEPTH: usize = 2;

/// The MD5 line a version 1 index ends with: Java's digest is reset after every line it
/// "digests", so the check compares the MD5 of nothing.
const INDEX_MD5: &str = "MD5:d41d8cd98f00b204e9800998ecf8427e";

/// A project's directory and name: `NAME.gpr` and `NAME.rep` live in `dir`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Resolved {
    /// The directory, as `File.getPath()` writes it.
    pub dir: String,
    /// The project name (the `.gpr` without its extension).
    pub name: String,
}

impl Resolved {
    /// The `.gpr` path.
    #[must_use]
    pub fn gpr(&self) -> String {
        join(&self.dir, &format!("{}.gpr", self.name))
    }

    /// The `.rep` path.
    #[must_use]
    pub fn rep(&self) -> String {
        join(&self.dir, &format!("{}.rep", self.name))
    }

    /// `ProjectFork.sidecar`: the fork record next to the `.gpr`.
    #[must_use]
    pub fn sidecar(&self) -> String {
        join(&self.dir, &format!("{}.fork.json", self.name))
    }

    /// The repository's file index.
    #[must_use]
    pub fn index_file(&self) -> PathBuf {
        PathBuf::from(self.rep()).join("idata").join("~index.dat")
    }
}

fn not_found(msg: String) -> Failure {
    SessionError::not_found(msg).into()
}

fn unsupported(msg: impl Into<String>) -> Failure {
    refuse(Reason::UnsupportedProject, msg)
}

fn is_file(p: &str) -> bool {
    fs::metadata(p).is_ok_and(|m| m.is_file())
}

fn is_dir(p: &str) -> bool {
    fs::metadata(p).is_ok_and(|m| m.is_dir())
}

/// `ProjectResolver.resolve`: a `.gpr`, a `.rep`, the folder holding a `.gpr`, or a folder with
/// exactly one project below it.
///
/// # Errors
///
/// `not_found` with Java's message; a refusal for a path or a name this does not reproduce.
pub fn resolve(path: &str) -> Result<Resolved, Failure> {
    let cwd = std::env::current_dir()
        .map_err(|e| unsupported(format!("no working directory: {e}")))?
        .display()
        .to_string();
    let f = absolute_path(path, &cwd).ok_or_else(|| {
        refuse(
            Reason::InexactValue,
            "a drive-relative path is not resolved here",
        )
    })?;
    if fs::metadata(&f).is_err() {
        return Err(not_found(format!("Path does not exist: {f}")));
    }
    if is_file(&f) {
        if !file_name(&f).ends_with(".gpr") {
            return Err(not_found(format!("Not a .gpr file: {f}")));
        }
        return from_gpr(&f);
    }
    if file_name(&f).ends_with(".rep") {
        let name = &file_name(&f)[..file_name(&f).len() - 4];
        let par = parent(&f).ok_or_else(|| unsupported("a .rep at the root of a drive"))?;
        let gpr = join(par, &format!("{name}.gpr"));
        if is_file(&gpr) {
            return from_gpr(&gpr);
        }
    }
    let mut found = Vec::new();
    search(&f, 0, &mut found)?;
    match found.len() {
        1 => from_gpr(&found[0]),
        0 => Err(not_found(format!(
            "No Ghidra project (.gpr) found in or below {f}"
        ))),
        _ => {
            let mut msg = format!("Several Ghidra projects found below {f}; pass one .gpr path:");
            for g in &found {
                msg.push_str("\n  ");
                msg.push_str(g);
            }
            Err(not_found(msg))
        }
    }
}

fn from_gpr(gpr: &str) -> Result<Resolved, Failure> {
    let n = file_name(gpr);
    let name = n[..n.len() - 4].to_owned();
    let dir = parent(gpr)
        .ok_or_else(|| unsupported("a .gpr at the root of a drive"))?
        .to_owned();
    if !is_dir(&join(&dir, &format!("{name}.rep"))) {
        return Err(not_found(format!("Missing {name}.rep next to {gpr}")));
    }
    Ok(Resolved { dir, name })
}

fn search(dir: &str, depth: usize, found: &mut Vec<String>) -> Result<(), Failure> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Ok(()); // listFiles() null
    };
    let mut names = Vec::new();
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if !n.is_ascii() {
            return Err(refuse(
                Reason::InexactValue,
                format!("{dir} holds a name that is not ASCII; its order is Java's to decide"),
            ));
        }
        names.push(n);
    }
    names.sort_by(|a, b| compare_files(a, b).unwrap_or(Ordering::Equal));
    for n in &names {
        let c = join(dir, n);
        if n.ends_with(".gpr") && is_file(&c) {
            found.push(c);
        }
    }
    if !found.is_empty() || depth >= MAX_DEPTH {
        return Ok(());
    }
    for n in &names {
        let c = join(dir, n);
        if is_dir(&c) && !n.ends_with(".rep") {
            search(&c, depth + 1, found)?;
        }
    }
    Ok(())
}

/// The key two paths to one project share (`getCanonicalPath` of the `.gpr`).
#[must_use]
pub fn canonical(r: &Resolved) -> String {
    let gpr = r.gpr();
    match fs::canonicalize(&gpr) {
        Ok(p) => {
            let s = p.display().to_string();
            s.strip_prefix("\\\\?\\").map_or(s.clone(), str::to_owned)
        }
        Err(_) => gpr,
    }
}

// ---- what the full daemon would clean up before an open -----------------------------------------

/// The name of something in `dir` that `ForkSweeper.sweepForOpen` would delete or resume before
/// the full daemon opens a project there (a staging folder of a fork, the temporary file of a
/// sidecar write, an old `tmp*.tmp`). The lite daemon writes nothing, so it leaves the directory
/// to the full daemon.
#[must_use]
pub fn sweep_pending(dir: &str) -> Option<String> {
    let rd = fs::read_dir(dir).ok()?;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Ok(ft) = e.file_type() else { continue };
        let staging = name.starts_with('.')
            && name.ends_with(".tmp")
            && name.rfind(".fork-").is_some_and(|i| i > 0);
        if ft.is_dir() && staging {
            return Some(name);
        }
        if ft.is_file()
            && (is_writer_tmp(&name) || is_old_tmp(&name) || name == ".ghidra.test.lock~~")
        {
            return Some(name);
        }
    }
    None
}

/// `(.+)\.(\d{1,10})\.tmp` whose base is a fork sidecar or the seal marker.
fn is_writer_tmp(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".tmp") else {
        return false;
    };
    let Some(dot) = stem.rfind('.') else {
        return false;
    };
    let (base, pid) = (&stem[..dot], &stem[dot + 1..]);
    !base.is_empty()
        && (1..=10).contains(&pid.len())
        && pid.bytes().all(|b| b.is_ascii_digit())
        && (base.ends_with(".fork.json") || base == "SEALED.json")
}

/// `tmp.*\.(tmp|ps)`.
fn is_old_tmp(name: &str) -> bool {
    name.starts_with("tmp") && (name.ends_with(".tmp") || name.ends_with(".ps"))
}

// ---- revision ---------------------------------------------------------------------------------

fn mtime_ms(m: &fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// `tmp<digits>.ps` or `tmp<digits>.tmp`: Ghidra's transient files inside a `.rep`.
fn is_transient(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("tmp") else {
        return false;
    };
    let Some(dot) = rest.find('.') else {
        return false;
    };
    let (digits, ext) = rest.split_at(dot);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (ext == ".ps" || ext == ".tmp")
}

fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<Vec<u16>, (String, PathBuf)>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(m) = fs::metadata(&p) else { continue };
        if m.is_dir() {
            walk(&p, base, out);
        } else if m.is_file() {
            let name = e.file_name().to_string_lossy().into_owned();
            if is_transient(&name) {
                continue;
            }
            if let Ok(rel) = p.strip_prefix(base) {
                let key = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.insert(key.encode_utf16().collect(), (key, p));
            }
        }
    }
}

/// `Revision.of`: a fingerprint of what is saved in the project, 16 hex digits.
///
/// # Errors
///
/// The I/O error when the project cannot be read.
pub fn revision(r: &Resolved) -> io::Result<String> {
    let gpr = PathBuf::from(r.gpr());
    let base = gpr
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("a .gpr without a directory"))?;
    let mut files: BTreeMap<Vec<u16>, (String, PathBuf)> = BTreeMap::new();
    let gpr_key = format!("{}.gpr", r.name);
    files.insert(gpr_key.encode_utf16().collect(), (gpr_key, gpr));
    let rep = PathBuf::from(r.rep());
    if rep.is_dir() {
        walk(&rep, &base, &mut files);
    }
    let state = format!("{}.rep/projectState", r.name);
    let mut md = Sha256::new();
    for (key, path) in files.values() {
        let Ok(m) = fs::metadata(path) else { continue };
        if *key == state {
            continue;
        }
        md.update(format!("|{key}|{}|{}", m.len(), mtime_ms(&m)).as_bytes());
        if m.len() <= HASH_LIMIT {
            match fs::read(path) {
                Ok(bytes) => md.update(&bytes),
                Err(e) if e.kind() == io::ErrorKind::NotFound => md.update(b"|gone"),
                Err(e) => return Err(e),
            }
        }
    }
    Ok(hex16(&md.finalize()))
}

/// `Revision.ofProgram`: a program's saved revision from its path and its stored file.
#[must_use]
pub fn program_revision(path: &str, length: u64, modified_ms: i64, version: u32) -> String {
    let mut md = Sha256::new();
    md.update(format!("{path}|{length}|{modified_ms}|{version}").as_bytes());
    hex16(&md.finalize())
}

fn hex16(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(16);
    for b in digest.iter().take(8) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---- the repository index and the items -------------------------------------------------------

/// One item of the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexItem {
    /// The item name (the file name in the project).
    pub name: String,
    /// The storage name (`00000000`).
    pub storage: String,
}

/// The folders and items of a repository, as `~index.dat` lists them.
#[derive(Debug, Clone, Default)]
pub struct Index {
    /// Folder path (`/`, `/a/b`) to its items in index order.
    folders: BTreeMap<String, Vec<IndexItem>>,
}

impl Index {
    /// Reads a version 1 index.
    ///
    /// # Errors
    ///
    /// A refusal when the file is missing, not version 1, or not exactly the shape Java reads.
    pub fn read(file: &Path) -> Result<Self, Failure> {
        let text = fs::read(file).map_err(|e| unsupported(format!("{}: {e}", file.display())))?;
        let text = String::from_utf8(text)
            .map_err(|_| unsupported("the repository index is not UTF-8"))?;
        let mut lines = text.lines();
        if lines.next() != Some("VERSION=1") {
            return Err(unsupported("the repository index is not version 1"));
        }
        let mut folders: BTreeMap<String, Vec<IndexItem>> = BTreeMap::new();
        folders.insert("/".to_owned(), Vec::new());
        let mut current: Option<String> = None;
        let mut next_id = false;
        let mut md5 = false;
        for line in lines {
            if md5 {
                return Err(unsupported("the repository index has lines after its MD5"));
            }
            if line.starts_with("MD5:") {
                if line != INDEX_MD5 || !next_id {
                    return Err(unsupported(
                        "the repository index does not end as Java checks",
                    ));
                }
                md5 = true;
            } else if let Some(id) = line.strip_prefix("NEXT-ID:") {
                if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(unsupported("the repository index has a bad NEXT-ID"));
                }
                next_id = true;
            } else if line.starts_with('/') {
                if next_id {
                    return Err(unsupported(
                        "a folder after NEXT-ID in the repository index",
                    ));
                }
                let mut path = String::new();
                for part in line.split('/').filter(|p| !p.is_empty()) {
                    path.push('/');
                    path.push_str(part);
                    folders.entry(path.clone()).or_default();
                }
                let key = if path.is_empty() {
                    "/".to_owned()
                } else {
                    path
                };
                folders.entry(key.clone()).or_default();
                current = Some(key);
            } else if let Some(entry) = line.strip_prefix("  ") {
                if next_id {
                    return Err(unsupported("an item after NEXT-ID in the repository index"));
                }
                let Some(folder) = &current else {
                    return Err(unsupported("an item before any folder in the index"));
                };
                let (storage, rest) = entry
                    .split_once(':')
                    .ok_or_else(|| unsupported("a repository index item without a name"))?;
                let name = match rest.split_once(':') {
                    Some((n, _file_id)) if !n.is_empty() => n,
                    _ => rest,
                };
                folders.entry(folder.clone()).or_default().push(IndexItem {
                    name: name.to_owned(),
                    storage: storage.to_owned(),
                });
            } else {
                return Err(unsupported("an unreadable line in the repository index"));
            }
        }
        if !md5 {
            return Err(unsupported("the repository index has no MD5 line"));
        }
        Ok(Self { folders })
    }

    /// `getItemCount`: every item of every folder.
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.folders.values().map(Vec::len).sum()
    }

    /// The folder at `path` (`/` or `/a/b`), if it exists.
    #[must_use]
    pub fn folder(&self, path: &str) -> Option<&Vec<IndexItem>> {
        self.folders.get(path)
    }

    /// The sub folders of a folder, by name in `String` order (a `TreeSet`).
    #[must_use]
    pub fn sub_folders(&self, path: &str) -> Vec<String> {
        let prefix = if path == "/" {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        let mut out: Vec<String> = self
            .folders
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix))
            .filter(|rest| !rest.is_empty() && !rest.contains('/'))
            .map(str::to_owned)
            .collect();
        out.sort_by(|a, b| compare_strings(a, b));
        out
    }

    /// The names of the files of a folder in the order `DomainFolder.getFiles()` lists them:
    /// the iteration order of a Java `HashMap` of the names. `None` when that order depends on
    /// more than the names (two names in one bucket: it then depends on lookup history).
    #[must_use]
    pub fn file_order(&self, path: &str) -> Option<Vec<&IndexItem>> {
        let items = self.folders.get(path)?;
        let mut sorted: Vec<&IndexItem> = items.iter().collect();
        sorted.sort_by(|a, b| compare_strings(&a.name, &b.name));
        let names: Vec<&str> = sorted.iter().map(|i| i.name.as_str()).collect();
        let ordered = hash_order(&names)?;
        // a bucket shared by two names makes the order depend on how the folder was reached
        let mut seen = std::collections::HashSet::new();
        let cap = crate::javaish::table_size(names.len());
        for n in &names {
            let b = usize::try_from(crate::javaish::spread(crate::javaish::string_hash(n))).ok()?
                & (cap - 1);
            if !seen.insert(b) {
                return None;
            }
        }
        Some(
            ordered
                .iter()
                .filter_map(|n| sorted.iter().find(|i| i.name == *n).copied())
                .collect(),
        )
    }
}

/// The properties of an item (`<storage>.prp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemProps {
    /// `CONTENT_TYPE`.
    pub content_type: String,
    /// `FILE_TYPE` (0 is a database).
    pub file_type: i32,
    /// `NAME`.
    pub name: String,
    /// `PARENT`.
    pub parent: String,
}

fn storage_dir(idata: &Path, storage: &str) -> Option<PathBuf> {
    let len = storage.len();
    if len < 3 || !storage.is_ascii() {
        return None;
    }
    Some(idata.join(&storage[len - 3..len - 1]))
}

fn xml_unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let end = tail.find(';')?;
        match &tail[1..end] {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            n if n.starts_with('#') => {
                let code = n.strip_prefix("#x").map_or_else(
                    || n[1..].parse::<u32>().ok(),
                    |h| u32::from_str_radix(h, 16).ok(),
                )?;
                out.push(char::from_u32(code)?);
            }
            _ => return None,
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let pat = format!("{name}=\"");
    let start = tag.find(&pat)? + pat.len();
    let len = tag[start..].find('"')?;
    Some(&tag[start..start + len])
}

/// Reads an item's property file.
///
/// # Errors
///
/// A refusal when the file is missing or not the shape Ghidra writes.
pub fn read_props(idata: &Path, item: &IndexItem) -> Result<ItemProps, Failure> {
    let dir = storage_dir(idata, &item.storage)
        .ok_or_else(|| unsupported(format!("storage name {}", item.storage)))?;
    let file = dir.join(format!("{}.prp", item.storage));
    let text =
        fs::read_to_string(&file).map_err(|e| unsupported(format!("{}: {e}", file.display())))?;
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for chunk in text.split("<STATE ").skip(1) {
        let tag = chunk.split("/>").next().unwrap_or_default();
        let (Some(n), Some(v)) = (attr(tag, "NAME"), attr(tag, "VALUE")) else {
            return Err(unsupported(format!(
                "{}: a STATE without NAME and VALUE",
                file.display()
            )));
        };
        let v = xml_unescape(v)
            .ok_or_else(|| unsupported(format!("{}: an XML entity", file.display())))?;
        map.insert(n.to_owned(), v);
    }
    let get = |k: &str| {
        map.get(k)
            .cloned()
            .ok_or_else(|| unsupported(format!("{}: no {k}", file.display())))
    };
    let props = ItemProps {
        content_type: get("CONTENT_TYPE")?,
        file_type: get("FILE_TYPE")?
            .parse()
            .map_err(|_| unsupported(format!("{}: FILE_TYPE", file.display())))?,
        name: get("NAME")?,
        parent: get("PARENT")?,
    };
    if props.name != item.name {
        return Err(unsupported(format!(
            "{}: the property file names the item {}, the index {}",
            file.display(),
            props.name,
            item.name
        )));
    }
    Ok(props)
}

/// The current stored version of a database item: the highest `db.N.gbf` of its directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    /// The `db.N.gbf` file.
    pub path: PathBuf,
    /// `N`, the item's current version.
    pub version: u32,
    /// The file length (`DomainFile.length()`).
    pub length: u64,
    /// The file's modification time in milliseconds (`DomainFile.getLastModifiedTime()`).
    pub modified_ms: i64,
}

/// Finds the stored file of a database item.
///
/// # Errors
///
/// A refusal when the item directory has no version file.
pub fn stored_file(idata: &Path, item: &IndexItem) -> Result<StoredFile, Failure> {
    let dir = storage_dir(idata, &item.storage)
        .ok_or_else(|| unsupported(format!("storage name {}", item.storage)))?
        .join(format!("~{}.db", item.storage));
    let rd = fs::read_dir(&dir).map_err(|e| unsupported(format!("{}: {e}", dir.display())))?;
    let mut best: Option<(u32, PathBuf)> = None;
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if let Some(mid) = n.strip_prefix("db.").and_then(|r| r.strip_suffix(".gbf"))
            && !mid.is_empty()
            && mid.bytes().all(|b| b.is_ascii_digit())
            && let Ok(v) = mid.parse::<u32>()
            && best.as_ref().is_none_or(|(b, _)| v > *b)
        {
            best = Some((v, e.path()));
        }
    }
    let (version, path) =
        best.ok_or_else(|| unsupported(format!("{}: no db.N.gbf", dir.display())))?;
    let m = fs::metadata(&path).map_err(|e| unsupported(format!("{}: {e}", path.display())))?;
    Ok(StoredFile {
        path,
        version,
        length: m.len(),
        modified_ms: mtime_ms(&m),
    })
}

/// The program database of an item, opened for its header.
///
/// # Errors
///
/// The error text when the file cannot be opened or is not a program database.
pub fn read_header(path: &Path) -> Result<ghidra_progdb::Header, String> {
    let file = ghidra_fmt_gbf::BufferFile::open(path, true).map_err(|e| e.to_string())?;
    ghidra_progdb::read_header(file).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_files_are_the_two_ghidra_kinds() {
        assert!(is_transient("tmp12.ps"), "a pre-save copy");
        assert!(is_transient("tmp7.tmp"), "a temporary database item file");
        assert!(!is_transient("tmp.ps"), "digits are required");
        assert!(!is_transient("tmp12.dat"), "other extensions stay");
        assert!(!is_transient("xtmp1.ps"), "the whole name matches");
    }

    #[test]
    fn sweep_candidates_are_the_files_the_full_daemon_removes() {
        assert!(is_writer_tmp("X.fork.json.123.tmp"), "a sidecar write");
        assert!(is_writer_tmp("SEALED.json.7.tmp"), "a marker write");
        assert!(!is_writer_tmp("other.123.tmp"), "another base");
        assert!(is_old_tmp("tmp-abc.ps"), "a temporary copy");
        assert!(!is_old_tmp("Fixture.gpr"), "a project file");
    }

    #[test]
    fn xml_entities() {
        assert_eq!(
            xml_unescape("a&amp;b&#65;&#x42;").as_deref(),
            Some("a&bAB"),
            "known ones"
        );
        assert_eq!(xml_unescape("&nbsp;"), None, "an unknown entity is refused");
    }

    #[test]
    fn index_text_is_read_as_java_reads_it() {
        let dir = std::env::temp_dir().join(format!("hl-index-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("mkdir");
        let f = dir.join("~index.dat");
        fs::write(
            &f,
            "VERSION=1\n/\n  00000000:alpha.exe:647bf976ce29145157920811000\n  00000001:beta.exe:647bf976ce2c145165175773400\n/sub\n  00000002:frag.exe:1\nNEXT-ID:3\nMD5:d41d8cd98f00b204e9800998ecf8427e\n",
        )
        .expect("write");
        let ix = Index::read(&f).expect("reads");
        assert_eq!(ix.item_count(), 3, "three items");
        assert_eq!(ix.sub_folders("/"), ["sub"], "one sub folder");
        let names: Vec<&str> = ix
            .file_order("/")
            .expect("order")
            .iter()
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["beta.exe", "alpha.exe"],
            "HashMap order of the two names"
        );
        fs::write(&f, "VERSION=1\n/\nNEXT-ID:3\nMD5:00\n").expect("write");
        assert!(Index::read(&f).is_err(), "a wrong MD5 line is refused");
        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
