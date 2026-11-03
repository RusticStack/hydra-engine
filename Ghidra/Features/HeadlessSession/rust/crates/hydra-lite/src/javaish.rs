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
//! The few Java behaviours that decide the order or the text of an answer: `String.hashCode`
//! and the iteration order of a `HashMap` / `ConcurrentHashMap` of strings, `String` order,
//! and `java.io.File` path text on Windows.

use std::cmp::Ordering;

/// `String.hashCode()`.
#[must_use]
pub fn string_hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for u in s.encode_utf16() {
        h = h.wrapping_mul(31).wrapping_add(i32::from(u));
    }
    h
}

/// `HashMap.hash(key)`: the hash with its high half folded in.
#[must_use]
pub fn spread(h: i32) -> u32 {
    let u = h.cast_unsigned();
    u ^ (u >> 16)
}

/// The table size a `HashMap` of default capacity has after `count` insertions.
#[must_use]
pub fn table_size(count: usize) -> usize {
    let mut cap = 16usize;
    // resize() runs when ++size > threshold, threshold = 0.75 * capacity
    while count > cap / 4 * 3 {
        cap *= 2;
    }
    cap
}

/// The iteration order of a default `HashMap<String, _>` (or `HashSet<String>`) into which
/// `keys` were inserted in the order given: by bucket, and within a bucket by insertion.
///
/// `None` when some bucket holds nine or more keys: Java then treeifies it (or grows the table),
/// and the order is no longer the simple one.
#[must_use]
pub fn hash_order<'a>(keys: &[&'a str]) -> Option<Vec<&'a str>> {
    let cap = table_size(keys.len());
    let mut buckets: Vec<Vec<&str>> = vec![Vec::new(); cap];
    for k in keys {
        let idx = usize::try_from(spread(string_hash(k))).ok()? & (cap - 1);
        buckets[idx].push(k);
        if buckets[idx].len() >= 9 {
            return None;
        }
    }
    Some(buckets.into_iter().flatten().collect())
}

/// `ConcurrentHashMap.spread`: the hash with its high half folded in and the sign bit cleared.
#[must_use]
pub fn chm_spread(h: i32) -> u32 {
    (h.cast_unsigned() ^ (h.cast_unsigned() >> 16)) & 0x7fff_ffff
}

/// The iteration order of a `ConcurrentHashMap<String, _>` that only ever holds the keys given to
/// [`ChmOrder::insert`] and not removed by [`ChmOrder::remove`]: the bins are walked in index
/// order, a bin's chain in its own order, and a resize splits every chain the way
/// `ConcurrentHashMap.transfer` does (the run of nodes that stay together at the tail is kept, the
/// nodes before it are put at the front in reverse). The table never shrinks.
///
/// Not modelled: a bin that reaches eight nodes (Java then treeifies it or grows the table); the
/// model notes it and [`ChmOrder::order`] gives `None` from then on.
#[derive(Debug, Clone)]
pub struct ChmOrder {
    bins: Vec<Vec<String>>,
    count: usize,
    size_ctl: usize,
    exact: bool,
}

impl Default for ChmOrder {
    fn default() -> Self {
        Self::new()
    }
}

impl ChmOrder {
    /// An empty map of default capacity.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bins: vec![Vec::new(); 16],
            count: 0,
            size_ctl: 12,
            exact: true,
        }
    }

    fn index(&self, key: &str) -> usize {
        usize::try_from(chm_spread(string_hash(key))).map_or(0, |h| h & (self.bins.len() - 1))
    }

    /// `put` of a key that may already be there (then nothing changes).
    pub fn insert(&mut self, key: &str) {
        let i = self.index(key);
        if self.bins[i].iter().any(|k| k == key) {
            return;
        }
        self.bins[i].push(key.to_owned());
        if self.bins[i].len() >= 8 {
            self.exact = false;
        }
        self.count += 1;
        while self.count >= self.size_ctl {
            self.transfer();
        }
    }

    /// `remove` of a key.
    pub fn remove(&mut self, key: &str) {
        let i = self.index(key);
        if let Some(at) = self.bins[i].iter().position(|k| k == key) {
            self.bins[i].remove(at);
            self.count -= 1;
        }
    }

    fn transfer(&mut self) {
        let n = self.bins.len();
        let mut next: Vec<Vec<String>> = vec![Vec::new(); n * 2];
        for (i, chain) in self.bins.iter().enumerate() {
            if chain.is_empty() {
                continue;
            }
            let bit = |k: &String| -> bool {
                usize::try_from(chm_spread(string_hash(k))).is_ok_and(|h| h & n != 0)
            };
            let mut run_bit = bit(&chain[0]);
            let mut last_run = 0;
            for (j, k) in chain.iter().enumerate().skip(1) {
                let b = bit(k);
                if b != run_bit {
                    run_bit = b;
                    last_run = j;
                }
            }
            let (mut lo, mut hi): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
            for k in &chain[..last_run] {
                if bit(k) {
                    hi.insert(0, k.clone());
                } else {
                    lo.insert(0, k.clone());
                }
            }
            let tail = chain[last_run..].iter().cloned();
            if run_bit {
                hi.extend(tail);
            } else {
                lo.extend(tail);
            }
            next[i] = lo;
            next[i + n] = hi;
        }
        self.bins = next;
        self.size_ctl = n * 2 - n / 2;
    }

    /// The keys in iteration order; `None` once the model left what it can follow.
    #[must_use]
    pub fn order(&self) -> Option<Vec<&str>> {
        self.exact
            .then(|| self.bins.iter().flatten().map(String::as_str).collect())
    }
}

/// `String.compareTo`: UTF-16 code unit order.
#[must_use]
pub fn compare_strings(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `java.io.File.compareTo` on Windows: `compareToIgnoreCase` of the path text. Only ASCII is
/// compared exactly; `None` when either text is not ASCII.
#[must_use]
pub fn compare_files(a: &str, b: &str) -> Option<Ordering> {
    if !a.is_ascii() || !b.is_ascii() {
        return None;
    }
    Some(
        a.bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.bytes().map(|c| c.to_ascii_lowercase())),
    )
}

/// The text `new File(path).getAbsoluteFile().getPath()` gives on Windows with working directory
/// `cwd`: forward slashes become backslashes, runs of separators collapse (a leading `\\`
/// stays), a trailing separator goes. `None` for the forms this does not reproduce (a drive
/// without a directory, `.`/`..` segments are kept as Java keeps them).
#[must_use]
pub fn absolute_path(path: &str, cwd: &str) -> Option<String> {
    let norm = normalize(path);
    let bytes = norm.as_bytes();
    let has_drive = bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic();
    if has_drive {
        if bytes.len() == 2 || bytes[2] != b'\\' {
            return None;
        }
        return Some(norm);
    }
    if norm.starts_with("\\\\") {
        return Some(norm);
    }
    let cwd = normalize(cwd);
    if norm.starts_with('\\') {
        let drive = cwd.get(..2)?;
        return Some(format!("{drive}{norm}"));
    }
    if norm.is_empty() {
        return Some(cwd);
    }
    Some(join(&cwd, &norm))
}

/// `File.normalize` on Windows.
fn normalize(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let unc = path.starts_with("\\\\") || path.starts_with("//");
    let mut last_sep = false;
    for (i, c) in path.chars().enumerate() {
        let c = if c == '/' { '\\' } else { c };
        if c == '\\' {
            if last_sep && !(unc && i == 1) {
                continue;
            }
            last_sep = true;
        } else {
            last_sep = false;
        }
        out.push(c);
    }
    let root_len = if out.len() >= 3 && out.as_bytes()[1] == b':' {
        3
    } else {
        1
    };
    while out.len() > root_len && out.ends_with('\\') {
        out.pop();
    }
    out
}

/// `new File(parent, child).getPath()`.
#[must_use]
pub fn join(parent: &str, child: &str) -> String {
    if parent.ends_with('\\') {
        format!("{parent}{child}")
    } else {
        format!("{parent}\\{child}")
    }
}

/// `File.getParent()` of a normalised absolute path.
#[must_use]
pub fn parent(path: &str) -> Option<&str> {
    let i = path.rfind('\\')?;
    if i == 0 {
        return None;
    }
    if i == 2 && path.as_bytes().get(1) == Some(&b':') {
        // C:\name -> C:\
        return if path.len() > 3 {
            Some(&path[..3])
        } else {
            None
        };
    }
    Some(&path[..i])
}

/// `File.getName()` of a normalised absolute path.
#[must_use]
pub fn file_name(path: &str) -> &str {
    path.rfind('\\').map_or(path, |i| &path[i + 1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_hash_is_javas() {
        assert_eq!(string_hash(""), 0, "empty");
        assert_eq!(string_hash("p1"), 3521, "two chars");
        assert_eq!(string_hash("hello"), 99_162_322, "the textbook value");
    }

    #[test]
    fn the_order_of_the_fixture_files_is_the_observed_one() {
        // the h6 daemon listed the files of the parity fixture as frag, beta, alpha
        let order = hash_order(&["alpha.exe", "beta.exe", "frag.exe"]).expect("simple");
        assert_eq!(
            order,
            ["frag.exe", "beta.exe", "alpha.exe"],
            "HashMap order of the names"
        );
    }

    #[test]
    fn concurrent_map_order_follows_bins_then_insertion() {
        let mut m = ChmOrder::new();
        for k in ["p1", "p2", "p3"] {
            m.insert(k);
        }
        assert_eq!(
            m.order().expect("exact"),
            ["p1", "p2", "p3"],
            "consecutive hashes"
        );
        m.remove("p2");
        m.insert("p4");
        assert_eq!(
            m.order().expect("exact"),
            ["p1", "p3", "p4"],
            "removal keeps the rest"
        );
        let mut big = ChmOrder::new();
        for i in 1..=14 {
            big.insert(&format!("p{i}"));
        }
        assert_eq!(
            big.order().expect("exact").len(),
            14,
            "a resize loses nothing"
        );
    }

    #[test]
    fn the_table_grows_at_three_quarters() {
        assert_eq!(table_size(12), 16, "twelve fit");
        assert_eq!(table_size(13), 32, "the thirteenth resizes");
        assert_eq!(table_size(25), 64, "twenty-five");
    }

    #[test]
    fn paths_follow_file_normalisation() {
        assert_eq!(
            absolute_path("C:/a//b/", "D:\\w").as_deref(),
            Some("C:\\a\\b"),
            "slashes and the tail"
        );
        assert_eq!(
            absolute_path("x\\y", "D:\\w").as_deref(),
            Some("D:\\w\\x\\y"),
            "relative"
        );
        assert_eq!(
            absolute_path("\\x", "D:\\w").as_deref(),
            Some("D:\\x"),
            "drive-relative root"
        );
        assert_eq!(
            absolute_path("C:x", "D:\\w"),
            None,
            "drive without a directory"
        );
        assert_eq!(parent("C:\\a\\b.gpr"), Some("C:\\a"), "parent");
        assert_eq!(parent("C:\\b.gpr"), Some("C:\\"), "parent of a root entry");
        assert_eq!(file_name("C:\\a\\b.gpr"), "b.gpr", "name");
    }
}
