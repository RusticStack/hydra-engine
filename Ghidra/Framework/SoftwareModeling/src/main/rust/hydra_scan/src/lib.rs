// IP: GHIDRA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Byte-pattern and string scanner for Hydra Engine memory search.
//!
//! The C ABI below is called from Java through FFM
//! (`ghidra.program.database.mem.NativeByteScanner`). Every function has a Java reference
//! implementation with the same contract (`ByteScanKernel`), and the Java tests compare the two
//! byte for byte: same matches, same order. Nothing here may panic (the cdylib is built with
//! `panic = "abort"`); invalid arguments return negative error codes instead.
//!
//! SIMD comes from the crates: `memchr::memmem` (SSE2/AVX2 Two-Way + prefilter, chosen at run
//! time from the CPU the process runs on) and `aho-corasick` (Teddy SIMD prefilter for small
//! pattern sets). One binary serves every x86-64 CPU.

use aho_corasick::{AhoCorasickBuilder, MatchKind};
use memchr::memmem;

/// ABI version; the Java side refuses a library with a different value.
pub const ABI_VERSION: u32 = 1;

pub const ERR_ARGS: i64 = -2;
pub const ERR_BUILD: i64 = -3;

/// Find the first (`forward`) or last window start `k` in `[0, count)` with
/// `data[k..k+pat.len()]` equal to `pat` under `mask` (byte `i` matches when
/// `data[k+i] & mask[i] == pat[i] & mask[i]`; no mask means all bits). Requires
/// `data.len() >= count + pat.len() - 1`. Returns `None` when no window matches.
pub fn find(
	data: &[u8],
	count: usize,
	pat: &[u8],
	mask: Option<&[u8]>,
	forward: bool,
) -> Option<usize> {
	if count == 0 || pat.is_empty() {
		return None;
	}
	let span = count + pat.len() - 1;
	if data.len() < span {
		return None;
	}
	let hay = &data[..span];
	match mask {
		None => {
			if forward {
				memmem::find(hay, pat)
			} else {
				memmem::rfind(hay, pat)
			}
		}
		Some(mask) => find_masked(hay, count, pat, mask, forward),
	}
}

fn window_matches(hay: &[u8], k: usize, pat: &[u8], mask: &[u8]) -> bool {
	let w = &hay[k..k + pat.len()];
	w.iter()
		.zip(pat)
		.zip(mask)
		.all(|((d, p), m)| d & m == p & m)
}

fn find_masked(hay: &[u8], count: usize, pat: &[u8], mask: &[u8], forward: bool) -> Option<usize> {
	// Anchor on the first byte whose mask is 0xFF: memchr (SIMD) finds its candidates.
	match mask.iter().position(|&m| m == 0xFF) {
		Some(a) => {
			let region = &hay[a..a + count];
			if forward {
				memchr::memchr_iter(pat[a], region).find(|&c| window_matches(hay, c, pat, mask))
			} else {
				memchr::memrchr_iter(pat[a], region).find(|&c| window_matches(hay, c, pat, mask))
			}
		}
		None => {
			if forward {
				(0..count).find(|&k| window_matches(hay, k, pat, mask))
			} else {
				(0..count)
					.rev()
					.find(|&k| window_matches(hay, k, pat, mask))
			}
		}
	}
}

/// Every occurrence of every pattern in `data`, overlapping, sorted by (offset, pattern index).
/// With `ascii_ci`, ASCII letters compare case-insensitively (other bytes exactly).
/// Returns `None` for an empty pattern set, an empty pattern or a failed automaton build.
pub fn find_all(data: &[u8], patterns: &[&[u8]], ascii_ci: bool) -> Option<Vec<(usize, u32)>> {
	if patterns.is_empty() || patterns.iter().any(|p| p.is_empty()) {
		return None;
	}
	let ac = AhoCorasickBuilder::new()
		.match_kind(MatchKind::Standard)
		.ascii_case_insensitive(ascii_ci)
		.build(patterns)
		.ok()?;
	let mut out: Vec<(usize, u32)> = ac
		.find_overlapping_iter(data)
		.map(|m| (m.start(), m.pattern().as_u32()))
		.collect();
	out.sort_unstable();
	Some(out)
}

unsafe fn slice<'a>(p: *const u8, len: i64) -> Option<&'a [u8]> {
	if len < 0 {
		return None;
	}
	if len == 0 {
		return Some(&[]);
	}
	if p.is_null() {
		return None;
	}
	Some(std::slice::from_raw_parts(p, len as usize))
}

#[no_mangle]
pub extern "C" fn hydra_scan_abi_version() -> u32 {
	ABI_VERSION
}

/// C ABI for [`find`]. `mask` may be null. Returns the offset, -1 for no match, or
/// [`ERR_ARGS`].
///
/// # Safety
/// `data` must point to `data_len` readable bytes, `pat` (and `mask` when not null) to
/// `pat_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn hydra_scan_find(
	data: *const u8,
	data_len: i64,
	count: i64,
	pat: *const u8,
	mask: *const u8,
	pat_len: i64,
	forward: i32,
) -> i64 {
	let (Some(d), Some(p)) = (slice(data, data_len), slice(pat, pat_len)) else {
		return ERR_ARGS;
	};
	if count < 0
		|| pat_len <= 0
		|| (count as u64).saturating_add(pat_len as u64 - 1) > data_len as u64
	{
		return ERR_ARGS;
	}
	let m = if mask.is_null() {
		None
	} else {
		match slice(mask, pat_len) {
			Some(m) => Some(m),
			None => return ERR_ARGS,
		}
	};
	match find(d, count as usize, p, m, forward != 0) {
		Some(k) => k as i64,
		None => -1,
	}
}

/// C ABI for [`find_all`]. Patterns are concatenated in `pats` with lengths in `pat_lens`.
/// Writes up to `cap` results into `out_offsets` / `out_patterns` and returns the total number
/// of matches (which may exceed `cap`; the caller then retries with more room), or a negative
/// error code.
///
/// # Safety
/// Pointers must cover the stated lengths; outputs must have room for `cap` elements.
#[no_mangle]
pub unsafe extern "C" fn hydra_scan_find_all(
	data: *const u8,
	data_len: i64,
	pats: *const u8,
	pats_len: i64,
	pat_lens: *const i32,
	n_pats: i32,
	ascii_ci: i32,
	out_offsets: *mut i64,
	out_patterns: *mut i32,
	cap: i64,
) -> i64 {
	let (Some(d), Some(all)) = (slice(data, data_len), slice(pats, pats_len)) else {
		return ERR_ARGS;
	};
	if n_pats <= 0
		|| pat_lens.is_null()
		|| cap < 0
		|| (cap > 0 && (out_offsets.is_null() || out_patterns.is_null()))
	{
		return ERR_ARGS;
	}
	let lens = std::slice::from_raw_parts(pat_lens, n_pats as usize);
	let mut list: Vec<&[u8]> = Vec::with_capacity(lens.len());
	let mut at = 0usize;
	for &l in lens {
		if l <= 0 || at + l as usize > all.len() {
			return ERR_ARGS;
		}
		list.push(&all[at..at + l as usize]);
		at += l as usize;
	}
	let Some(found) = find_all(d, &list, ascii_ci != 0) else {
		return ERR_BUILD;
	};
	let n = found.len().min(cap as usize);
	for (i, &(o, p)) in found.iter().take(n).enumerate() {
		*out_offsets.add(i) = o as i64;
		*out_patterns.add(i) = p as i32;
	}
	found.len() as i64
}

#[cfg(test)]
mod tests {
	use super::*;

	fn naive_find(
		data: &[u8],
		count: usize,
		pat: &[u8],
		mask: Option<&[u8]>,
		fwd: bool,
	) -> Option<usize> {
		let ok = |k: usize| {
			(0..pat.len()).all(|i| {
				let m = mask.map_or(0xFF, |m| m[i]);
				data[k + i] & m == pat[i] & m
			})
		};
		if fwd {
			(0..count).find(|&k| ok(k))
		} else {
			(0..count).rev().find(|&k| ok(k))
		}
	}

	struct Rng(u64);
	impl Rng {
		fn next(&mut self) -> u64 {
			self.0 ^= self.0 << 13;
			self.0 ^= self.0 >> 7;
			self.0 ^= self.0 << 17;
			self.0
		}
	}

	#[test]
	fn find_matches_naive() {
		let mut r = Rng(0x9E3779B97F4A7C15);
		for _ in 0..3000 {
			let alpha = 1 + (r.next() % 4) as u8;
			let n = (r.next() % 300) as usize;
			let data: Vec<u8> = (0..n).map(|_| (r.next() % alpha as u64) as u8).collect();
			let plen = 1 + (r.next() % 6) as usize;
			if n < plen {
				continue;
			}
			let count = n - plen + 1;
			let pat: Vec<u8> = (0..plen).map(|_| (r.next() % alpha as u64) as u8).collect();
			let mask: Vec<u8> = (0..plen)
				.map(|_| [0xFF, 0x0F, 0x00, 0xF0][(r.next() % 4) as usize])
				.collect();
			for fwd in [true, false] {
				assert_eq!(
					find(&data, count, &pat, None, fwd),
					naive_find(&data, count, &pat, None, fwd)
				);
				assert_eq!(
					find(&data, count, &pat, Some(&mask), fwd),
					naive_find(&data, count, &pat, Some(&mask), fwd)
				);
			}
		}
	}

	#[test]
	fn find_all_matches_naive() {
		let mut r = Rng(12345);
		for _ in 0..1000 {
			let n = (r.next() % 400) as usize;
			let data: Vec<u8> = (0..n).map(|_| b"aAbB\0"[(r.next() % 5) as usize]).collect();
			let np = 1 + (r.next() % 5) as usize;
			let pats: Vec<Vec<u8>> = (0..np)
				.map(|_| {
					let l = 1 + (r.next() % 4) as usize;
					(0..l).map(|_| b"aAbB\0"[(r.next() % 5) as usize]).collect()
				})
				.collect();
			let refs: Vec<&[u8]> = pats.iter().map(|p| p.as_slice()).collect();
			for ci in [false, true] {
				let eq = |a: u8, b: u8| {
					if ci {
						a.eq_ignore_ascii_case(&b)
					} else {
						a == b
					}
				};
				let mut want = vec![];
				for o in 0..n {
					for (i, p) in pats.iter().enumerate() {
						if o + p.len() <= n && p.iter().zip(&data[o..]).all(|(&x, &y)| eq(x, y)) {
							want.push((o, i as u32));
						}
					}
				}
				assert_eq!(find_all(&data, &refs, ci).unwrap(), want);
			}
		}
	}
}
