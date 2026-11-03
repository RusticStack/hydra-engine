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
//! The few operating-system facilities beyond `std`: the system random generator for the endpoint
//! token and the process's own memory figures for `hello.memory`.

use std::io;

/// 32 random bytes from the operating system, as 64 lower-case hex digits (the token of the
/// endpoint file: `HexFormat.of().formatHex` of 32 `SecureRandom` bytes in the Java daemon).
///
/// # Errors
///
/// The error of the system generator.
pub fn random_token() -> io::Result<String> {
    let mut buf = [0u8; 32];
    fill_random(&mut buf)?;
    let mut s = String::with_capacity(64);
    for b in buf {
        s.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
    }
    Ok(s)
}

#[cfg(windows)]
fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let len = u32::try_from(buf.len()).unwrap_or(0);
    // SAFETY: `buf` is valid for `len` bytes; a null algorithm handle with the flag is documented.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            len,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("BCryptGenRandom: {status:#x}")))
    }
}

#[cfg(not(windows))]
fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The working set and the peak working set of this process in bytes, when the system says.
#[must_use]
pub fn memory_bytes() -> Option<(u64, u64)> {
    memory_impl()
}

#[cfg(windows)]
fn memory_impl() -> Option<(u64, u64)> {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: an all-zero PROCESS_MEMORY_COUNTERS is a valid value.
    let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    let size = u32::try_from(std::mem::size_of_val(&c)).ok()?;
    c.cb = size;
    // SAFETY: GetCurrentProcess takes no arguments and returns a pseudo handle.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: the pseudo handle of the current process is always valid; `c` is a live,
    // correctly sized structure.
    let ok = unsafe { GetProcessMemoryInfo(process, &raw mut c, size) };
    if ok == 0 {
        return None;
    }
    Some((
        u64::try_from(c.WorkingSetSize).ok()?,
        u64::try_from(c.PeakWorkingSetSize).ok()?,
    ))
}

#[cfg(not(windows))]
fn memory_impl() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb = |key: &str| -> Option<u64> {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|r| r.trim().trim_end_matches(" kB").trim().parse::<u64>().ok())
            .map(|v| v * 1024)
    };
    Some((kb("VmRSS:")?, kb("VmHWM:")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_64_lower_hex_digits_and_differs() {
        let a = random_token().expect("token");
        let b = random_token().expect("token");
        assert_eq!(a.len(), 64, "32 bytes");
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "hex"
        );
        assert_ne!(a, b, "random");
    }

    #[test]
    fn memory_figures_exist() {
        let (ws, peak) = memory_bytes().expect("the system gives them");
        assert!(ws > 0 && peak >= ws, "working set {ws}, peak {peak}");
    }
}
