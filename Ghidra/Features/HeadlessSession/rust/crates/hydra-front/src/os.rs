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
//! The few operating-system facilities the front needs beyond `std`: a Job Object that ends the
//! JVM backend with the front, and the system random generator for the endpoint token.

use std::io;

/// A Windows Job Object that kills its processes when the front exits or is killed, so the
/// launcher's `kill` (which ends the front's pid) can never leave an orphan JVM holding project
/// locks. Elsewhere it does nothing.
#[derive(Debug)]
pub(crate) struct KillOnClose {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

// SAFETY: a job handle is a plain kernel handle; the kernel serialises calls on it.
#[cfg(windows)]
unsafe impl Send for KillOnClose {}
// SAFETY: as above, every use is a thread-safe kernel call.
#[cfg(windows)]
unsafe impl Sync for KillOnClose {}

#[cfg(windows)]
impl KillOnClose {
    /// Creates the job with `KILL_ON_JOB_CLOSE`.
    pub(crate) fn new() -> io::Result<Self> {
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        // SAFETY: null attributes and name are documented as valid; the result is checked.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: an all-zero JOBOBJECT_EXTENDED_LIMIT_INFORMATION is a valid value.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let size = u32::try_from(std::mem::size_of_val(&info)).unwrap_or(u32::MAX);
        // SAFETY: `info` is a live, correctly sized structure of the class named.
        let ok = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&info).cast(),
                size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    /// Puts a child process into the job.
    pub(crate) fn assign(&self, child: &std::process::Child) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        // SAFETY: both handles are live for the call.
        let ok = unsafe { AssignProcessToJobObject(self.handle, child.as_raw_handle().cast()) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(not(windows))]
impl KillOnClose {
    /// No job objects here.
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {})
    }

    /// No job objects here.
    pub(crate) fn assign(&self, _child: &std::process::Child) -> io::Result<()> {
        Ok(())
    }
}

/// 32 random bytes from the operating system, as 64 hex digits.
pub(crate) fn random_token() -> io::Result<String> {
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
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
