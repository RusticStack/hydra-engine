//! The Windows layer: elevation check, a real-time ETW session, `EnableTraceEx2` per provider, `OpenTrace` /
//! `ProcessTrace`, and TDH decoding of an event's properties. All `unsafe` in the crate is here.

use crate::events::{Prop, Provider};
use std::collections::HashMap;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EVENT_PROPERTY_INFO, EVENT_RECORD,
    EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
    PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW, TRACE_EVENT_INFO,
    TdhGetEventInformation, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::core::GUID;

/// `EVENT_FILTER_TYPE_PID`.
const FILTER_PID: u32 = 0x8000_0004;
const INVALID_TRACE: u64 = u64::MAX;
const INSUFFICIENT_BUFFER: u32 = 122;

/// Whether the process token is elevated.
pub(crate) fn is_elevated() -> bool {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: `token` is a valid out pointer and the handle is closed before returning.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&raw mut elevation).cast(),
            4,
            &raw mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn guid_of(p: Provider) -> GUID {
    let (data1, data2, data3, data4) = p.guid();
    GUID {
        data1,
        data2,
        data3,
        data4,
    }
}

fn guid_text(g: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}

/// What the session reports about itself (the ETW side of capture health).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SessionStats {
    pub(crate) events_lost: u32,
    pub(crate) buffers_lost: u32,
    pub(crate) real_time_buffers_lost: u32,
    pub(crate) buffers_written: u32,
}

/// A started real-time session.
pub(crate) struct Session {
    handle: CONTROLTRACE_HANDLE,
    name: Vec<u16>,
    props: Vec<u8>,
}

fn props_buffer(name: &[u16]) -> Vec<u8> {
    let header = size_of::<EVENT_TRACE_PROPERTIES>();
    let total = header + name.len() * 2;
    let mut buf = vec![0u8; total];
    // SAFETY: a zeroed EVENT_TRACE_PROPERTIES is a valid starting value.
    let mut p: EVENT_TRACE_PROPERTIES = unsafe { std::mem::zeroed() };
    p.Wnode.BufferSize = u32::try_from(total).unwrap_or(u32::MAX);
    p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p.Wnode.ClientContext = 1; // QueryPerformanceCounter ticks
    p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p.BufferSize = 256;
    p.MinimumBuffers = 8;
    p.MaximumBuffers = 64;
    p.FlushTimer = 1;
    p.LoggerNameOffset = u32::try_from(header).unwrap_or(0);
    // SAFETY: the buffer holds at least one EVENT_TRACE_PROPERTIES; a `Vec<u8>` is not aligned for it, so write unaligned.
    unsafe { ptr::write_unaligned(buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>(), p) };
    for (i, unit) in name.iter().enumerate() {
        buf[header + i * 2..header + i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    buf
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("handle", &self.handle.Value)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Start a real-time session called `name`. The Win32 error code on failure.
    pub(crate) fn start(name: &str) -> Result<Self, u32> {
        let wname = wide(name);
        let mut props = props_buffer(&wname);
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        // SAFETY: `props` holds a valid EVENT_TRACE_PROPERTIES followed by the NUL-terminated name it points to.
        let status =
            unsafe { StartTraceW(&raw mut handle, wname.as_ptr(), props.as_mut_ptr().cast()) };
        if status != ERROR_SUCCESS {
            return Err(status);
        }
        Ok(Self {
            handle,
            name: wname,
            props,
        })
    }

    /// Enable `provider`, filtered in the kernel to `pids` when there are at most eight. The Win32 status.
    pub(crate) fn enable(&self, provider: Provider, pids: &[u32]) -> u32 {
        let guid = guid_of(provider);
        let mut list: Vec<u32> = pids.iter().copied().take(8).collect();
        let mut filter = EVENT_FILTER_DESCRIPTOR {
            Ptr: 0,
            Size: 0,
            Type: 0,
        };
        // SAFETY: a zeroed ENABLE_TRACE_PARAMETERS is valid before the fields below are set.
        let mut params: ENABLE_TRACE_PARAMETERS = unsafe { std::mem::zeroed() };
        params.Version = 2;
        if !list.is_empty() && pids.len() <= 8 {
            filter.Ptr = list.as_mut_ptr() as u64;
            filter.Size = u32::try_from(list.len() * 4).unwrap_or(0);
            filter.Type = FILTER_PID;
            params.FilterDescCount = 1;
            params.EnableFilterDesc = &raw mut filter;
        }
        // SAFETY: `params`, `filter` and `list` outlive the call; the GUID is valid.
        unsafe {
            EnableTraceEx2(
                self.handle,
                &raw const guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                5,
                provider.keywords(),
                0,
                0,
                &raw const params,
            )
        }
    }

    /// Counters of the live session.
    pub(crate) fn stats(&mut self) -> SessionStats {
        // SAFETY: the properties buffer and name are the ones the session was started with.
        unsafe {
            ControlTraceW(
                self.handle,
                self.name.as_ptr(),
                self.props.as_mut_ptr().cast(),
                EVENT_TRACE_CONTROL_QUERY,
            );
            let p = ptr::read_unaligned(self.props.as_ptr().cast::<EVENT_TRACE_PROPERTIES>());
            SessionStats {
                events_lost: p.EventsLost,
                buffers_lost: p.LogBuffersLost,
                real_time_buffers_lost: p.RealTimeBuffersLost,
                buffers_written: p.BuffersWritten,
            }
        }
    }

    /// Stop the session (the consumer's `ProcessTrace` then returns).
    pub(crate) fn stop(&mut self) -> u32 {
        // SAFETY: as in `stats`.
        unsafe {
            ControlTraceW(
                self.handle,
                self.name.as_ptr(),
                self.props.as_mut_ptr().cast(),
                EVENT_TRACE_CONTROL_STOP,
            )
        }
    }
}

/// The per-event callback the consumer thread runs.
pub(crate) type Callback = Box<dyn FnMut(&Event<'_>) + Send>;

/// One raw event, borrowed from the ETW buffer for the duration of the callback.
pub(crate) struct Event<'a> {
    pub(crate) provider: Option<Provider>,
    pub(crate) id: u16,
    pub(crate) version: u8,
    pub(crate) opcode: u8,
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) ticks: u64,
    record: &'a EVENT_RECORD,
}

static CALLBACK: std::sync::Mutex<Option<Callback>> = std::sync::Mutex::new(None);

unsafe extern "system" fn on_record(record: *mut EVENT_RECORD) {
    // SAFETY: ETW passes a valid record for the duration of the call.
    let r = unsafe { &*record };
    let h = &r.EventHeader;
    let g = &h.ProviderId;
    let provider = Provider::ALL.into_iter().find(|p| {
        let (a, b, c, d) = p.guid();
        g.data1 == a && g.data2 == b && g.data3 == c && g.data4 == d
    });
    let ev = Event {
        provider,
        id: h.EventDescriptor.Id,
        version: h.EventDescriptor.Version,
        opcode: h.EventDescriptor.Opcode,
        pid: h.ProcessId,
        tid: h.ThreadId,
        ticks: u64::try_from(h.TimeStamp).unwrap_or(0),
        record: r,
    };
    if let Ok(mut slot) = CALLBACK.lock()
        && let Some(cb) = slot.as_mut()
    {
        cb(&ev);
    }
}

/// Open the real-time trace `name` and run `ProcessTrace` on the calling thread until the session stops.
/// Returns the `ProcessTrace` status, or the `OpenTrace` error.
pub(crate) fn consume(name: &str, callback: Callback) -> Result<u32, u32> {
    let mut wname = wide(name);
    if let Ok(mut slot) = CALLBACK.lock() {
        *slot = Some(callback);
    }
    // SAFETY: a zeroed EVENT_TRACE_LOGFILEW is valid; the fields set are the documented ones for a real-time consumer.
    unsafe {
        let mut log: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
        log.LoggerName = wname.as_mut_ptr();
        log.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
            | PROCESS_TRACE_MODE_EVENT_RECORD
            | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        log.Anonymous2.EventRecordCallback = Some(on_record);
        let handle = OpenTraceW(&raw mut log);
        if handle.Value == INVALID_TRACE {
            return Err(GetLastError());
        }
        let status = ProcessTrace(&raw const handle, 1, ptr::null(), ptr::null());
        CloseTrace(handle);
        Ok(status)
    }
}

/// Drop the callback (and the channel sender it owns) so the writer can finish.
pub(crate) fn clear_callback() {
    if let Ok(mut slot) = CALLBACK.lock() {
        *slot = None;
    }
}

/// TDH event-information buffers, by (provider, event id, version).
pub(crate) type InfoCache = HashMap<(u16, u16, u8), Vec<u8>>;

impl Event<'_> {
    fn pointer_size(&self) -> usize {
        if self.record.EventHeader.Flags & 0x20 != 0 {
            4
        } else {
            8
        }
    }

    /// Decode the top-level properties with TDH. The flag is true when decoding stopped early (arrays, structs, a
    /// length taken from another property).
    pub(crate) fn properties(&self, cache: &mut InfoCache) -> Option<(Vec<(String, Prop)>, bool)> {
        let key = (
            self.provider.map_or(0, |p| p as u16 + 1),
            self.id,
            self.version,
        );
        if let std::collections::hash_map::Entry::Vacant(e) = cache.entry(key) {
            let mut size = 0u32;
            // SAFETY: the first call asks for the size only.
            let status = unsafe {
                TdhGetEventInformation(self.record, 0, ptr::null(), ptr::null_mut(), &raw mut size)
            };
            if status != INSUFFICIENT_BUFFER || size == 0 {
                return None;
            }
            let mut buf = vec![0u8; size as usize];
            // SAFETY: `buf` is `size` bytes.
            let status = unsafe {
                TdhGetEventInformation(
                    self.record,
                    0,
                    ptr::null(),
                    buf.as_mut_ptr().cast::<TRACE_EVENT_INFO>(),
                    &raw mut size,
                )
            };
            if status != ERROR_SUCCESS {
                return None;
            }
            e.insert(buf);
        }
        Some(decode(cache.get(&key)?, self))
    }
}

fn read_wide(bytes: &[u8]) -> (String, usize) {
    let mut units = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        i += 2;
        if u == 0 {
            return (String::from_utf16_lossy(&units), i);
        }
        units.push(u);
    }
    (String::from_utf16_lossy(&units), i)
}

fn read_narrow(bytes: &[u8]) -> (String, usize) {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    (
        String::from_utf8_lossy(&bytes[..end]).into_owned(),
        (end + 1).min(bytes.len()),
    )
}

fn name_at(info: &[u8], offset: u32) -> String {
    let start = offset as usize;
    if start == 0 || start >= info.len() {
        return String::new();
    }
    read_wide(&info[start..]).0
}

fn decode(info: &[u8], ev: &Event<'_>) -> (Vec<(String, Prop)>, bool) {
    // SAFETY: `info` is a TDH-filled TRACE_EVENT_INFO buffer.
    let top = unsafe { ptr::read_unaligned(info.as_ptr().cast::<TRACE_EVENT_INFO>()) };
    let count = top.TopLevelPropertyCount as usize;
    let first = std::mem::offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
    let stride = size_of::<EVENT_PROPERTY_INFO>();
    // SAFETY: the user data pointer and length come from the record.
    let data: &[u8] = unsafe {
        if ev.record.UserData.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(
                ev.record.UserData.cast::<u8>(),
                usize::from(ev.record.UserDataLength),
            )
        }
    };
    let psize = ev.pointer_size();
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut partial = false;
    for i in 0..count {
        let offset = first + i * stride;
        if offset + stride > info.len() {
            partial = true;
            break;
        }
        // SAFETY: the element lies inside `info`.
        let p =
            unsafe { ptr::read_unaligned(info.as_ptr().add(offset).cast::<EVENT_PROPERTY_INFO>()) };
        let name = name_at(info, p.NameOffset);
        // SAFETY: reading plain integer union members.
        let (in_type, count_field, length_field) = unsafe {
            (
                p.Anonymous1.nonStructType.InType,
                p.Anonymous2.count,
                p.Anonymous3.length,
            )
        };
        // Struct 1, length from a property 2, count from a property 4, XML fragment 8, fixed length 0x10, fixed count 0x20.
        if p.Flags & 0x2F != 0 || count_field != 1 {
            partial = true;
            break;
        }
        let rest = &data[at.min(data.len())..];
        let fixed = |n: usize| -> Option<u64> {
            if rest.len() < n {
                return None;
            }
            let mut b = [0u8; 8];
            b[..n].copy_from_slice(&rest[..n]);
            Some(u64::from_le_bytes(b))
        };
        let step: Option<(Prop, usize)> = match in_type {
            1 => {
                let (s, used) = read_wide(rest);
                Some((Prop::Text(s), used))
            }
            2 => {
                let (s, used) = read_narrow(rest);
                Some((Prop::Text(s), used))
            }
            3 | 4 => fixed(1).map(|v| (Prop::Int(v), 1)),
            5 | 6 => fixed(2).map(|v| (Prop::Int(v), 2)),
            7 | 8 | 13 | 20 => fixed(4).map(|v| (Prop::Int(v), 4)),
            9 | 10 | 17 | 21 => fixed(8).map(|v| (Prop::Int(v), 8)),
            16 => fixed(psize).map(|v| (Prop::Int(v), psize)),
            15 if rest.len() >= 16 => {
                let g = GUID {
                    data1: u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]),
                    data2: u16::from_le_bytes([rest[4], rest[5]]),
                    data3: u16::from_le_bytes([rest[6], rest[7]]),
                    data4: [
                        rest[8], rest[9], rest[10], rest[11], rest[12], rest[13], rest[14],
                        rest[15],
                    ],
                };
                Some((Prop::Guid(guid_text(&g)), 16))
            }
            19 if rest.len() >= 8 => {
                // A SID: revision, sub-authority count, 6-byte authority, then the sub-authorities.
                let n = 8 + 4 * usize::from(rest[1]);
                (rest.len() >= n).then_some((Prop::Bytes(n), n))
            }
            14 if length_field > 0 => {
                let n = usize::from(length_field);
                (rest.len() >= n).then_some((Prop::Bytes(n), n))
            }
            _ => None,
        };
        let Some((prop, used)) = step else {
            partial = true;
            break;
        };
        at += used;
        out.push((name, prop));
    }
    (out, partial)
}
