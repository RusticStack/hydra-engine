//! Mapping from decoded kernel ETW events to TRACE-1 events. Strings never reach the segment: each becomes a keyed id
//! and a length. Event ids are the documented manifest ids; one that is not in a table is kept as `etw.event` with its
//! provider and id, so nothing is dropped for being unknown.

use crate::segment::keyed_id;
use serde_json::{Map, Value, json};

/// A decoded property value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Prop {
    Int(u64),
    Text(String),
    Bytes(usize),
    Guid(String),
}

/// The providers this consumer enables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Provider {
    Process,
    File,
    Registry,
    Network,
    Pnp,
}

impl Provider {
    pub(crate) const ALL: [Self; 5] = [
        Self::Process,
        Self::File,
        Self::Registry,
        Self::Network,
        Self::Pnp,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Process => "Microsoft-Windows-Kernel-Process",
            Self::File => "Microsoft-Windows-Kernel-File",
            Self::Registry => "Microsoft-Windows-Kernel-Registry",
            Self::Network => "Microsoft-Windows-Kernel-Network",
            Self::Pnp => "Microsoft-Windows-Kernel-PnP",
        }
    }

    pub(crate) fn short(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::File => "file",
            Self::Registry => "registry",
            Self::Network => "network",
            Self::Pnp => "pnp",
        }
    }

    /// (data1, data2, data3, data4) of the provider GUID.
    pub(crate) fn guid(self) -> (u32, u16, u16, [u8; 8]) {
        match self {
            Self::Process => (
                0x22FB_2CD6,
                0x0E7B,
                0x422B,
                [0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
            ),
            Self::File => (
                0xEDD0_8927,
                0x9CC4,
                0x4E65,
                [0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89],
            ),
            Self::Registry => (
                0x70EB_4F03,
                0xC1DE,
                0x4F73,
                [0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD],
            ),
            Self::Network => (
                0x7DD4_2A49,
                0x5329,
                0x4832,
                [0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88],
            ),
            Self::Pnp => (
                0x9C20_5A39,
                0x1250,
                0x487D,
                [0xAB, 0xD7, 0xE8, 0x31, 0xC6, 0x29, 0x05, 0x39],
            ),
        }
    }

    /// The match-any keyword mask: what the trace needs, not everything the provider can say.
    pub(crate) fn keywords(self) -> u64 {
        match self {
            // process 0x10, thread 0x20, image 0x40
            Self::Process => 0x70,
            // filename 0x10, fileio 0x20, create 0x80, read 0x100, write 0x200, delete path 0x400, rename 0x800
            Self::File => 0xFB0,
            Self::Registry | Self::Network | Self::Pnp => u64::MAX,
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.short() == name)
    }
}

/// The TRACE-1 kind for an event id of a provider.
pub(crate) fn kind_of(provider: Provider, id: u16) -> &'static str {
    match (provider, id) {
        (Provider::Process, 1) => "core.process.start",
        (Provider::Process, 2) => "core.process.exit",
        (Provider::Process, 3) => "core.thread.start",
        (Provider::Process, 4) => "core.thread.exit",
        (Provider::Process, 5) => "core.module.load",
        (Provider::Process, 6) => "core.module.unload",
        (Provider::File, 12) => "core.resource.open",
        (Provider::File, 13 | 14) => "core.resource.close",
        (Provider::File, 15) => "core.resource.read",
        (Provider::File, 16) => "core.resource.write",
        (Provider::Registry, 1 | 2) => "core.resource.open",
        (Provider::Registry, 5) => "core.resource.write",
        (Provider::Registry, 7) => "core.resource.read",
        (Provider::Registry, 13) => "core.resource.close",
        (Provider::Network, 12 | 15 | 28 | 31) => "core.resource.open",
        (Provider::Network, 10 | 26) => "core.resource.write",
        (Provider::Network, 11 | 27) => "core.resource.read",
        (Provider::Network, 13 | 29) => "core.resource.close",
        (Provider::Pnp, _) => "driver.pnp",
        _ => "etw.event",
    }
}

/// The resource family a provider's events describe.
fn resource_kind(provider: Provider) -> Option<&'static str> {
    match provider {
        Provider::File => Some("file"),
        Provider::Registry => Some("registry"),
        Provider::Network => Some("socket"),
        Provider::Process | Provider::Pnp => None,
    }
}

/// The payload of an event: integers as they are, strings as `<name>_id` + `<name>_len`, GUIDs as text.
pub(crate) fn payload(
    provider: Provider,
    id: u16,
    version: u8,
    opcode: u8,
    props: &[(String, Prop)],
    partial: bool,
    key: &[u8],
) -> Value {
    let mut map = Map::new();
    map.insert("provider".into(), provider.name().into());
    map.insert("event_id".into(), id.into());
    map.insert("version".into(), version.into());
    map.insert("opcode".into(), opcode.into());
    if partial {
        map.insert("partial".into(), true.into());
    }
    if let Some(kind) = resource_kind(provider) {
        map.insert("resource_kind".into(), kind.into());
    }
    let mut resource: Option<String> = None;
    for (name, prop) in props {
        let name = name.to_ascii_lowercase();
        match prop {
            Prop::Int(v) => {
                map.insert(name, Value::from(*v));
            }
            Prop::Text(text) => {
                // Lower-cased (ASCII only), `/` as `\`, UTF-16LE: one pass, one allocation.
                let mut units: Vec<u8> = Vec::with_capacity(text.len() * 2);
                let mut utf16 = [0u16; 2];
                for c in text.chars() {
                    let c = if c == '/' {
                        '\\'
                    } else {
                        c.to_ascii_lowercase()
                    };
                    for unit in c.encode_utf16(&mut utf16) {
                        units.extend_from_slice(&unit.to_le_bytes());
                    }
                }
                let id = keyed_id(key, &units);
                if resource.is_none() {
                    resource = Some(id.clone());
                }
                map.insert(format!("{name}_id"), id.into());
                map.insert(format!("{name}_len"), units.len().into());
            }
            Prop::Bytes(n) => {
                map.insert(format!("{name}_bytes"), (*n).into());
            }
            Prop::Guid(text) => {
                map.insert(name, text.clone().into());
            }
        }
    }
    if let Some(r) = resource {
        map.insert("resource_id".into(), r.into());
    }
    json!(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_never_reach_the_payload() {
        let props = vec![
            (
                "OpenPath".to_owned(),
                Prop::Text(r"C:\Secret\Token.txt".into()),
            ),
            ("Irp".to_owned(), Prop::Int(7)),
        ];
        let value = payload(Provider::File, 12, 0, 0, &props, false, &[3; 32]);
        let text = value.to_string();
        assert!(!text.to_lowercase().contains("secret"));
        assert_eq!(value["openpath_len"], 38);
        assert_eq!(value["irp"], 7);
        assert_eq!(value["resource_id"], value["openpath_id"]);
    }

    #[test]
    fn path_case_does_not_change_the_id() {
        let a = payload(
            Provider::File,
            12,
            0,
            0,
            &[("P".into(), Prop::Text(r"C:\A".into()))],
            false,
            &[1; 32],
        );
        let b = payload(
            Provider::File,
            12,
            0,
            0,
            &[("P".into(), Prop::Text("c:/a".into()))],
            false,
            &[1; 32],
        );
        assert_eq!(a["resource_id"], b["resource_id"]);
    }

    #[test]
    fn unknown_ids_are_kept_not_dropped() {
        assert_eq!(kind_of(Provider::File, 999), "etw.event");
        assert_eq!(kind_of(Provider::Process, 1), "core.process.start");
        assert_eq!(kind_of(Provider::Pnp, 5), "driver.pnp");
    }
}
