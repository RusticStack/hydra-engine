//! Keyed correlation ids (TRACE-1 section 11). A string never enters the trace as text: it
//! becomes `HMAC-SHA256(key(scope), scope || 0x00 || value)` truncated to 128 bits, hex. The scope
//! is recorded with the id; the key lives in a file of its own, is never serialized, printed or
//! returned, and different scopes cannot be linked. Redacted previews (at most 256 bytes) are
//! produced only when the policy allows them.

use crate::store::{Error, Result};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

/// A scope key. There is deliberately no accessor, no `Serialize` and a redacted `Debug`.
pub struct Key([u8; 32]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        for b in &mut self.0 {
            // SAFETY: b is a valid, aligned, exclusive reference; a volatile write keeps the
            // compiler from removing the wipe.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl Key {
    /// A key from 32 bytes (tests, a shared scope provisioned out of band).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        random_fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// The keyed id of `value` in `scope`: 32 lowercase hex digits.
    pub fn id(&self, scope: &str, value: &[u8]) -> String {
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.0) else {
            return String::new();
        };
        mac.update(scope.as_bytes());
        mac.update(&[0]);
        mac.update(value);
        mac.finalize()
            .into_bytes()
            .iter()
            .take(16)
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(windows)]
fn random_fill(buf: &mut [u8]) -> Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    // SAFETY: buf is valid for buf.len() bytes; a null algorithm handle with the system
    // preferred RNG flag is the documented form.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Refused(format!("BCryptGenRandom failed: {status:#x}")))
    }
}

#[cfg(not(windows))]
fn random_fill(buf: &mut [u8]) -> Result<()> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")?.read_exact(buf)?;
    Ok(())
}

/// Scope keys kept as files in one directory.
pub struct KeyRing {
    dir: PathBuf,
    keys: HashMap<String, Key>,
}

fn file_name(scope: &str) -> String {
    // Scope names are free text: keep the file name safe and unambiguous.
    let safe: String = scope
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '~'
            }
        })
        .collect();
    let digest = Key::from_bytes([0; 32]).id("file", scope.as_bytes());
    format!("{safe}.{}.key", &digest[..8])
}

impl KeyRing {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            keys: HashMap::new(),
        })
    }

    fn key(&mut self, scope: &str) -> Result<&Key> {
        if !self.keys.contains_key(scope) {
            let path = self.dir.join(file_name(scope));
            let key = match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let mut bytes = [0u8; 32];
                    let text = text.trim();
                    if text.len() != 64 {
                        return Err(Error::Refused(format!("key file {} is damaged", path.display())));
                    }
                    for (i, b) in bytes.iter_mut().enumerate() {
                        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                            .map_err(|_| Error::Refused("key file is damaged".into()))?;
                    }
                    Key(bytes)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let key = Key::generate()?;
                    let hex: String = key.0.iter().map(|b| format!("{b:02x}")).collect();
                    let tmp = path.with_extension("tmp");
                    std::fs::write(&tmp, hex)?;
                    std::fs::rename(&tmp, &path)?;
                    key
                }
                Err(e) => return Err(e.into()),
            };
            self.keys.insert(scope.to_string(), key);
        }
        Ok(&self.keys[scope])
    }

    /// The keyed id of `value` in `scope`.
    pub fn derive(&mut self, scope: &str, value: &[u8]) -> Result<String> {
        Ok(self.key(scope)?.id(scope, value))
    }
}

/// What may appear next to a keyed id.
#[derive(Clone, Copy, Debug, Default)]
pub struct PreviewPolicy {
    pub allow_preview: bool,
}

const SECRET_WORDS: [&str; 7] = [
    "password", "passwd", "secret", "token", "apikey", "api_key", "key",
];

/// A preview of `text`: at most 256 bytes, secret-like runs masked.
pub fn redacted_preview(text: &str) -> String {
    let mut out = String::new();
    let mut mask_next = false;
    for word in text.split_whitespace() {
        let lower = word.to_ascii_lowercase();
        let has_digit = word.bytes().any(|b| b.is_ascii_digit());
        let has_alpha = word.bytes().any(|b| b.is_ascii_alphabetic());
        let long_mixed = word.len() >= 16 && has_digit && has_alpha;
        let assigns_secret = SECRET_WORDS
            .iter()
            .any(|w| lower.starts_with(&format!("{w}=")) || lower.starts_with(&format!("{w}:")));
        let shown = if mask_next || long_mixed {
            "***".to_string()
        } else if assigns_secret {
            let cut = word.find(['=', ':']).map_or(word.len(), |i| i + 1);
            format!("{}***", &word[..cut])
        } else {
            word.to_string()
        };
        mask_next = SECRET_WORDS.iter().any(|w| lower.trim_end_matches([':', '=']) == *w)
            && (lower.ends_with(':') || lower.ends_with('='));
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&shown);
        if out.len() >= 256 {
            break;
        }
    }
    let mut end = out.len().min(256);
    while !out.is_char_boundary(end) {
        end -= 1;
    }
    out.truncate(end);
    out
}

/// Replace every `{"$string": "text"}` in `map` (at any depth) by a keyed id record, so the text
/// never reaches a segment. Returns how many strings were replaced.
pub fn scrub(
    map: &mut Map<String, Value>,
    ring: &mut KeyRing,
    scope: &str,
    policy: PreviewPolicy,
) -> Result<usize> {
    let mut replaced = 0;
    for value in map.values_mut() {
        replaced += scrub_value(value, ring, scope, policy)?;
    }
    Ok(replaced)
}

fn scrub_value(
    value: &mut Value,
    ring: &mut KeyRing,
    scope: &str,
    policy: PreviewPolicy,
) -> Result<usize> {
    match value {
        Value::Object(obj) => {
            if obj.len() == 1
                && let Some(Value::String(text)) = obj.get("$string")
            {
                let mut out = json!({
                    "corr_id": ring.derive(scope, text.as_bytes())?,
                    "scope": scope,
                    "len": text.len(),
                });
                if policy.allow_preview {
                    out["preview"] = Value::String(redacted_preview(text));
                }
                *value = out;
                return Ok(1);
            }
            let mut n = 0;
            for v in obj.values_mut() {
                n += scrub_value(v, ring, scope, policy)?;
            }
            Ok(n)
        }
        Value::Array(items) => {
            let mut n = 0;
            for v in items {
                n += scrub_value(v, ring, scope, policy)?;
            }
            Ok(n)
        }
        _ => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hydra-corrid-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn same_scope_same_id_different_scope_unlinkable() {
        let d = dir("a");
        let mut ring = KeyRing::open(&d).unwrap();
        let a1 = ring.derive("session:1", b"hunter2").unwrap();
        let a2 = ring.derive("session:1", b"hunter2").unwrap();
        let b = ring.derive("session:2", b"hunter2").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert_eq!(a1.len(), 32);
        // The key is kept: a new ring over the same directory derives the same id.
        let mut again = KeyRing::open(&d).unwrap();
        assert_eq!(again.derive("session:1", b"hunter2").unwrap(), a1);
        // Another directory (another install) cannot reproduce it.
        let mut other = KeyRing::open(dir("b")).unwrap();
        assert_ne!(other.derive("session:1", b"hunter2").unwrap(), a1);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn matches_a_reference_hmac() {
        let key = Key::from_bytes([7; 32]);
        let mut mac = HmacSha256::new_from_slice(&[7; 32]).unwrap();
        mac.update(b"scope\0value");
        let full = mac.finalize().into_bytes();
        let want: String = full.iter().take(16).map(|b| format!("{b:02x}")).collect();
        assert_eq!(key.id("scope", b"value"), want);
    }

    #[test]
    fn the_key_is_never_printed() {
        let key = Key::from_bytes([0xab; 32]);
        assert_eq!(format!("{key:?}"), "Key(<redacted>)");
    }

    #[test]
    fn scrub_removes_the_text_and_records_the_scope() {
        let d = dir("c");
        let mut ring = KeyRing::open(&d).unwrap();
        let mut map = json!({
            "name": {"$string": "password=hunter2 for alice"},
            "nested": [{"$string": "plain words"}],
            "n": 5
        })
        .as_object()
        .unwrap()
        .clone();
        let n = scrub(&mut map, &mut ring, "session:s", PreviewPolicy::default()).unwrap();
        assert_eq!(n, 2);
        let text = Value::Object(map.clone()).to_string();
        assert!(!text.contains("hunter2") && !text.contains("alice"));
        assert!(!text.contains("preview"));
        assert_eq!(map["name"]["scope"], "session:s");
        assert_eq!(map["n"], 5);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn previews_are_bounded_and_mask_secrets() {
        let p = redacted_preview("login password=hunter2 token: abcDEF1234567890xyz ok");
        assert!(!p.contains("hunter2") && !p.contains("abcDEF"));
        assert!(p.contains("login") && p.contains("ok"));
        assert!(redacted_preview(&"word ".repeat(200)).len() <= 256);
        let d = dir("d");
        let mut ring = KeyRing::open(&d).unwrap();
        let mut map = json!({"s": {"$string": "token: abcDEF1234567890xyz"}})
            .as_object()
            .unwrap()
            .clone();
        scrub(&mut map, &mut ring, "x", PreviewPolicy { allow_preview: true }).unwrap();
        assert!(map["s"]["preview"].as_str().unwrap().contains("***"));
        assert!(!map.to_owned().into_iter().any(|(_, v)| v.to_string().contains("abcDEF")));
        let _ = std::fs::remove_dir_all(d);
    }
}
