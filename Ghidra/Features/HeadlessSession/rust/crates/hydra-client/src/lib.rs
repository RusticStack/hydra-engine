//! A Rust client of the Hydra Engine headless session protocol (versions 2 and 3).
//!
//! The protocol is one JSON object per line over a loopback TCP socket (the daemon's endpoint
//! file names host, port and token) or over a child process's stdin/stdout (the private stdio
//! session). This crate speaks the socket transport, which is the one the multi-agent benchmark
//! and the Hydralysis MCP server use. It is a port of `ghidra_session.py` 1.1.0's client half:
//! the same request ids, the same `hello` negotiation, the same deadlines and cancellation,
//! the same handling of events, of non-protocol lines and of an unterminated last line.
//!
//! ```no_run
//! use hydra_client::{ConnectOptions, Endpoint, Session};
//!
//! # fn main() -> hydra_client::Result<()> {
//! let endpoint = Endpoint::from_state(std::path::Path::new("C:/state"), "default")?;
//! let session = Session::connect(endpoint, &ConnectOptions::new("agent", "bench"))?;
//! let info = session.info(None, None, Some(5.0))?;
//! assert!(info.get("key").is_some());
//! # Ok(())
//! # }
//! ```
//!
//! The Python client remains the shipped default; this crate exists so the 16-agent shape can
//! run without the `CPython` 8.5 MB floor per agent. `PORTING.md` maps every ported behaviour and
//! lists the deliberate differences.

#![deny(unsafe_code)]

pub mod client;
pub mod error;
pub mod json;
pub mod session;
pub mod version;

pub use client::{Access, Discard};
pub use error::{Error, Result, SessionError};
pub use json::{decompile_projection, digest, python_dumps, sha256_hex};
pub use session::{ConnectOptions, Endpoint, Labelled, Reply, Session, fields};
pub use version::{
    CLIENT_VERSION, PROTOCOL, PROTOCOL_MIN, check_compatible, check_endpoint, engine_protocols,
    parse_version, requested_protocol,
};
