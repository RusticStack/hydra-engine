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
//! The two ways a request can fail: with an error the Java daemon would give too
//! ([`SessionError`], reproduced word for word), or with a refusal ([`Refusal`]) because the
//! lite daemon cannot reproduce the answer exactly. A refusal is the structured error
//! `use_full_daemon` (HYDRA-LITE.md); it is never a guess.

use crate::json::Json;

/// The error code of a refusal: "ask the full daemon".
pub const USE_FULL_DAEMON: &str = "use_full_daemon";

/// Why the lite daemon refuses. The set is closed and documented (HYDRA-LITE.md); a client may
/// switch on it, and every value means the same thing: the full daemon answers, this one does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reason {
    /// The command is not in the lite set (a decompile, a write, a script, `status`, ...).
    UnsupportedCommand,
    /// The request asks for something the lite set leaves out (`writable`, `overlay`, `regex`,
    /// a field that changes behaviour).
    UnsupportedRequest,
    /// The request text is not one strict JSON object (Gson would read some such lines).
    UnparsableRequest,
    /// A number or a name the lite daemon cannot read the way Java does.
    InexactValue,
    /// An earlier refusal on this connection means the full daemon's state for it differs from
    /// this one's; only `ping` and `hello` are answered from then on.
    DivergedConnection,
    /// No learned identity, so `hello` cannot be reproduced.
    NoIdentity,
    /// A project this build cannot present exactly (layout, fork sidecar, links, versions).
    UnsupportedProject,
    /// A program this build cannot present exactly (format version, language, spaces, names).
    UnsupportedProgram,
    /// A limit of the lite daemon (projects, views) that the full daemon does not have.
    Capacity,
    /// The engine this daemon stands in for is not one whose database constants it was checked
    /// against (another Ghidra release).
    UnsupportedEngine,
}

impl Reason {
    /// The value of `error.details.reason`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedCommand => "unsupported_command",
            Self::UnsupportedRequest => "unsupported_request",
            Self::UnparsableRequest => "unparsable_request",
            Self::InexactValue => "inexact_value",
            Self::DivergedConnection => "diverged_connection",
            Self::NoIdentity => "no_identity",
            Self::UnsupportedProject => "unsupported_project",
            Self::UnsupportedProgram => "unsupported_program",
            Self::Capacity => "capacity",
            Self::UnsupportedEngine => "unsupported_engine",
        }
    }
}

/// An `ok:false` answer the Java daemon gives too: a code, a message, and optional details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError {
    /// The protocol's error code (`bad_request`, `no_project`, ...).
    pub code: &'static str,
    /// The message, word for word as the Java daemon words it.
    pub message: String,
    /// `error.details`, when the Java daemon sends some.
    pub details: Option<Json>,
}

impl SessionError {
    /// An error without details.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// An error with details.
    #[must_use]
    pub fn with_details(code: &'static str, message: impl Into<String>, details: Json) -> Self {
        Self {
            code,
            message: message.into(),
            details: Some(details),
        }
    }

    /// `bad_request`.
    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("bad_request", message)
    }

    /// `not_found`.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("not_found", message)
    }

    /// `no_project`, no details.
    #[must_use]
    pub fn no_project(message: impl Into<String>) -> Self {
        Self::new("no_project", message)
    }

    /// `no_program`, no details.
    #[must_use]
    pub fn no_program(message: impl Into<String>) -> Self {
        Self::new("no_program", message)
    }
}

/// A refusal: this request is for the full daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Why.
    pub reason: Reason,
    /// For the human: what was refused and why, in one sentence.
    pub message: String,
}

impl Refusal {
    /// A refusal.
    #[must_use]
    pub fn new(reason: Reason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

/// What a command returns instead of a result.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failure {
    /// An error the Java daemon gives too.
    Error(SessionError),
    /// A refusal: ask the full daemon.
    Refuse(Refusal),
}

impl From<SessionError> for Failure {
    fn from(e: SessionError) -> Self {
        Self::Error(e)
    }
}

impl From<Refusal> for Failure {
    fn from(r: Refusal) -> Self {
        Self::Refuse(r)
    }
}

/// A command's result.
pub type Reply = Result<Json, Failure>;

/// Shorthand for a refusal as a `Failure`.
#[must_use]
pub fn refuse(reason: Reason, message: impl Into<String>) -> Failure {
    Failure::Refuse(Refusal::new(reason, message))
}
