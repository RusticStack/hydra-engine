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
//! The command line's failures and the exit codes they map to (documented in `CLI.md`).

use std::fmt;
use std::process::ExitCode;

use hydra_client::error::code;
use serde_json::{Value, json};

/// The process exit status. The numbers are a public contract; add new ones, never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The command succeeded.
    Ok,
    /// The engine failed the request (`failed`, or a code with no better home).
    Failed,
    /// The command line is wrong, or the engine called the request malformed (`bad_request`).
    Usage,
    /// The function, address, program or project asked for does not exist (`not_found`).
    NotFound,
    /// No daemon could be reached or started, or the install is unusable.
    Unavailable,
    /// The engine was busy, or the deadline passed, or the request was cancelled.
    Busy,
    /// The daemon speaks a protocol this client does not.
    Incompatible,
    /// No project or program is selected (`no_project`, `no_program`, or none given).
    NoContext,
    /// The engine refused: `read_only`, `not_owner`, `conflict`, `unsaved_changes`.
    Refused,
    /// `--backend lite` was asked for something only the full daemon answers.
    FullDaemonRequired,
}

impl Exit {
    /// The number the process exits with.
    #[must_use]
    pub fn number(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
            Self::Usage => 2,
            Self::NotFound => 3,
            Self::Unavailable => 4,
            Self::Busy => 5,
            Self::Incompatible => 6,
            Self::NoContext => 7,
            Self::Refused => 8,
            Self::FullDaemonRequired => 9,
        }
    }

    /// The same as a process exit code.
    #[must_use]
    pub fn code(self) -> ExitCode {
        ExitCode::from(self.number())
    }
}

/// A failed command: what to exit with and what to tell the caller.
#[derive(Debug)]
pub struct CliError {
    /// The exit status.
    pub exit: Exit,
    /// A stable machine-readable code (the engine's own when it sent one).
    pub code: String,
    /// What went wrong, for a person.
    pub message: String,
    /// The engine's `error.details`, or `{}`.
    pub details: Value,
    /// What to do about it, when there is something to do.
    pub hint: Option<String>,
}

impl CliError {
    /// A failure with no details and no hint.
    #[must_use]
    pub fn new(exit: Exit, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            exit,
            code: code.into(),
            message: message.into(),
            details: json!({}),
            hint: None,
        }
    }

    /// A wrong command line.
    #[must_use]
    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Exit::Usage, "usage", message)
    }

    /// No daemon, no install, no launcher.
    #[must_use]
    pub fn unavailable(code: &str, message: impl Into<String>) -> Self {
        Self::new(Exit::Unavailable, code, message)
    }

    /// No project or program selected.
    #[must_use]
    pub fn no_context(message: impl Into<String>) -> Self {
        let mut e = Self::new(Exit::NoContext, "no_context", message);
        e.hint = Some(
            "run `hydra open <project.gpr> --program <name>`, or pass --project and --program, \
             or set HYDRA_PROJECT and HYDRA_PROGRAM"
                .to_owned(),
        );
        e
    }

    /// Adds a hint.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// The JSON the command prints on stdout when it fails.
    #[must_use]
    pub fn to_json(&self, command: &str) -> Value {
        let mut error = json!({
            "code": self.code,
            "message": self.message,
            "details": self.details,
        });
        if let Some(hint) = &self.hint {
            error["hint"] = Value::String(hint.clone());
        }
        json!({
            "ok": false,
            "command": command,
            "exit": self.exit.number(),
            "error": error,
        })
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CliError {}

impl From<hydra_client::Error> for CliError {
    fn from(e: hydra_client::Error) -> Self {
        let engine_code = e.code().to_owned();
        let message = e.message();
        let exit = match engine_code.as_str() {
            "not_found" => Exit::NotFound,
            "bad_request" | "unknown_command" | code::INVALID => Exit::Usage,
            "no_project" | "no_program" => Exit::NoContext,
            "busy" | "cancelled" | "canceled" | code::DEADLINE_EXCEEDED => Exit::Busy,
            code::INCOMPATIBLE => Exit::Incompatible,
            "read_only" | "not_owner" | "conflict" | "unsaved_changes" => Exit::Refused,
            "use_full_daemon" => Exit::FullDaemonRequired,
            code::IO | code::BAD_ENDPOINT | code::CLOSED | "unauthorized" => Exit::Unavailable,
            _ => Exit::Failed,
        };
        let script_missing = engine_code == "failed" && message.contains("script did not load");
        let mut out = Self {
            exit: if script_missing {
                Exit::Unavailable
            } else {
                exit
            },
            code: if script_missing {
                "script_unavailable".to_owned()
            } else {
                engine_code
            },
            message,
            details: e.details(),
            hint: None,
        };
        if script_missing {
            out.hint = Some(
                "this daemon was started without hydra's script folder; run `hydra shutdown` \
                 and retry so the next daemon is started with it"
                    .to_owned(),
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydra_client::{Error, SessionError};

    fn session_error(code: &str, message: &str) -> Error {
        Error::Session(SessionError::new(code, message))
    }

    #[test]
    fn engine_codes_map_to_the_documented_exits() {
        let table = [
            ("not_found", Exit::NotFound),
            ("bad_request", Exit::Usage),
            ("no_project", Exit::NoContext),
            ("no_program", Exit::NoContext),
            ("busy", Exit::Busy),
            ("cancelled", Exit::Busy),
            ("deadline_exceeded", Exit::Busy),
            ("incompatible", Exit::Incompatible),
            ("read_only", Exit::Refused),
            ("conflict", Exit::Refused),
            ("use_full_daemon", Exit::FullDaemonRequired),
            ("closed", Exit::Unavailable),
            ("failed", Exit::Failed),
            ("something_new", Exit::Failed),
        ];
        for (code, want) in table {
            let got = CliError::from(session_error(code, "m")).exit;
            assert_eq!(got, want, "engine code {code}");
        }
    }

    #[test]
    fn exit_numbers_are_stable() {
        assert_eq!(Exit::Ok.number(), 0);
        assert_eq!(Exit::Usage.number(), 2);
        assert_eq!(Exit::Unavailable.number(), 4);
        assert_eq!(Exit::FullDaemonRequired.number(), 9);
    }

    #[test]
    fn a_missing_script_becomes_an_actionable_unavailable() {
        let e = CliError::from(session_error(
            "failed",
            "script did not load: The class could not be found",
        ));
        assert_eq!(e.exit, Exit::Unavailable);
        assert_eq!(e.code, "script_unavailable");
        assert!(e.hint.is_some_and(|h| h.contains("hydra shutdown")));
    }

    #[test]
    fn the_failure_json_carries_exit_code_and_hint() {
        let e = CliError::no_context("no project");
        let v = e.to_json("info");
        assert_eq!(v["ok"], false);
        assert_eq!(v["exit"], 7);
        assert_eq!(v["error"]["code"], "no_context");
        assert!(v["error"]["hint"].is_string());
    }
}
