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
//! Working with a `hydra-lite` daemon (`HYDRA-LITE.md`, "Clients").
//!
//! A lite daemon answers a small subset of protocol 3 and refuses everything else with the error
//! code [`USE_FULL_DAEMON`]. A [`crate::Session`] opened with a [`FullDaemon`] in its
//! [`crate::ConnectOptions`] moves itself to the full daemon the first time that happens: it
//! connects there, opens again what it had opened, and sends the refused request again (and any
//! other request still unanswered). The rules are those of `ghidra_session.py`.
//!
//! Starting daemons is not this crate's job (it has no launcher), so the full daemon comes from a
//! [`FullDaemon`] the caller supplies; [`PythonLauncher`] is one that asks the Python launcher
//! (`ghidra_session.py ... ensure`), the same program that decides, from `HYDRA_LITE`, whether the
//! daemon of an instance is lite.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};
use crate::session::Endpoint;

/// The error code of a lite daemon that cannot answer a request exactly.
pub const USE_FULL_DAEMON: &str = "use_full_daemon";

/// Commands whose success changes what the daemon holds for a connection; a session replays the
/// ones that succeeded, in order, on the full daemon.
pub(crate) const STATE_COMMANDS: [&str; 6] = [
    "hello",
    "open_project",
    "close_project",
    "open_program",
    "switch",
    "close_program",
];

/// `HYDRA_LITE`: whether the launcher starts `hydra-lite` for an instance, and what a client does
/// with a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LiteMode {
    /// The launcher never starts hydra-lite. A refusal from one that runs anyway still moves a
    /// session to the full daemon. The default.
    #[default]
    Off,
    /// hydra-lite is started first when it is installed and has learned the install; a refusal
    /// moves the session to the full daemon.
    Auto,
    /// hydra-lite is started and a refusal is returned to the caller as the error
    /// [`USE_FULL_DAEMON`] (diagnostics, tests).
    Only,
}

impl LiteMode {
    /// Reads a setting: `off`, `auto` or `only`, case-insensitive, trimmed.
    ///
    /// # Errors
    /// [`code::INVALID`] for anything else.
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "auto" => Ok(Self::Auto),
            "only" => Ok(Self::Only),
            _ => Err(Error::Invalid(format!(
                "HYDRA_LITE must be off, auto or only, not {text:?}"
            ))),
        }
    }

    /// The mode in the `HYDRA_LITE` environment variable; [`LiteMode::Off`] when it is unset or
    /// empty.
    ///
    /// # Errors
    /// As [`LiteMode::parse`].
    pub fn from_env() -> Result<Self> {
        match std::env::var("HYDRA_LITE") {
            Ok(text) if !text.trim().is_empty() => Self::parse(&text),
            _ => Ok(Self::Off),
        }
    }

    /// True when a refusal is returned to the caller instead of moving the session.
    #[must_use]
    pub fn returns_refusals(self) -> bool {
        self == Self::Only
    }
}

/// The instance name of the full daemon that goes with a lite one: `<instance>.full`, the name cut
/// so the whole fits the 64 characters an instance may have.
#[must_use]
pub fn full_instance(instance: &str) -> String {
    let head: String = instance.chars().take(59).collect();
    format!("{head}.full")
}

/// Somewhere a session can find the full daemon of its instance, started if need be.
pub trait FullDaemon: Send + Sync + std::fmt::Debug {
    /// The endpoint of the running full daemon.
    ///
    /// # Errors
    /// Whatever stops the daemon from being found or started.
    fn endpoint(&self) -> Result<Endpoint>;
}

/// A [`FullDaemon`] that asks the Python launcher: `python ghidra_session.py [--ghidra DIR]
/// --state STATE --instance <instance>.full ensure`, run with `HYDRA_LITE=off` and no
/// `GHIDRA_SESSION_FRONT`, then reads `STATE/<instance>.full.json`.
#[derive(Debug, Clone)]
pub struct PythonLauncher {
    python: PathBuf,
    session_py: PathBuf,
    ghidra: Option<PathBuf>,
    state: PathBuf,
    instance: String,
}

impl PythonLauncher {
    /// A launcher for the daemon of `instance` in `state`; `session_py` is `ghidra_session.py`.
    /// The interpreter is `HYDRA_PYTHON` or `python`.
    #[must_use]
    pub fn new(session_py: &Path, state: &Path, instance: &str) -> Self {
        Self {
            python: std::env::var_os("HYDRA_PYTHON")
                .map_or_else(|| PathBuf::from("python"), PathBuf::from),
            session_py: session_py.to_owned(),
            ghidra: None,
            state: state.to_owned(),
            instance: instance.to_owned(),
        }
    }

    /// The launcher for the instance whose endpoint file is `<state>/<instance>.json`.
    ///
    /// # Errors
    /// [`code::INVALID`] when the path has no parent directory or no file stem.
    pub fn for_endpoint_file(session_py: &Path, endpoint_file: &Path) -> Result<Self> {
        let state = endpoint_file.parent().filter(|p| !p.as_os_str().is_empty());
        let instance = endpoint_file.file_stem().and_then(|s| s.to_str());
        match (state, instance) {
            (Some(state), Some(instance)) => Ok(Self::new(session_py, state, instance)),
            _ => Err(Error::Invalid(format!(
                "{} is not <state>/<instance>.json",
                endpoint_file.display()
            ))),
        }
    }

    /// Uses this Ghidra install (`--ghidra`).
    #[must_use]
    pub fn with_ghidra(mut self, ghidra: &Path) -> Self {
        self.ghidra = Some(ghidra.to_owned());
        self
    }

    /// Uses this interpreter.
    #[must_use]
    pub fn with_python(mut self, python: &Path) -> Self {
        python.clone_into(&mut self.python);
        self
    }

    fn ensure(&self, instance: &str, lite: Option<&str>) -> Result<Endpoint> {
        let mut command = Command::new(&self.python);
        command.arg(&self.session_py);
        if let Some(ghidra) = &self.ghidra {
            command.arg("--ghidra").arg(ghidra);
        }
        command
            .arg("--state")
            .arg(&self.state)
            .arg("--instance")
            .arg(instance)
            .arg("ensure");
        if let Some(mode) = lite {
            command
                .env("HYDRA_LITE", mode)
                .env_remove("GHIDRA_SESSION_FRONT");
        }
        let output = command.output()?;
        if !output.status.success() {
            return Err(Error::Invalid(format!(
                "starting daemon {instance} failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Endpoint::from_state(&self.state, instance)
    }

    /// The endpoint of the instance itself, started by the launcher as `HYDRA_LITE` says (the
    /// environment is inherited): lite when the setting and the installation allow it.
    ///
    /// # Errors
    /// [`code::INVALID`] when the launcher fails, or the endpoint file cannot be read.
    pub fn primary_endpoint(&self) -> Result<Endpoint> {
        self.ensure(&self.instance, None)
    }
}

impl FullDaemon for PythonLauncher {
    fn endpoint(&self) -> Result<Endpoint> {
        self.ensure(&full_instance(&self.instance), Some("off"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_parse_like_the_python_setting() {
        assert_eq!(LiteMode::parse(" AUTO ").ok(), Some(LiteMode::Auto));
        assert_eq!(LiteMode::parse("only").ok(), Some(LiteMode::Only));
        assert_eq!(LiteMode::parse("Off").ok(), Some(LiteMode::Off));
        assert!(LiteMode::parse("sometimes").is_err());
        assert!(LiteMode::Only.returns_refusals() && !LiteMode::Auto.returns_refusals());
    }

    #[test]
    fn the_full_instance_name_fits_an_instance() {
        assert_eq!(full_instance("default"), "default.full");
        let long = "x".repeat(64);
        assert_eq!(full_instance(&long), format!("{}.full", "x".repeat(59)));
        assert_eq!(full_instance(&long).len(), 64);
    }

    #[test]
    fn a_launcher_is_made_from_an_endpoint_file() {
        let l =
            PythonLauncher::for_endpoint_file(Path::new("s.py"), Path::new("/st/ate/inst.json"))
                .expect("a path with a parent and a stem");
        assert_eq!(l.instance, "inst");
        assert_eq!(l.state, Path::new("/st/ate"));
        assert!(
            PythonLauncher::for_endpoint_file(Path::new("s.py"), Path::new("inst.json")).is_err()
        );
    }
}
