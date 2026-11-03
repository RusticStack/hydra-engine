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
//! Finding, attaching to and starting the daemons. A daemon is started the way every shipped
//! client starts it, through the install's launcher (`ghidra_session.py ensure`), so the launcher
//! keeps owning the JDK choice, the class cache and the process hand-off. The interpreter is the
//! only thing this command line needs besides the install.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hydra_client::{ConnectOptions, Endpoint, Error, Session};
use serde_json::Value;

use crate::args::StartPolicy;
use crate::env::Env;
use crate::error::CliError;

/// How long the launcher may take to report a daemon ready.
const START_LIMIT: Duration = Duration::from_secs(240);
/// How long a `hello` may take.
const HELLO_DEADLINE_S: f64 = 15.0;
/// `CREATE_NO_WINDOW`, so a launcher started from a console-less agent opens no window.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Which of the two daemons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instance {
    /// The Java daemon, which answers everything.
    Full,
    /// `hydra-lite`, which answers a read-only subset without a JVM.
    Lite,
}

impl Instance {
    /// The backend name printed in results.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Lite => "lite",
        }
    }

    /// The launcher instance name.
    #[must_use]
    pub fn name(self, env: &Env) -> String {
        match self {
            Self::Full => env.instance.clone(),
            Self::Lite => format!("{}-lite", env.instance),
        }
    }
}

fn connect_options() -> ConnectOptions {
    ConnectOptions {
        hello_deadline: Some(HELLO_DEADLINE_S),
        ..ConnectOptions::new("hydra-cli", "agent")
    }
}

/// The endpoint file of an instance.
#[must_use]
pub fn endpoint_file(env: &Env, which: Instance) -> PathBuf {
    env.state.join(format!("{}.json", which.name(env)))
}

/// Connects to a running daemon, or answers `None` when there is none to connect to (no endpoint
/// file, or a stale one whose port refuses).
///
/// # Errors
/// A daemon that answers but cannot be used: wrong token, incompatible protocol.
pub fn attach(env: &Env, which: Instance) -> Result<Option<Session>, CliError> {
    let path = endpoint_file(env, which);
    if !path.is_file() {
        return Ok(None);
    }
    let endpoint = match Endpoint::read_file(&path) {
        Ok(e) => e,
        Err(Error::Io(_) | Error::Json(_) | Error::Endpoint(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    match Session::connect(endpoint, &connect_options()) {
        Ok(s) => Ok(Some(s)),
        Err(Error::Io(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Attaches to the daemon, starting it first when there is none and the policy allows.
///
/// # Errors
/// `Unavailable` when no daemon runs and none may or can be started; otherwise as [`attach`].
pub fn attach_or_start(env: &Env, which: Instance) -> Result<Session, CliError> {
    if let Some(s) = attach(env, which)? {
        return Ok(s);
    }
    if env.start == StartPolicy::Never {
        return Err(CliError::unavailable(
            "no_daemon",
            format!(
                "no {} daemon is running and --no-start was given",
                which.label()
            ),
        ));
    }
    start(env, which)?;
    let mut last = None;
    for _ in 0..20 {
        match attach(env, which) {
            Ok(Some(s)) => return Ok(s),
            Ok(None) => std::thread::sleep(Duration::from_millis(250)),
            Err(e) => last = Some(e),
        }
        if last.is_some() {
            break;
        }
    }
    Err(last.unwrap_or_else(|| {
        CliError::unavailable(
            "daemon_unreachable",
            format!(
                "the launcher reported a {} daemon but it does not answer",
                which.label()
            ),
        )
    }))
}

/// The interpreter candidates, in order.
fn interpreters(env: &Env) -> Vec<String> {
    match &env.python {
        Some(p) => vec![p.clone()],
        None => vec!["python".to_owned(), "python3".to_owned(), "py".to_owned()],
    }
}

/// Runs `ghidra_session.py ensure` for an instance.
///
/// # Errors
/// `Unavailable` when there is no install, no interpreter, the launcher fails or takes too long.
pub fn start(env: &Env, which: Instance) -> Result<(), CliError> {
    let (ghidra, launcher) = env.launcher()?;
    env.publish_script()?;
    std::fs::create_dir_all(&env.state)
        .map_err(|e| CliError::unavailable("state_io", format!("{}: {e}", env.state.display())))?;
    let lite =
        match which {
            Instance::Full => None,
            Instance::Lite => Some(env.lite_bin.clone().filter(|p| p.is_file()).ok_or_else(
                || {
                    CliError::unavailable("no_lite", "hydra-lite.exe was not found")
                        .with_hint("pass --lite-bin or set HYDRA_LITE, or use --backend full")
                },
            )?),
        };
    let mut tried = Vec::new();
    for python in interpreters(env) {
        let mut cmd = Command::new(&python);
        cmd.arg("-I")
            .arg(&launcher)
            .arg("--ghidra")
            .arg(&ghidra)
            .arg("--state")
            .arg(&env.state)
            .arg("--instance")
            .arg(which.name(env))
            .arg("ensure")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match &lite {
            Some(bin) => cmd.env("GHIDRA_SESSION_FRONT", bin),
            None => cmd.env_remove("GHIDRA_SESSION_FRONT"),
        };
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut cmd, CREATE_NO_WINDOW);
        match cmd.spawn() {
            Ok(child) => return wait_for(child, which),
            Err(e) => tried.push(format!("{python}: {e}")),
        }
    }
    Err(CliError::unavailable(
        "no_python",
        format!(
            "cannot run the launcher: no interpreter works ({})",
            tried.join("; ")
        ),
    )
    .with_hint("install Python 3 or pass --python EXE; the install's launcher is a Python script"))
}

fn wait_for(mut child: std::process::Child, which: Instance) -> Result<(), CliError> {
    let began = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = child.wait_with_output().map_err(|e| {
                    CliError::unavailable(
                        "launcher_io",
                        format!("reading the launcher's output: {e}"),
                    )
                })?;
                if status.success() {
                    return Ok(());
                }
                let err = String::from_utf8_lossy(&out.stderr);
                let tail: String = err.trim().lines().last().unwrap_or("no output").to_owned();
                let mut e = CliError::unavailable(
                    "launch_failed",
                    format!(
                        "the launcher could not start the {} daemon ({status}): {tail}",
                        which.label()
                    ),
                );
                e.details = serde_json::json!({"stderr": err.trim()});
                return Err(e);
            }
            Ok(None) if began.elapsed() < START_LIMIT => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CliError::unavailable(
                    "launch_timeout",
                    format!(
                        "the launcher did not report a {} daemon within {} s",
                        which.label(),
                        START_LIMIT.as_secs()
                    ),
                ));
            }
            Err(e) => {
                return Err(CliError::unavailable(
                    "launcher_io",
                    format!("waiting for the launcher: {e}"),
                ));
            }
        }
    }
}

/// The endpoint object of a running daemon without its token, for `status` and `start`.
#[must_use]
pub fn public_endpoint(session: &Session) -> Value {
    let mut value = session.endpoint().value.clone();
    if let Some(o) = value.as_object_mut() {
        o.remove("token");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::Global;

    fn env_for(state: &std::path::Path) -> Env {
        let vars = [("HYDRA_STATE", state.to_str().expect("utf8").to_owned())];
        Env::resolve(
            &Global::default(),
            &|k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone()),
            None,
        )
        .expect("resolves")
    }

    #[test]
    fn instances_have_distinct_endpoint_files() {
        let dir = std::env::temp_dir().join(format!("hydra-daemon-{}", std::process::id()));
        let env = env_for(&dir);
        assert_eq!(endpoint_file(&env, Instance::Full), dir.join("hydra.json"));
        assert_eq!(
            endpoint_file(&env, Instance::Lite),
            dir.join("hydra-lite.json")
        );
    }

    #[test]
    fn no_endpoint_file_means_no_daemon() {
        let dir = std::env::temp_dir().join(format!("hydra-daemon-none-{}", std::process::id()));
        let env = env_for(&dir);
        assert!(attach(&env, Instance::Full).expect("no error").is_none());
    }

    #[test]
    fn no_start_refuses_to_launch() {
        let dir = std::env::temp_dir().join(format!("hydra-daemon-nostart-{}", std::process::id()));
        let mut env = env_for(&dir);
        env.start = StartPolicy::Never;
        let err = attach_or_start(&env, Instance::Full).expect_err("refuses");
        assert_eq!(err.code, "no_daemon");
        assert_eq!(err.exit, crate::error::Exit::Unavailable);
    }

    #[test]
    fn starting_without_an_install_names_the_remedy() {
        let dir =
            std::env::temp_dir().join(format!("hydra-daemon-noinstall-{}", std::process::id()));
        let env = env_for(&dir);
        let err = start(&env, Instance::Full).expect_err("no install");
        assert_eq!(err.code, "no_install");
        assert!(err.hint.is_some());
    }
}
