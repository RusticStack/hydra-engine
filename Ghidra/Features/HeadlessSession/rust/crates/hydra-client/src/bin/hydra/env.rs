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
//! Where the daemon's state lives, which install runs it, and which project and program a command
//! acts on. Every lookup of the process environment goes through [`Lookup`] so tests can fake it.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::args::{BackendChoice, Global, StartPolicy};
use crate::error::{CliError, Exit};

/// Reads one environment variable.
pub type Lookup<'a> = &'a dyn Fn(&str) -> Option<String>;

/// The launcher, relative to an install.
const LAUNCHER: &str = "Ghidra/Features/HeadlessSession/support/ghidra_session.py";
/// The default per-request deadline.
pub const DEFAULT_DEADLINE_S: f64 = 600.0;
/// The embedded script that answers what the protocol has no command for.
pub const SCRIPT_SOURCE: &str = include_str!("HydraCli.java");
/// The script's file name, which is also the name the `script` command is given.
pub const SCRIPT_NAME: &str = "HydraCli.java";

/// The project and program a command acts on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selection {
    /// A `.gpr` file or a project folder.
    pub project: Option<String>,
    /// A path, unique name or key of a program in the project.
    pub program: Option<String>,
}

/// Everything resolved from options, environment and the context file.
#[derive(Debug, Clone)]
pub struct Env {
    /// The daemon state directory.
    pub state: PathBuf,
    /// The install, when one was found.
    pub ghidra: Option<PathBuf>,
    /// What the command acts on.
    pub selection: Selection,
    /// The program named by a flag or variable, not by the context file (what `open` selects).
    pub requested_program: Option<String>,
    /// The daemon instance name (the full daemon; the lite one adds `-lite`).
    pub instance: String,
    /// Which daemon answers.
    pub backend: BackendChoice,
    /// Whether a missing daemon is started.
    pub start: StartPolicy,
    /// Interpreter for the launcher.
    pub python: Option<String>,
    /// The `hydra-lite` executable, when one was found.
    pub lite_bin: Option<PathBuf>,
    /// Per-request deadline in seconds.
    pub deadline_s: f64,
    /// Where `open` and `import` remember their selection.
    pub context_file: PathBuf,
}

impl Env {
    /// Resolves options, environment and context file into one value.
    ///
    /// # Errors
    /// A usage error when `HYDRA_DEADLINE` is not a positive number.
    pub fn resolve(global: &Global, get: Lookup<'_>, exe: Option<&Path>) -> Result<Self, CliError> {
        let state = global
            .state
            .clone()
            .or_else(|| get("HYDRA_STATE").map(PathBuf::from))
            .or_else(|| get("GHIDRA_SESSION_HOME").map(PathBuf::from))
            .unwrap_or_else(|| default_state(get));
        let ghidra = global
            .ghidra
            .clone()
            .or_else(|| get("HYDRA_GHIDRA").map(PathBuf::from))
            .or_else(|| get("GHIDRA_INSTALL_DIR").map(PathBuf::from))
            .or_else(|| exe.and_then(install_around));
        let context_file = get("HYDRA_CONTEXT")
            .map_or_else(|| state.join("hydra-cli-context.json"), PathBuf::from);
        let remembered = read_context(&context_file);
        let selection = Selection {
            project: global
                .project
                .clone()
                .or_else(|| get("HYDRA_PROJECT"))
                .or(remembered.project),
            program: global
                .program
                .clone()
                .or_else(|| get("HYDRA_PROGRAM"))
                .or(remembered.program),
        };
        let requested_program = global.program.clone().or_else(|| get("HYDRA_PROGRAM"));
        let deadline_s = match (global.deadline_s, get("HYDRA_DEADLINE")) {
            (Some(s), _) => s,
            (None, Some(v)) => v
                .parse::<f64>()
                .ok()
                .filter(|s| s.is_finite() && *s > 0.0)
                .ok_or_else(|| {
                    CliError::usage(format!("HYDRA_DEADLINE is not a positive number: {v:?}"))
                })?,
            (None, None) => DEFAULT_DEADLINE_S,
        };
        let lite_bin = global
            .lite_bin
            .clone()
            .or_else(|| get("HYDRA_LITE").map(PathBuf::from))
            .or_else(|| {
                exe.and_then(Path::parent)
                    .map(|d| d.join("hydra-lite.exe"))
                    .filter(|p| p.is_file())
            });
        Ok(Self {
            state,
            ghidra,
            selection,
            requested_program,
            instance: global
                .instance
                .clone()
                .or_else(|| get("HYDRA_INSTANCE"))
                .unwrap_or_else(|| "hydra".to_owned()),
            backend: global.backend,
            start: global.start,
            python: global.python.clone().or_else(|| get("HYDRA_PYTHON")),
            lite_bin,
            deadline_s,
            context_file,
        })
    }

    /// The launcher script of the install.
    ///
    /// # Errors
    /// `Unavailable` when no install was found or it has no launcher.
    pub fn launcher(&self) -> Result<(PathBuf, PathBuf), CliError> {
        let ghidra = self.ghidra.clone().ok_or_else(|| {
            CliError::unavailable("no_install", "no Hydra Engine install found").with_hint(
                "pass --ghidra DIR, set HYDRA_GHIDRA, or run hydra from the install's support folder",
            )
        })?;
        let launcher = ghidra.join(LAUNCHER);
        if !launcher.is_file() {
            return Err(CliError::unavailable(
                "no_launcher",
                format!(
                    "{} is not a Hydra Engine install: {} is missing",
                    ghidra.display(),
                    launcher.display()
                ),
            ));
        }
        Ok((ghidra, launcher))
    }

    /// The folder `HydraCli.java` is published to, which the daemon gets as a script path.
    #[must_use]
    pub fn script_dir(&self) -> PathBuf {
        self.state.join("hydra-cli")
    }

    /// Remembers the selection for later commands.
    ///
    /// # Errors
    /// `Failed` when the file cannot be written.
    pub fn remember(&self, selection: &Selection) -> Result<(), CliError> {
        let value = json!({"project": selection.project, "program": selection.program});
        let text = serde_json::to_string_pretty(&value).unwrap_or_default();
        write_atomic(&self.context_file, text.as_bytes()).map_err(|e| {
            CliError::new(
                Exit::Failed,
                "context_write",
                format!("cannot write {}: {e}", self.context_file.display()),
            )
        })
    }

    /// Publishes `HydraCli.java` and makes sure the state's `config.json` lists its folder.
    ///
    /// The daemon reads `config.json` when it starts, so this must happen before it is started;
    /// a daemon that is already running keeps the script path it started with.
    ///
    /// # Errors
    /// `Unavailable` when the state folder is unusable or `config.json` is not a JSON object
    /// (it is never overwritten in that case).
    pub fn publish_script(&self) -> Result<(), CliError> {
        let io = |what: &str, e: std::io::Error| {
            CliError::unavailable("state_io", format!("{what}: {e}"))
        };
        let dir = self.script_dir();
        fs::create_dir_all(&dir).map_err(|e| io(&dir.display().to_string(), e))?;
        let script = dir.join(SCRIPT_NAME);
        if fs::read_to_string(&script).ok().as_deref() != Some(SCRIPT_SOURCE) {
            write_atomic(&script, SCRIPT_SOURCE.as_bytes())
                .map_err(|e| io(&script.display().to_string(), e))?;
        }
        let config_path = self.state.join("config.json");
        let mut config = match fs::read_to_string(&config_path) {
            Ok(text) => serde_json::from_str::<Value>(&text)
                .ok()
                .filter(Value::is_object)
                .ok_or_else(|| {
                    CliError::unavailable(
                        "bad_config",
                        format!(
                            "{} is not a JSON object; not touching it",
                            config_path.display()
                        ),
                    )
                })?,
            Err(_) => json!({}),
        };
        let wanted = dir.display().to_string().replace('\\', "/");
        let paths = config
            .as_object_mut()
            .and_then(|o| {
                o.entry("scriptPath")
                    .or_insert_with(|| json!([]))
                    .as_array_mut()
            })
            .ok_or_else(|| {
                CliError::unavailable("bad_config", "config.json scriptPath is not a list")
            })?;
        let listed = paths
            .iter()
            .filter_map(Value::as_str)
            .any(|p| p.replace('\\', "/").eq_ignore_ascii_case(&wanted));
        if !listed {
            paths.push(Value::String(wanted));
            let text = serde_json::to_string_pretty(&config).unwrap_or_default();
            write_atomic(&config_path, text.as_bytes())
                .map_err(|e| io(&config_path.display().to_string(), e))?;
        }
        Ok(())
    }
}

fn default_state(get: Lookup<'_>) -> PathBuf {
    let base = get("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| get("USERPROFILE").map(|h| PathBuf::from(h).join("AppData").join("Local")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("GhidraSession")
}

/// The install around an executable in `<install>/Ghidra/Features/HeadlessSession/support`.
fn install_around(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .skip(1)
        .take(6)
        .find(|dir| dir.join(LAUNCHER).is_file())
        .map(Path::to_path_buf)
}

fn read_context(path: &Path) -> Selection {
    let Ok(text) = fs::read_to_string(path) else {
        return Selection::default();
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return Selection::default();
    };
    let field = |k: &str| value.get(k).and_then(Value::as_str).map(str::to_owned);
    Selection {
        project: field("project"),
        program: field("program"),
    }
}

/// Writes `bytes` to `path` through a sibling temporary file and a rename, so a reader never sees
/// half a file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hydra-env-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn env_with(vars: &[(&str, &str)], global: &Global) -> Env {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Env::resolve(global, &|k| map.get(k).cloned(), None).expect("resolves")
    }

    #[test]
    fn flags_beat_environment_beat_the_context_file() {
        let dir = scratch("select");
        let ctx = dir.join("ctx.json");
        fs::write(&ctx, r#"{"project":"ctx.gpr","program":"ctx.exe"}"#).expect("write ctx");
        let vars = [
            ("HYDRA_CONTEXT", ctx.to_str().expect("utf8")),
            ("HYDRA_STATE", dir.to_str().expect("utf8")),
        ];
        let none = env_with(&vars, &Global::default());
        assert_eq!(none.selection.project.as_deref(), Some("ctx.gpr"));
        let with_env = env_with(
            &[vars[0], vars[1], ("HYDRA_PROJECT", "env.gpr")],
            &Global::default(),
        );
        assert_eq!(with_env.selection.project.as_deref(), Some("env.gpr"));
        assert_eq!(with_env.selection.program.as_deref(), Some("ctx.exe"));
        let flag = Global {
            project: Some("flag.gpr".into()),
            ..Global::default()
        };
        let with_flag = env_with(&[vars[0], vars[1], ("HYDRA_PROJECT", "env.gpr")], &flag);
        assert_eq!(with_flag.selection.project.as_deref(), Some("flag.gpr"));
    }

    #[test]
    fn remember_round_trips_through_the_context_file() {
        let dir = scratch("remember");
        let e = env_with(
            &[("HYDRA_STATE", dir.to_str().expect("utf8"))],
            &Global::default(),
        );
        let sel = Selection {
            project: Some("a.gpr".into()),
            program: Some("/b.exe".into()),
        };
        e.remember(&sel).expect("remember");
        let again = env_with(
            &[("HYDRA_STATE", dir.to_str().expect("utf8"))],
            &Global::default(),
        );
        assert_eq!(again.selection, sel);
    }

    #[test]
    fn publish_script_writes_the_script_and_lists_it_once() {
        let dir = scratch("publish");
        fs::write(
            dir.join("config.json"),
            r#"{"keepWarm":5,"scriptPath":["X:/other"]}"#,
        )
        .expect("config");
        let e = env_with(
            &[("HYDRA_STATE", dir.to_str().expect("utf8"))],
            &Global::default(),
        );
        e.publish_script().expect("first");
        e.publish_script().expect("second");
        assert_eq!(
            fs::read_to_string(dir.join("hydra-cli").join(SCRIPT_NAME)).expect("script"),
            SCRIPT_SOURCE
        );
        let config: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("config.json")).expect("read"))
                .expect("json");
        assert_eq!(config["keepWarm"], 5);
        let paths = config["scriptPath"].as_array().expect("list");
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert_eq!(paths[0], "X:/other");
    }

    #[test]
    fn publish_script_never_clobbers_a_config_it_cannot_read() {
        let dir = scratch("badconfig");
        fs::write(dir.join("config.json"), "not json").expect("config");
        let e = env_with(
            &[("HYDRA_STATE", dir.to_str().expect("utf8"))],
            &Global::default(),
        );
        let err = e.publish_script().expect_err("refuses");
        assert_eq!(err.exit, Exit::Unavailable);
        assert_eq!(
            fs::read_to_string(dir.join("config.json")).expect("read"),
            "not json"
        );
    }

    #[test]
    fn a_bad_timeout_variable_is_a_usage_error() {
        let map = HashMap::from([("HYDRA_DEADLINE".to_owned(), "soon".to_owned())]);
        let err =
            Env::resolve(&Global::default(), &|k| map.get(k).cloned(), None).expect_err("refuses");
        assert_eq!(err.exit, Exit::Usage);
    }
}
