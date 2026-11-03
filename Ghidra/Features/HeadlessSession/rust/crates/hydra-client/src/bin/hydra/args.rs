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
//! The command line: global options, one subcommand, its options. No prompts, no defaults that
//! need a terminal.

use std::collections::{HashMap, HashSet};
use std::ops::RangeInclusive;
use std::path::PathBuf;

use crate::error::CliError;

/// Which daemon answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendChoice {
    /// `hydra-lite` when it is running and can answer, the full daemon otherwise.
    #[default]
    Auto,
    /// The full daemon only.
    Full,
    /// `hydra-lite` only; a refusal is an error.
    Lite,
}

/// How the result is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// One JSON object on stdout (the default).
    #[default]
    Json,
    /// Plain text meant for a person.
    Text,
}

/// Whether a missing daemon is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StartPolicy {
    /// Start one.
    #[default]
    Auto,
    /// Never start one; a missing daemon is exit 4.
    Never,
}

/// Options every subcommand accepts.
#[derive(Debug, Clone, Default)]
pub struct Global {
    /// `--state`: the daemon state directory.
    pub state: Option<PathBuf>,
    /// `--ghidra`: the Hydra Engine install.
    pub ghidra: Option<PathBuf>,
    /// `--project`: the project (a `.gpr` or its folder).
    pub project: Option<String>,
    /// `--program`: the program in it.
    pub program: Option<String>,
    /// `--instance`: the daemon instance name.
    pub instance: Option<String>,
    /// `--backend`.
    pub backend: BackendChoice,
    /// `--json` / `--text`.
    pub format: Format,
    /// `--deadline`: client-side deadline of each request, in seconds.
    pub deadline_s: Option<f64>,
    /// `--no-start`.
    pub start: StartPolicy,
    /// `--python`: the interpreter that runs the install's launcher.
    pub python: Option<String>,
    /// `--lite-bin`: the `hydra-lite` executable.
    pub lite_bin: Option<PathBuf>,
}

/// Whether `analyze` runs on the imported program too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Analysis {
    /// Import only.
    Skip,
    /// Import, then auto-analyse.
    Run,
}

/// What `open` does with a project that does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Creation {
    /// A missing project is `not_found`.
    Never,
    /// A missing project is created empty.
    IfMissing,
}

/// What `import` does with a file already in the project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duplicates {
    /// Answer `imported:false` with the existing entry.
    Reuse,
    /// Import it again.
    Allow,
}

/// What `shutdown` does while other clients are connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Force {
    /// Refuse (`conflict`).
    No,
    /// Stop anyway; unsaved changes are discarded.
    Yes,
}

/// What `import` is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportArgs {
    /// The file to import.
    pub file: String,
    /// Project folder, default `/`.
    pub folder: Option<String>,
    /// Name in the project.
    pub name: Option<String>,
    /// Ghidra language id.
    pub language: Option<String>,
    /// Compiler spec id.
    pub compiler: Option<String>,
    /// Analyse after importing.
    pub analysis: Analysis,
    /// Re-import a file the project already holds.
    pub duplicates: Duplicates,
    /// Engine-side timeout in seconds.
    pub timeout_s: Option<u64>,
}

/// A parsed subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `open`: select a project (and program), creating the project on request.
    Open {
        /// The project path.
        path: String,
        /// Create it when missing.
        creation: Creation,
    },
    /// `import`: add a binary to a project, optionally analysing it.
    Import(ImportArgs),
    /// `analyze`: auto-analyse the selected program and save it.
    Analyze {
        /// Engine-side timeout in seconds.
        timeout_s: Option<u64>,
    },
    /// `status`: what is running; starts nothing.
    Status,
    /// `start`: make sure a daemon is running.
    Start,
    /// `shutdown`: stop the daemons this command line talks to.
    Shutdown(Force),
    /// `info`: facts about the selected program.
    Info,
    /// `list`: the project's folders and programs.
    List {
        /// Folder, default `/`.
        folder: Option<String>,
        /// Page size.
        limit: Option<u64>,
        /// Page start.
        offset: Option<u64>,
    },
    /// `functions` (and `search --name`): functions by name filter.
    Functions {
        /// Substring of the name.
        contains: Option<String>,
        /// Page size.
        limit: Option<u64>,
        /// Page start.
        offset: Option<u64>,
    },
    /// `decompile`: C text for a function.
    Decompile {
        /// Address or function name.
        target: String,
        /// Decompiler timeout in seconds.
        timeout_s: Option<u64>,
        /// Cap on the text.
        max_chars: Option<u64>,
    },
    /// Everything `HydraCli.java` answers: `function`, `disasm`, `xrefs`, `callers`, `callees`,
    /// `strings`, `imports`, `bytes`, `search`.
    Script {
        /// The subcommand's name, which is also the script's operation.
        op: &'static str,
        /// Address or function name, when the operation takes one.
        target: Option<String>,
        /// `key=value` options for the script.
        opts: Vec<(&'static str, String)>,
    },
    /// `version`.
    Version,
    /// `help`.
    Help,
}

impl Command {
    /// The subcommand's name as typed and as printed in results.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Open { .. } => "open",
            Self::Import(_) => "import",
            Self::Analyze { .. } => "analyze",
            Self::Status => "status",
            Self::Start => "start",
            Self::Shutdown(_) => "shutdown",
            Self::Info => "info",
            Self::List { .. } => "list",
            Self::Functions { .. } => "functions",
            Self::Decompile { .. } => "decompile",
            Self::Script { op, .. } => op,
            Self::Version => "version",
            Self::Help => "help",
        }
    }
}

/// The result of parsing.
#[derive(Debug, Clone)]
pub struct Parsed {
    /// The global options.
    pub global: Global,
    /// The subcommand.
    pub command: Command,
}

/// The usage text.
pub const USAGE: &str = "usage: hydra [global options] <command> [options]

commands:
  open <project.gpr> [--program NAME] [--create]   select a project (and program); --create makes it
  import <file> [--analyze] [--folder F] [--name N] [--language L] [--compiler C] [--duplicate]
  analyze [--timeout S]                            auto-analyse the selected program and save it
  status                                           what is running (starts nothing)
  start                                            start the daemon if it is not running
  shutdown [--force]                               stop the daemon(s)
  info                                             facts about the selected program
  list [--folder F] [--limit N] [--offset N]       the project's programs
  functions [--contains S] [--limit N] [--offset N]
  function <addr|name>                             signature, bounds, calling convention, counts
  decompile <addr|name> [--timeout S] [--max-chars N]
  disasm <addr|name> [--count N]                   a function (by name) or N instructions from an address
  xrefs <addr|name> [--direction to|from|both] [--limit N]
  callers <addr|name> [--limit N]
  callees <addr|name>
  strings [--min N] [--contains S] [--limit N] [--offset N]
  imports [--contains S] [--library L] [--limit N] [--offset N]
  bytes <addr|name> [--len N]
  search (--hex 'AA BB ?? CC' | --text S [--wide] | --name S) [--limit N]
  version | help

global options:
  --project P --program NAME     override the selected project / program (or HYDRA_PROJECT / HYDRA_PROGRAM)
  --state DIR --ghidra DIR       daemon state directory / Hydra Engine install (HYDRA_STATE / HYDRA_GHIDRA)
  --backend auto|full|lite       default auto: hydra-lite if it is running and can answer, else full
  --json | --text                JSON object on stdout (default) | plain text
  --deadline S                   client-side deadline of each request, seconds (default 600)
  --no-start                     never start a daemon (exit 4 when none runs)
  --instance NAME --python EXE --lite-bin EXE

exit codes: 0 ok, 1 failed, 2 usage, 3 not found, 4 no daemon, 5 busy/timeout, 6 incompatible,
            7 no project/program selected, 8 refused, 9 needs the full daemon
";

const GLOBAL_VALUES: &[&str] = &[
    "state", "ghidra", "project", "program", "instance", "backend", "deadline", "python",
    "lite-bin",
];
const GLOBAL_SWITCHES: &[&str] = &["json", "text", "no-start"];

struct Spec {
    name: &'static str,
    positionals: RangeInclusive<usize>,
    values: &'static [&'static str],
    switches: &'static [&'static str],
}

const fn spec(
    name: &'static str,
    positionals: RangeInclusive<usize>,
    values: &'static [&'static str],
    switches: &'static [&'static str],
) -> Spec {
    Spec {
        name,
        positionals,
        values,
        switches,
    }
}

const SPECS: &[Spec] = &[
    spec("open", 1..=1, &[], &["create"]),
    spec(
        "import",
        1..=1,
        &["folder", "name", "language", "compiler", "timeout"],
        &["analyze", "duplicate"],
    ),
    spec("analyze", 0..=0, &["timeout"], &[]),
    spec("status", 0..=0, &[], &[]),
    spec("start", 0..=0, &[], &[]),
    spec("shutdown", 0..=0, &[], &["force"]),
    spec("info", 0..=0, &[], &[]),
    spec("list", 0..=0, &["folder", "limit", "offset"], &[]),
    spec("functions", 0..=0, &["contains", "limit", "offset"], &[]),
    spec("function", 1..=1, &[], &[]),
    spec("decompile", 1..=1, &["timeout", "max-chars"], &[]),
    spec("disasm", 1..=1, &["count"], &[]),
    spec("xrefs", 1..=1, &["direction", "limit"], &[]),
    spec("callers", 1..=1, &["limit"], &[]),
    spec("callees", 1..=1, &[], &[]),
    spec(
        "strings",
        0..=0,
        &["min", "contains", "limit", "offset"],
        &[],
    ),
    spec(
        "imports",
        0..=0,
        &["contains", "library", "limit", "offset"],
        &[],
    ),
    spec("bytes", 1..=1, &["len"], &[]),
    spec(
        "search",
        0..=0,
        &["hex", "text", "name", "limit"],
        &["wide"],
    ),
    spec("version", 0..=0, &[], &[]),
    spec("help", 0..=0, &[], &[]),
];

/// One command's flags after the spec has sorted them.
#[derive(Debug, Default)]
struct Flags {
    positional: Vec<String>,
    values: HashMap<String, String>,
    switches: HashSet<String>,
}

impl Flags {
    fn value(&self, name: &str) -> Option<String> {
        self.values.get(name).cloned()
    }

    fn switch(&self, name: &str) -> bool {
        self.switches.contains(name)
    }

    fn number(&self, name: &str) -> Result<Option<u64>, CliError> {
        self.values
            .get(name)
            .map(|v| {
                v.parse::<u64>().map_err(|_| {
                    CliError::usage(format!(
                        "--{name} needs a non-negative whole number, got {v:?}"
                    ))
                })
            })
            .transpose()
    }

    /// The script option `key=value` for a numeric flag, validated here so the script never sees
    /// a malformed number.
    fn number_opt(
        &self,
        flag: &str,
        key: &'static str,
        out: &mut Vec<(&'static str, String)>,
    ) -> Result<(), CliError> {
        if let Some(n) = self.number(flag)? {
            out.push((key, n.to_string()));
        }
        Ok(())
    }

    fn text_opt(&self, flag: &str, key: &'static str, out: &mut Vec<(&'static str, String)>) {
        if let Some(v) = self.value(flag) {
            out.push((key, v));
        }
    }
}

fn take_value(
    name: &str,
    inline: Option<String>,
    rest: &mut std::slice::Iter<'_, String>,
) -> Result<String, CliError> {
    match inline {
        Some(v) => Ok(v),
        None => rest
            .next()
            .cloned()
            .ok_or_else(|| CliError::usage(format!("--{name} needs a value"))),
    }
}

fn split_flag(token: &str) -> Option<(&str, Option<String>)> {
    let body = token.strip_prefix("--")?;
    if body.is_empty() {
        return None;
    }
    Some(match body.split_once('=') {
        Some((n, v)) => (n, Some(v.to_owned())),
        None => (body, None),
    })
}

fn set_global(g: &mut Global, name: &str, value: String) -> Result<(), CliError> {
    match name {
        "state" => g.state = Some(PathBuf::from(value)),
        "ghidra" => g.ghidra = Some(PathBuf::from(value)),
        "project" => g.project = Some(value),
        "program" => g.program = Some(value),
        "instance" => g.instance = Some(value),
        "python" => g.python = Some(value),
        "lite-bin" => g.lite_bin = Some(PathBuf::from(value)),
        "backend" => {
            g.backend = match value.as_str() {
                "auto" => BackendChoice::Auto,
                "full" => BackendChoice::Full,
                "lite" => BackendChoice::Lite,
                other => {
                    return Err(CliError::usage(format!(
                        "--backend is auto, full or lite, not {other:?}"
                    )));
                }
            };
        }
        "deadline" => {
            let s: f64 = value
                .parse()
                .map_err(|_| CliError::usage(format!("--deadline needs seconds, got {value:?}")))?;
            if !s.is_finite() || s <= 0.0 {
                return Err(CliError::usage(
                    "--deadline must be a positive number of seconds",
                ));
            }
            g.deadline_s = Some(s);
        }
        other => return Err(CliError::usage(format!("unknown option --{other}"))),
    }
    Ok(())
}

/// Parses everything after the program name.
///
/// # Errors
/// A usage error for an unknown command or option, a missing value or argument, or a malformed
/// number.
pub fn parse(argv: &[String]) -> Result<Parsed, CliError> {
    let mut global = Global::default();
    let mut rest: Vec<String> = Vec::new();
    let mut tokens = argv.iter();
    let mut only_positionals = false;
    while let Some(token) = tokens.next() {
        if only_positionals {
            rest.push(token.clone());
            continue;
        }
        if token == "--" {
            only_positionals = true;
            rest.push(token.clone());
            continue;
        }
        if token == "-h" {
            rest.push("help".to_owned());
            continue;
        }
        match split_flag(token) {
            Some((name, inline)) if GLOBAL_VALUES.contains(&name) => {
                let value = take_value(name, inline, &mut tokens)?;
                set_global(&mut global, name, value)?;
            }
            Some(("json", None)) => global.format = Format::Json,
            Some(("text", None)) => global.format = Format::Text,
            Some(("no-start", None)) => global.start = StartPolicy::Never,
            Some((name, _)) if GLOBAL_SWITCHES.contains(&name) => {
                return Err(CliError::usage(format!("--{name} takes no value")));
            }
            Some(("help", _)) => rest.push("help".to_owned()),
            _ => rest.push(token.clone()),
        }
    }
    let mut rest_iter = rest.into_iter();
    let name = rest_iter
        .next()
        .ok_or_else(|| CliError::usage("no command given; try `hydra help`"))?;
    let command = parse_command(&name, &rest_iter.collect::<Vec<_>>())?;
    Ok(Parsed { global, command })
}

fn sort_flags(spec: &Spec, tokens: &[String]) -> Result<Flags, CliError> {
    let mut flags = Flags::default();
    let mut iter = tokens.iter();
    let mut only_positionals = false;
    while let Some(token) = iter.next() {
        if only_positionals || !token.starts_with("--") {
            flags.positional.push(token.clone());
            continue;
        }
        if token == "--" {
            only_positionals = true;
            continue;
        }
        let Some((name, inline)) = split_flag(token) else {
            flags.positional.push(token.clone());
            continue;
        };
        if spec.values.contains(&name) {
            let value = take_value(name, inline, &mut iter)?;
            flags.values.insert(name.to_owned(), value);
        } else if spec.switches.contains(&name) {
            if inline.is_some() {
                return Err(CliError::usage(format!("--{name} takes no value")));
            }
            flags.switches.insert(name.to_owned());
        } else {
            return Err(CliError::usage(format!(
                "`hydra {}` has no option --{name}",
                spec.name
            )));
        }
    }
    if !spec.positionals.contains(&flags.positional.len()) {
        return Err(CliError::usage(format!(
            "`hydra {}` takes {} argument(s), got {}",
            spec.name,
            if spec.positionals.start() == spec.positionals.end() {
                spec.positionals.start().to_string()
            } else {
                format!("{}..{}", spec.positionals.start(), spec.positionals.end())
            },
            flags.positional.len()
        )));
    }
    Ok(flags)
}

fn parse_command(name: &str, tokens: &[String]) -> Result<Command, CliError> {
    let spec = SPECS
        .iter()
        .find(|s| s.name == name)
        .ok_or_else(|| CliError::usage(format!("unknown command {name:?}; try `hydra help`")))?;
    let f = sort_flags(spec, tokens)?;
    Ok(match name {
        "open" => Command::Open {
            path: f.positional[0].clone(),
            creation: if f.switch("create") {
                Creation::IfMissing
            } else {
                Creation::Never
            },
        },
        "import" => Command::Import(ImportArgs {
            file: f.positional[0].clone(),
            folder: f.value("folder"),
            name: f.value("name"),
            language: f.value("language"),
            compiler: f.value("compiler"),
            analysis: if f.switch("analyze") {
                Analysis::Run
            } else {
                Analysis::Skip
            },
            duplicates: if f.switch("duplicate") {
                Duplicates::Allow
            } else {
                Duplicates::Reuse
            },
            timeout_s: f.number("timeout")?,
        }),
        "analyze" => Command::Analyze {
            timeout_s: f.number("timeout")?,
        },
        "status" => Command::Status,
        "start" => Command::Start,
        "shutdown" => Command::Shutdown(if f.switch("force") {
            Force::Yes
        } else {
            Force::No
        }),
        "info" => Command::Info,
        "list" => Command::List {
            folder: f.value("folder"),
            limit: f.number("limit")?,
            offset: f.number("offset")?,
        },
        "functions" => Command::Functions {
            contains: f.value("contains"),
            limit: f.number("limit")?,
            offset: f.number("offset")?,
        },
        "decompile" => Command::Decompile {
            target: f.positional[0].clone(),
            timeout_s: f.number("timeout")?,
            max_chars: f.number("max-chars")?,
        },
        "function" | "callees" | "disasm" | "xrefs" | "callers" | "strings" | "imports"
        | "bytes" => parse_script_command(name, &f)?,
        "search" => parse_search(&f)?,
        "version" => Command::Version,
        "help" => Command::Help,
        other => unreachable!("SPECS lists {other:?} but parse_command does not handle it"),
    })
}

fn parse_script_command(name: &str, f: &Flags) -> Result<Command, CliError> {
    let mut o = Vec::new();
    let op: &'static str = match name {
        "function" => "function",
        "callees" => "callees",
        "disasm" => {
            f.number_opt("count", "count", &mut o)?;
            "disasm"
        }
        "xrefs" => {
            if let Some(d) = f.value("direction") {
                if !["to", "from", "both"].contains(&d.as_str()) {
                    return Err(CliError::usage("--direction is to, from or both"));
                }
                o.push(("direction", d));
            }
            f.number_opt("limit", "limit", &mut o)?;
            "xrefs"
        }
        "callers" => {
            f.number_opt("limit", "limit", &mut o)?;
            "callers"
        }
        "strings" => {
            f.number_opt("min", "min", &mut o)?;
            f.text_opt("contains", "contains", &mut o);
            f.number_opt("limit", "limit", &mut o)?;
            f.number_opt("offset", "offset", &mut o)?;
            "strings"
        }
        "imports" => {
            f.text_opt("contains", "contains", &mut o);
            f.text_opt("library", "library", &mut o);
            f.number_opt("limit", "limit", &mut o)?;
            f.number_opt("offset", "offset", &mut o)?;
            "imports"
        }
        "bytes" => {
            f.number_opt("len", "len", &mut o)?;
            "bytes"
        }
        other => unreachable!("{other:?} is not a script command"),
    };
    Ok(Command::Script {
        op,
        target: f.positional.first().cloned(),
        opts: o,
    })
}

fn parse_search(f: &Flags) -> Result<Command, CliError> {
    let given = ["hex", "text", "name"]
        .iter()
        .filter(|k| f.values.contains_key(**k))
        .count();
    if given != 1 {
        return Err(CliError::usage(
            "`hydra search` needs exactly one of --hex, --text or --name",
        ));
    }
    if let Some(name) = f.value("name") {
        if f.switch("wide") {
            return Err(CliError::usage("--wide goes with --text"));
        }
        return Ok(Command::Functions {
            contains: Some(name),
            limit: f.number("limit")?,
            offset: None,
        });
    }
    let mut opts = Vec::new();
    f.text_opt("hex", "hex", &mut opts);
    f.text_opt("text", "text", &mut opts);
    if f.switch("wide") {
        if !f.values.contains_key("text") {
            return Err(CliError::usage("--wide goes with --text"));
        }
        opts.push(("wide", "1".to_owned()));
    }
    f.number_opt("limit", "limit", &mut opts)?;
    Ok(Command::Script {
        op: "search",
        target: None,
        opts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(args: &[&str]) -> Parsed {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        parse(&owned).unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }

    fn parse_err(args: &[&str]) -> CliError {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        parse(&owned).expect_err("should not parse")
    }

    #[test]
    fn global_options_may_come_before_or_after_the_command() {
        let a = parse_ok(&["--state", "S", "info", "--text"]);
        assert_eq!(a.global.state, Some(PathBuf::from("S")));
        assert_eq!(a.global.format, Format::Text);
        assert_eq!(a.command, Command::Info);
        let b = parse_ok(&["info", "--state=S", "--program", "x.exe"]);
        assert_eq!(b.global.state, Some(PathBuf::from("S")));
        assert_eq!(b.global.program.as_deref(), Some("x.exe"));
    }

    #[test]
    fn decompile_takes_a_target_and_numbers() {
        let p = parse_ok(&["decompile", "0x401000", "--timeout", "5", "--max-chars=99"]);
        assert_eq!(
            p.command,
            Command::Decompile {
                target: "0x401000".into(),
                timeout_s: Some(5),
                max_chars: Some(99)
            }
        );
    }

    #[test]
    fn script_commands_carry_validated_options() {
        let p = parse_ok(&["xrefs", "main", "--direction", "both", "--limit", "7"]);
        assert_eq!(
            p.command,
            Command::Script {
                op: "xrefs",
                target: Some("main".into()),
                opts: vec![("direction", "both".into()), ("limit", "7".into())],
            }
        );
    }

    #[test]
    fn search_name_is_a_function_filter_and_hex_is_a_script() {
        assert!(matches!(
            parse_ok(&["search", "--name", "Init"]).command,
            Command::Functions { contains: Some(ref s), .. } if s == "Init"
        ));
        assert!(matches!(
            parse_ok(&["search", "--hex", "4d 5a ??"]).command,
            Command::Script { op: "search", .. }
        ));
    }

    #[test]
    fn mistakes_are_usage_errors() {
        for args in [
            &["nonsense"][..],
            &[],
            &["decompile"],
            &["decompile", "a", "b"],
            &["info", "--bogus"],
            &["functions", "--limit", "many"],
            &["xrefs", "x", "--direction", "up"],
            &["search"],
            &["search", "--hex", "00", "--text", "a"],
            &["search", "--name", "a", "--wide"],
            &["--backend", "fast", "info"],
            &["--deadline", "0", "info"],
            &["--state"],
            &["info", "--text=1"],
        ] {
            assert_eq!(
                parse_err(args).exit,
                crate::error::Exit::Usage,
                "args {args:?}"
            );
        }
    }

    #[test]
    fn double_dash_ends_options() {
        let p = parse_ok(&["function", "--", "--odd-name"]);
        assert!(matches!(
            p.command,
            Command::Script { target: Some(ref t), .. } if t == "--odd-name"
        ));
    }

    #[test]
    fn every_spec_has_a_unique_name() {
        let mut seen = HashSet::new();
        for s in SPECS {
            assert!(seen.insert(s.name), "duplicate spec {}", s.name);
        }
    }
}
