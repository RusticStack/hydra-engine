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
//! `hydra`: the Hydra Engine as a plain command line for coding agents.
//!
//! Every command prints one JSON object on stdout (or text with `--text`), exits with a
//! documented status, never prompts and never starts a GUI. A daemon is attached to, or started
//! through the install's launcher, as needed. `CLI.md` is the manual.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool: stdout carries the result, stderr the diagnostics"
)]
#![expect(
    unreachable_pub,
    reason = "a binary: nothing is reachable from outside, `pub` only marks each module's interface"
)]

mod args;
mod commands;
mod daemon;
mod env;
mod error;
mod render;

use std::process::ExitCode;
use std::time::Instant;

use args::{Command, Format};
use error::{CliError, Exit};
use serde_json::{Value, json};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match args::parse(&argv) {
        Ok(p) => p,
        Err(e) => return report(Format::Json, "hydra", &e),
    };
    let format = parsed.global.format;
    let name = parsed.command.name();
    match parsed.command {
        Command::Help => {
            println!("{}", args::USAGE);
            return ExitCode::SUCCESS;
        }
        Command::Version => {
            let v = json!({
                "ok": true,
                "command": "version",
                "result": {
                    "hydra": env!("CARGO_PKG_VERSION"),
                    "client": hydra_client::CLIENT_VERSION,
                    "protocol": hydra_client::PROTOCOL,
                },
            });
            println!("{v}");
            return ExitCode::SUCCESS;
        }
        _ => {}
    }
    let exe = std::env::current_exe().ok();
    let resolved = env::Env::resolve(&parsed.global, &|k| std::env::var(k).ok(), exe.as_deref());
    let env = match resolved {
        Ok(e) => e,
        Err(e) => return report(format, name, &e),
    };
    let began = Instant::now();
    match commands::run(&env, &parsed.command) {
        Ok(outcome) => {
            print_success(format, name, &outcome, began);
            Exit::Ok.code()
        }
        Err(e) => report(format, name, &e),
    }
}

fn print_success(format: Format, name: &str, outcome: &commands::Outcome, began: Instant) {
    match format {
        Format::Json => {
            let ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
            let v: Value = json!({
                "ok": true,
                "command": name,
                "backend": outcome.backend,
                "ms": ms,
                "result": outcome.result,
            });
            println!("{v}");
        }
        Format::Text => print!("{}", render::text(name, &outcome.result)),
    }
}

fn report(format: Format, name: &str, e: &CliError) -> ExitCode {
    match format {
        Format::Json => println!("{}", e.to_json(name)),
        Format::Text => eprint!("{}", render::error_text(e)),
    }
    e.exit.code()
}
