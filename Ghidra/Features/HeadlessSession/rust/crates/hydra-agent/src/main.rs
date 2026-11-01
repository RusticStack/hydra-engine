//! `hydra-agent`: the benchmark's agent shape on the Rust client.
//!
//! Two uses:
//! - `hydra-agent agent --spec spec.json` runs one read/query agent: open the project view,
//!   list the functions, decompile a hot set and a fresh set, run `BenchRead.java` over a few
//!   addresses, ask `info`, close. It writes one JSON line per operation, in the benchmark's
//!   row schema, so the same aggregator reads Python and Rust agents.
//! - `hydra-agent call --endpoint <file>` is the differential harness: one request object per
//!   stdin line, one answer line per stdout line, exactly the bytes the engine sent.
//!
//! The engine and its replies are untouched; this is a second client, not a second server.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line agent host: stdout carries the call mode's protocol lines"
)]

mod call;
mod rows;
mod spec;
mod workload;

use std::process::ExitCode;

const USAGE: &str = "usage:
  hydra-agent agent --spec <spec.json>
  hydra-agent call --endpoint <endpoint.json> [--client NAME] [--harness NAME] [--keep-raw]
  hydra-agent probe --endpoint <endpoint.json> [--client NAME] [--harness NAME]
  hydra-agent version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    match command.as_str() {
        "agent" => run_agent(&args),
        "call" => run_call(&args),
        "probe" => run_probe(&args),
        "version" => {
            println!(
                "hydra-agent {} (client {}, protocol {})",
                env!("CARGO_PKG_VERSION"),
                hydra_client::CLIENT_VERSION,
                hydra_client::PROTOCOL
            );
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("hydra-agent: unknown command {other:?}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_agent(args: &[String]) -> ExitCode {
    let Some(path) = option(args, "--spec") else {
        eprintln!("hydra-agent agent: --spec is required\n{USAGE}");
        return ExitCode::from(2);
    };
    match workload::run(std::path::Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hydra-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_call(args: &[String]) -> ExitCode {
    let Some(path) = option(args, "--endpoint") else {
        eprintln!("hydra-agent call: --endpoint is required\n{USAGE}");
        return ExitCode::from(2);
    };
    let raw = if args.iter().any(|a| a == "--keep-raw") {
        call::KeepRaw::Keep
    } else {
        call::KeepRaw::Drop
    };
    call::run(
        std::path::Path::new(&path),
        option(args, "--client").as_deref().unwrap_or("rust-call"),
        option(args, "--harness").as_deref().unwrap_or("diff"),
        raw,
    )
}

fn run_probe(args: &[String]) -> ExitCode {
    let Some(path) = option(args, "--endpoint") else {
        eprintln!("hydra-agent probe: --endpoint is required\n{USAGE}");
        return ExitCode::from(2);
    };
    call::probe(
        std::path::Path::new(&path),
        option(args, "--client").as_deref().unwrap_or("rust-probe"),
        option(args, "--harness").as_deref().unwrap_or("diff"),
    )
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
