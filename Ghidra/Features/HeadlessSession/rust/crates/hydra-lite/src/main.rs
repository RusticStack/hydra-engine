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
//! The `hydra-lite` executable (see `HYDRA-LITE.md`).

#![allow(
    clippy::print_stderr,
    reason = "a daemon with no console: stderr is the launcher's log file"
)]

use std::process::ExitCode;

use hydra_lite::server::{parse_args, run, run_learn};

fn main() -> ExitCode {
    let result = parse_args(std::env::args().skip(1)).and_then(|o| {
        if o.learn_from.is_some() {
            run_learn(&o)
        } else {
            run(&o)
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hydra-lite: {e}");
            ExitCode::from(2)
        }
    }
}
