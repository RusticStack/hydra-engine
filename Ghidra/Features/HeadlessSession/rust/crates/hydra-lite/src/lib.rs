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
//! `hydra-lite`: a JVM-free, read-only Hydra Engine daemon.
//!
//! It speaks protocol 3 of the session daemon (PROTOCOL-3.md) for the subset the Rust Program
//! database reader (`ghidra-progdb`) can answer exactly, with replies byte-identical to the Java
//! daemon's, and answers everything else with the structured error `use_full_daemon`, which a
//! client reads as "send this session to the full daemon". See `HYDRA-LITE.md`.

pub mod engine;
pub mod error;
pub mod identity;
pub mod javaish;
pub mod json;
pub mod os;
pub mod program;
pub mod project;
pub mod request;
pub mod server;
