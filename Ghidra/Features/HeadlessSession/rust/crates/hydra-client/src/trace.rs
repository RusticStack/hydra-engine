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
//! The semantic trace commands (protocol 3, capability `trace`; `PROTOCOL-3.md` "Trace commands").
//!
//! One method per command, named like the Python client's `trace_*`. Each sends exactly the
//! fields the Python method sends and returns the engine's `result` unchanged, so the same request
//! gets the same reply bytes from either client (`daemon_tests.py trace_client_identity`).
//! A writer opens a session with [`Session::trace_open`] and passes the `lease.cap` it got to the
//! writing commands; the reading commands need no capability.

use serde_json::{Map, Value};

use crate::error::Result;
use crate::session::{Session, fields};

fn text(s: &str) -> Value {
    Value::String(s.to_owned())
}

impl Session {
    /// `trace_open`: creates (`create`) or opens a session. `extra` carries `mode`, `cap`,
    /// `takeover`, `name`, `program`, `project`, `modules`, `moduleBase`, `profile`.
    ///
    /// # Errors
    /// As [`Session::call`]; the engine answers `not_owner` for a live writer, `not_found`,
    /// `conflict`, or `busy` (disk reserve).
    pub fn trace_open(
        &self,
        session: Option<&str>,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = extra;
        if let Some(session) = session {
            f.insert("session".to_owned(), text(session));
        }
        self.call("trace_open", f, deadline)
    }

    /// `trace_append`: events (TRACE-1 envelopes without `seq` or `event_id`) as one group commit;
    /// the engine answers `accepted` and `rejected`.
    ///
    /// # Errors
    /// As [`Session::call`]; `not_owner` without the writer lease.
    pub fn trace_append(
        &self,
        session: &str,
        cap: &str,
        events: Vec<Value>,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = extra;
        f.insert("session".to_owned(), text(session));
        f.insert("cap".to_owned(), text(cap));
        f.insert("events".to_owned(), Value::Array(events));
        self.call("trace_append", f, deadline)
    }

    /// `trace_mark`: a `core.marker` event with `label`.
    ///
    /// # Errors
    /// As [`Session::trace_append`].
    pub fn trace_mark(
        &self,
        session: &str,
        cap: &str,
        label: &str,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = extra;
        f.insert("session".to_owned(), text(session));
        f.insert("cap".to_owned(), text(cap));
        f.insert("label".to_owned(), text(label));
        self.call("trace_mark", f, deadline)
    }

    /// `trace_query`: a bounded page (`kinds`, `after`, `upTo`, `limit`, `resource`, `state`,
    /// `corr`, `process_gen`) or, with `group_by`, counts per group.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn trace_query(
        &self,
        session: &str,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        self.trace_read("trace_query", session, extra, deadline)
    }

    /// `trace_explain`: the events upstream or downstream of `event_id`.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn trace_explain(
        &self,
        session: &str,
        event_id: &str,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = extra;
        f.insert("event_id".to_owned(), text(event_id));
        self.trace_read("trace_explain", session, f, deadline)
    }

    /// `trace_diff`: compares sessions `a` and `b` (`group_by`, `kinds`, `align`, `background`).
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn trace_diff(
        &self,
        a: &str,
        b: &str,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = extra;
        f.insert("a".to_owned(), text(a));
        f.insert("b".to_owned(), text(b));
        self.call("trace_diff", f, deadline)
    }

    /// `trace_check`: evaluates assertions (each `pass`, `fail` or `unknown`); the results are
    /// stored only with the writer's `cap` in `extra`.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn trace_check(
        &self,
        session: &str,
        assertions: Vec<Value>,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = extra;
        f.insert("assertions".to_owned(), Value::Array(assertions));
        self.trace_read("trace_check", session, f, deadline)
    }

    /// `trace_export`: the events as JSONL under the session's folder (long lane).
    ///
    /// # Errors
    /// As [`Session::call`]; `cancelled` leaves no file.
    pub fn trace_export(
        &self,
        session: &str,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        self.trace_read("trace_export", session, extra, deadline)
    }

    /// `trace_close`: ends the writer's lease; the session stays readable.
    ///
    /// # Errors
    /// As [`Session::trace_append`].
    pub fn trace_close(
        &self,
        session: &str,
        cap: &str,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = extra;
        f.insert("session".to_owned(), text(session));
        f.insert("cap".to_owned(), text(cap));
        self.call("trace_close", f, deadline)
    }

    /// `trace_list`: the sessions under the trace root and their lease state.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn trace_list(&self, extra: Map<String, Value>, deadline: Option<f64>) -> Result<Value> {
        self.call("trace_list", extra, deadline)
    }

    /// `trace_info`: revision, events, segments, interpretations and the lease state.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn trace_info(
        &self,
        session: &str,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        self.trace_read("trace_info", session, extra, deadline)
    }

    /// `trace_resymbolize`: re-resolves every code address against `program` as it stands now
    /// (a new interpretation revision, long lane).
    ///
    /// # Errors
    /// As [`Session::trace_append`].
    pub fn trace_resymbolize(
        &self,
        session: &str,
        cap: &str,
        program: &str,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = extra;
        f.insert("session".to_owned(), text(session));
        f.insert("cap".to_owned(), text(cap));
        f.insert("program".to_owned(), text(program));
        self.call("trace_resymbolize", f, deadline)
    }

    fn trace_read(
        &self,
        cmd: &str,
        session: &str,
        extra: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = fields([("session", text(session))]);
        f.extend(extra);
        self.call(cmd, f, deadline)
    }
}
