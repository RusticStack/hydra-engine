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
//! The read path the agents use: project and program opens, `info`, `functions`, `decompile`,
//! scripts (`BenchRead.java`, the byte/xref/symbol read), and the closes; and the write path
//! the multi-agent benchmark's direct agents exercise: `apply_overlay`, `drop_overlay`, `edit`,
//! `save` and `fork_project`.
//!
//! Every method returns the engine's `result` object unchanged: the protocol's replies are the
//! contract, and a typed view would silently drop fields the engine may add. The methods exist
//! to name the fields and keep the addresses as strings (`0x...`, `rva:...`, `space:offset`),
//! exactly as the Python client passes them.

use serde_json::{Map, Value, json};

use crate::error::Result;
use crate::session::{Session, fields};

/// Whether an open asks for write access. A bool parameter reads as `true`/`false` at the call
/// site; the protocol field is still a JSON boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Access {
    /// Join as a reader.
    ReadOnly,
    /// Own or share the program for writing.
    Writable,
}

impl Access {
    fn json(self) -> Value {
        Value::Bool(matches!(self, Self::Writable))
    }
}

/// Whether a close may throw away unsaved changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Discard {
    /// Never discard: the engine answers `unsaved_changes` instead.
    Keep,
    /// Discard this client's unsaved changes.
    Discard,
}

impl Discard {
    fn json(self) -> Value {
        Value::Bool(matches!(self, Self::Discard))
    }
}

/// The comment kinds `edit` and `apply_overlay` accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommentKind {
    /// A plate comment (the function's header block).
    Plate,
    /// The comment above the address.
    Pre,
    /// The comment after the instruction on the same line.
    Eol,
    /// A repeatable comment.
    Repeatable,
    /// The comment below the address.
    Post,
}

impl CommentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Plate => "plate",
            Self::Pre => "pre",
            Self::Eol => "eol",
            Self::Repeatable => "repeatable",
            Self::Post => "post",
        }
    }
}

/// One entry of `edit`'s or `apply_overlay`'s `ops` array.
///
/// The engine has five native write operations (rename, label, comment, signature, data type);
/// this enum names the three the multi-agent benchmark uses. Every other op is still reachable
/// through [`Session::call`] with a raw `ops` array, so no protocol surface is lost.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EditOp {
    /// `{"op": "rename", "address", "name"}`.
    Rename {
        /// The address of the symbol to rename.
        address: String,
        /// The new name.
        name: String,
    },
    /// `{"op": "comment", "address", "text", "type"}`.
    Comment {
        /// The address to comment.
        address: String,
        /// The comment text.
        text: String,
        /// Which comment.
        kind: CommentKind,
    },
    /// `{"op": "signature", "address", "signature"}`.
    Signature {
        /// The function whose prototype changes.
        address: String,
        /// The new prototype, without a trailing semicolon.
        signature: String,
    },
}

impl EditOp {
    /// The protocol's JSON object for this operation.
    #[must_use]
    pub fn to_json(&self) -> Value {
        match self {
            Self::Rename { address, name } => {
                json!({"op": "rename", "address": address, "name": name})
            }
            Self::Comment {
                address,
                text,
                kind,
            } => json!({"op": "comment", "address": address, "text": text, "type": kind.as_str()}),
            Self::Signature { address, signature } => {
                json!({"op": "signature", "address": address, "signature": signature})
            }
        }
    }
}

fn ops_json(ops: &[EditOp]) -> Value {
    Value::Array(ops.iter().map(EditOp::to_json).collect())
}

impl Session {
    /// `ping`: `{"pong": true}`.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn ping(&self) -> Result<Value> {
        self.call("ping", Map::new(), None)
    }

    /// `status`: the session identity, projects, programs, lanes, clients and import queue.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn status(&self, deadline: Option<f64>) -> Result<Value> {
        self.call("status", Map::new(), deadline)
    }

    /// `hello` again with new labels (the protocol allows one `hello` per connection; a second
    /// one changes nothing about the protocol).
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn hello_again(&self, client: &str, harness: &str) -> Result<Value> {
        self.call(
            "hello",
            fields([
                ("client", Value::String(client.to_owned())),
                ("harness", Value::String(harness.to_owned())),
            ]),
            None,
        )
    }

    /// `open_project`: joins the project (opening it if needed) and makes it active.
    ///
    /// # Errors
    /// As [`Session::call`]; the engine answers `conflict`, `no_project`, ... here.
    pub fn open_project(
        &self,
        path: &str,
        access: Access,
        discard: Discard,
        deadline: Option<f64>,
    ) -> Result<Value> {
        self.call(
            "open_project",
            fields([
                ("path", Value::String(path.to_owned())),
                ("writable", access.json()),
                ("discard", discard.json()),
            ]),
            deadline,
        )
    }

    /// `open_program`: opens or joins a program and makes it active. `path` may be a project
    /// path, a unique name or a key; `project` an id or a path.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn open_program(
        &self,
        path: &str,
        project: Option<&str>,
        access: Access,
        overlay: Option<&str>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = fields([
            ("path", Value::String(path.to_owned())),
            ("writable", access.json()),
        ]);
        if let Some(project) = project {
            f.insert("project".to_owned(), Value::String(project.to_owned()));
        }
        if let Some(overlay) = overlay {
            f.insert("overlay".to_owned(), Value::String(overlay.to_owned()));
        }
        self.call("open_program", f, deadline)
    }

    /// `info`: key, language, compiler, hashes, function counts, mode, owner, revisions.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn info(
        &self,
        program: Option<&str>,
        overlay: Option<&str>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = Map::new();
        if let Some(program) = program {
            f.insert("program".to_owned(), Value::String(program.to_owned()));
        }
        if let Some(overlay) = overlay {
            f.insert("overlay".to_owned(), Value::String(overlay.to_owned()));
        }
        self.call("info", f, deadline)
    }

    /// `functions`, one page: `{"functions": [...], "returned", "truncated"}`.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn functions(
        &self,
        program: &str,
        offset: u64,
        limit: u64,
        contains: Option<&str>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = fields([
            ("program", Value::String(program.to_owned())),
            ("offset", Value::from(offset)),
            ("limit", Value::from(limit)),
        ]);
        if let Some(contains) = contains {
            f.insert("contains".to_owned(), Value::String(contains.to_owned()));
        }
        self.call("functions", f, deadline)
    }

    /// Every function of a program, page by page, the way the benchmark lists them:
    /// `limit` 1000, `offset += returned` until `truncated` is false.
    ///
    /// # Errors
    /// As [`Session::call`], or [`crate::error::Error::BadReply`] when a page does not move
    /// the offset (the engine would answer `returned: 0` forever and the Python client would
    /// loop the same way; stopping is the only difference).
    pub fn functions_all(&self, program: &str, deadline: Option<f64>) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut offset = 0_u64;
        loop {
            let page = self.functions(program, offset, 1000, None, deadline)?;
            if let Some(items) = page.get("functions").and_then(Value::as_array) {
                out.extend(items.iter().cloned());
            }
            if page.get("truncated") != Some(&Value::Bool(true)) {
                return Ok(out);
            }
            let returned = page.get("returned").and_then(Value::as_u64).unwrap_or(0);
            if returned == 0 {
                return Err(crate::error::Error::BadReply(
                    "a functions page is truncated but returned nothing".to_owned(),
                ));
            }
            offset += returned;
        }
    }

    /// `decompile`: C text and signature, by `address` or by `name`.
    ///
    /// `timeout_s` is the engine's decompiler timeout in seconds (the protocol's default 60);
    /// `max_chars` caps the text (the protocol's default 200000).
    ///
    /// # Errors
    /// As [`Session::call`]; the engine may answer `canceled` on a timeout.
    #[expect(
        clippy::too_many_arguments,
        reason = "the protocol's decompile names eight optional fields; the call site reads best when they are named"
    )]
    pub fn decompile(
        &self,
        program: &str,
        address: Option<&str>,
        name: Option<&str>,
        overlay: Option<&str>,
        timeout_s: Option<u64>,
        max_chars: Option<u64>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = fields([("program", Value::String(program.to_owned()))]);
        if let Some(address) = address {
            f.insert("address".to_owned(), Value::String(address.to_owned()));
        }
        if let Some(name) = name {
            f.insert("name".to_owned(), Value::String(name.to_owned()));
        }
        if let Some(overlay) = overlay {
            f.insert("overlay".to_owned(), Value::String(overlay.to_owned()));
        }
        if let Some(timeout_s) = timeout_s {
            f.insert("timeout".to_owned(), Value::from(timeout_s));
        }
        if let Some(max_chars) = max_chars {
            f.insert("maxChars".to_owned(), Value::from(max_chars));
        }
        self.call("decompile", f, deadline)
    }

    /// `script`: runs a `GhidraScript` and returns its `output`, `mode`, `changed` and `unsaved`.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn script(
        &self,
        script: &str,
        args: &[String],
        program: Option<&str>,
        timeout_s: Option<u64>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = fields([
            ("script", Value::String(script.to_owned())),
            (
                "args",
                Value::Array(args.iter().cloned().map(Value::String).collect()),
            ),
        ]);
        if let Some(program) = program {
            f.insert("program".to_owned(), Value::String(program.to_owned()));
        }
        if let Some(timeout_s) = timeout_s {
            f.insert("timeout".to_owned(), Value::from(timeout_s));
        }
        self.call("script", f, deadline)
    }

    /// The byte/xref/symbol read the benchmark's agents run: `BenchRead.java` over `addresses`,
    /// answering its printed lines.
    ///
    /// There is no `bytes` command in version 2 of the protocol; the engine's script is the
    /// read path, so the Rust client runs the same script the Python agents run.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn bench_read(
        &self,
        program: &str,
        addresses: &[String],
        deadline: Option<f64>,
    ) -> Result<String> {
        let result = self.script("BenchRead.java", addresses, Some(program), Some(120), deadline)?;
        Ok(result
            .get("output")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned())
    }

    /// `close_project`: leaves the project, closing this client's programs there.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn close_project(
        &self,
        project: Option<&str>,
        discard: Option<Discard>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = Map::new();
        if let Some(project) = project {
            f.insert("project".to_owned(), Value::String(project.to_owned()));
        }
        if let Some(discard) = discard {
            f.insert("discard".to_owned(), discard.json());
        }
        self.call("close_project", f, deadline)
    }

    /// `close_program`: drops this client's use of one program.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn close_program(
        &self,
        program: &str,
        discard: Discard,
        deadline: Option<f64>,
    ) -> Result<Value> {
        self.call(
            "close_program",
            fields([
                ("program", Value::String(program.to_owned())),
                ("discard", discard.json()),
            ]),
            deadline,
        )
    }

    /// `projects`: the open projects and this client's active one.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn projects(&self) -> Result<Value> {
        self.call("projects", Map::new(), None)
    }

    /// `open_program` for a fork this client owns: writable, and upgrading the project's
    /// format when the engine says the fork is in an older one.
    ///
    /// # Errors
    /// As [`Session::call`]; the engine may answer `backup_required` or `sealed` here.
    pub fn open_program_upgrading(
        &self,
        path: &str,
        project: Option<&str>,
        overlay: Option<&str>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = fields([
            ("path", Value::String(path.to_owned())),
            ("writable", Value::Bool(true)),
            ("upgrade", Value::Bool(true)),
        ]);
        if let Some(project) = project {
            f.insert("project".to_owned(), Value::String(project.to_owned()));
        }
        if let Some(overlay) = overlay {
            f.insert("overlay".to_owned(), Value::String(overlay.to_owned()));
        }
        self.call("open_program", f, deadline)
    }

    /// `apply_overlay`: applies `ops` in one transaction to a view's overlay.
    ///
    /// The reply carries the changed subjects and the overlay's new revision; the ops are
    /// [`EditOp`]s, and an op this enum does not name is still reachable through
    /// [`Session::call`] with a raw array.
    ///
    /// # Errors
    /// As [`Session::call`]; the engine may answer `conflict` or `not_found` here.
    pub fn apply_overlay(
        &self,
        program: &str,
        overlay: &str,
        ops: &[EditOp],
        deadline: Option<f64>,
    ) -> Result<Value> {
        self.call(
            "apply_overlay",
            fields([
                ("program", Value::String(program.to_owned())),
                ("overlay", Value::String(overlay.to_owned())),
                ("ops", ops_json(ops)),
            ]),
            deadline,
        )
    }

    /// `drop_overlay`: discards a view's overlay and everything unsaved in it.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn drop_overlay(
        &self,
        program: &str,
        overlay: &str,
        deadline: Option<f64>,
    ) -> Result<Value> {
        self.call(
            "drop_overlay",
            fields([
                ("program", Value::String(program.to_owned())),
                ("overlay", Value::String(overlay.to_owned())),
            ]),
            deadline,
        )
    }

    /// `edit`: applies `ops` to a writable program, changing its in-memory database.
    ///
    /// # Errors
    /// As [`Session::call`]; the engine may answer `read_only`, `conflict` or `sealed` here.
    pub fn edit(&self, program: &str, ops: &[EditOp], deadline: Option<f64>) -> Result<Value> {
        self.call(
            "edit",
            fields([
                ("program", Value::String(program.to_owned())),
                ("ops", ops_json(ops)),
            ]),
            deadline,
        )
    }

    /// `save`: writes a writable program's changes, with an optional journal comment.
    ///
    /// # Errors
    /// As [`Session::call`].
    pub fn save(
        &self,
        program: &str,
        comment: Option<&str>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = fields([("program", Value::String(program.to_owned()))]);
        if let Some(comment) = comment {
            f.insert("comment".to_owned(), Value::String(comment.to_owned()));
        }
        self.call("save", f, deadline)
    }

    /// `fork_project`: copies a project to `path`; the reply names the new project's id.
    ///
    /// `timeout_s` is the engine's fork timeout (the protocol's default is 600 s for a fork
    /// of a large project).
    ///
    /// # Errors
    /// As [`Session::call`]; the engine may answer `conflict`, `not_found` or `failed` here.
    pub fn fork_project(
        &self,
        project: &str,
        path: &str,
        access: Access,
        timeout_s: Option<u64>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        let mut f = fields([
            ("project", Value::String(project.to_owned())),
            ("path", Value::String(path.to_owned())),
            ("writable", access.json()),
        ]);
        if let Some(timeout_s) = timeout_s {
            f.insert("timeout".to_owned(), Value::from(timeout_s));
        }
        self.call("fork_project", f, deadline)
    }
}
